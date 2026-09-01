from __future__ import annotations

import argparse
import hashlib
import http.client
import ipaddress
import json
import os
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from .network_dataset_policy import (
    AcquisitionPlan,
    NetworkDatasetDenied,
    NetworkDatasetManager,
    NetworkDatasetPolicyError,
)

ACQUISITION_RECEIPT_SCHEMA = "workspace-network-public-acquisition-receipt/v1"
ACQUISITION_VERSION = "workspace-network-public-acquisition/0.1"
DEFAULT_POLICY = Path("config/network-data-policy.json")
DEFAULT_REGISTRY = Path("config/network-datasets.registry.json")
CHUNK_BYTES = 1024 * 1024
REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})


class PublicCorpusAcquisitionError(RuntimeError):
    """Operator-side public corpus acquisition failed closed."""

    def __init__(self, reason_code: str, message: str):
        self.reason_code = reason_code
        super().__init__(f"{reason_code}: {message}")


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _safe_output_name(value: str) -> str:
    name = str(value or "").strip()
    if not name or len(name) > 180:
        raise PublicCorpusAcquisitionError("OUTPUT_NAME_INVALID", "output name must be bounded")
    if name in {".", ".."} or Path(name).name != name or "/" in name or "\\" in name:
        raise PublicCorpusAcquisitionError("OUTPUT_NAME_INVALID", "output name must be a basename")
    if any(ord(char) < 32 for char in name):
        raise PublicCorpusAcquisitionError("OUTPUT_NAME_INVALID", "output name contains control characters")
    return name


def _canonical_source_path(raw_path: str) -> str:
    try:
        decoded = urllib.parse.unquote(raw_path or "/", errors="strict")
    except UnicodeError as exc:
        raise PublicCorpusAcquisitionError("SOURCE_PATH_INVALID", "source path has invalid encoding") from exc
    if not decoded.startswith("/") or "\\" in decoded or any(ord(char) < 32 for char in decoded):
        raise PublicCorpusAcquisitionError("SOURCE_PATH_INVALID", "source path is not a canonical URL path")
    segments = decoded.split("/")
    if any(segment in {".", ".."} for segment in segments):
        raise PublicCorpusAcquisitionError("SOURCE_PATH_TRAVERSAL_DENIED", "source path contains dot traversal segments")
    return decoded


def _validate_public_ip(ip_text: str) -> None:
    try:
        address = ipaddress.ip_address(ip_text)
    except ValueError as exc:
        raise PublicCorpusAcquisitionError("DNS_ADDRESS_INVALID", "resolver returned invalid IP") from exc
    if not address.is_global:
        raise PublicCorpusAcquisitionError(
            "PRIVATE_SPECIAL_DESTINATION_DENIED",
            "dataset acquisition may only connect to globally routable public addresses",
        )


@dataclass(frozen=True)
class AcquisitionReceipt:
    dataset_id: str
    variant: str | None
    purpose: str
    source_url: str
    source_sha256: str
    source_size_bytes: int
    destination_path: str
    fetched_at: str
    plan_fingerprint: str
    registry_fingerprint: str
    policy_fingerprint: str
    acquisition_version: str = ACQUISITION_VERSION
    schema_version: str = ACQUISITION_RECEIPT_SCHEMA

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "acquisition_version": self.acquisition_version,
            "dataset_id": self.dataset_id,
            "variant": self.variant,
            "purpose": self.purpose,
            "source_url": self.source_url,
            "source_sha256": self.source_sha256,
            "source_size_bytes": self.source_size_bytes,
            "destination_path": self.destination_path,
            "fetched_at": self.fetched_at,
            "plan_fingerprint": self.plan_fingerprint,
            "registry_fingerprint": self.registry_fingerprint,
            "policy_fingerprint": self.policy_fingerprint,
        }


@dataclass(frozen=True)
class _ValidatedSource:
    parsed: urllib.parse.SplitResult
    host: str
    public_addresses: tuple[str, ...]


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that never resolves the reviewed hostname at connect time.

    DNS is resolved and policy-validated before construction. The TCP socket is
    opened to that exact vetted address while TLS SNI and certificate hostname
    verification continue to use the reviewed hostname.
    """

    def __init__(self, host: str, pinned_ip: str, *, timeout: float):
        super().__init__(host=host, port=443, timeout=timeout, context=ssl.create_default_context())
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        if self._tunnel_host is not None:
            raise PublicCorpusAcquisitionError("PROXY_TUNNEL_DENIED", "HTTPS proxy tunnels are not admitted")
        raw_socket = socket.create_connection(
            (self._pinned_ip, self.port),
            self.timeout,
            self.source_address,
        )
        try:
            self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)
        except BaseException:
            raw_socket.close()
            raise


class _PinnedHTTPResponse:
    def __init__(
        self,
        connection: http.client.HTTPSConnection,
        response: http.client.HTTPResponse,
        url: str,
    ):
        self._connection = connection
        self._response = response
        self._url = url
        self.headers = response.headers
        self._closed = False

    def __enter__(self) -> "_PinnedHTTPResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.close()
        return False

    def geturl(self) -> str:
        return self._url

    def read(self, size: int = -1) -> bytes:
        return self._response.read(size)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._response.close()
        finally:
            self._connection.close()


class _PinnedHTTPSOpener:
    def __init__(self, fetcher: "PublicCorpusFetcher", plan: AcquisitionPlan):
        self._fetcher = fetcher
        self._plan = plan

    def open(self, request: urllib.request.Request, timeout: float = 30) -> _PinnedHTTPResponse:
        if request.get_method() != "GET":
            raise PublicCorpusAcquisitionError("HTTP_METHOD_DENIED", "only GET is admitted for corpus fetch")

        current_url = request.full_url
        redirects = 0
        while True:
            validated = self._fetcher._validate_source(self._plan, current_url)
            parsed = validated.parsed
            target = parsed.path or "/"
            last_error: BaseException | None = None
            connection: http.client.HTTPSConnection | None = None
            response: http.client.HTTPResponse | None = None

            for pinned_ip in validated.public_addresses:
                candidate = self._fetcher._connection_factory(
                    validated.host,
                    pinned_ip,
                    timeout=timeout,
                )
                try:
                    candidate.request(
                        "GET",
                        target,
                        headers={"User-Agent": "WorkSpace-Public-Corpus/0.1"},
                    )
                    response = candidate.getresponse()
                    connection = candidate
                    break
                except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
                    last_error = exc
                    candidate.close()

            if connection is None or response is None:
                raise PublicCorpusAcquisitionError(
                    "FETCH_CONNECT_FAILED",
                    "could not connect to any policy-validated public dataset address",
                ) from last_error

            if response.status in REDIRECT_STATUS_CODES:
                location = response.getheader("Location")
                response.close()
                connection.close()
                if not self._fetcher._allow_redirects:
                    raise PublicCorpusAcquisitionError("REDIRECT_DENIED", "redirects are disabled by policy")
                if redirects >= self._fetcher._max_redirects:
                    raise PublicCorpusAcquisitionError("REDIRECT_LIMIT_EXCEEDED", "redirect limit exceeded")
                if not location:
                    raise PublicCorpusAcquisitionError("REDIRECT_LOCATION_MISSING", "redirect response has no Location")
                current_url = urllib.parse.urljoin(current_url, location)
                redirects += 1
                continue

            if response.status < 200 or response.status >= 300:
                status = response.status
                response.close()
                connection.close()
                raise PublicCorpusAcquisitionError(
                    "FETCH_HTTP_STATUS_DENIED",
                    f"dataset source returned HTTP status {status}",
                )

            return _PinnedHTTPResponse(connection, response, current_url)


class PublicCorpusFetcher:
    """Bounded operator-side HTTPS acquisition for reviewed public datasets.

    This component is deliberately separate from model/agent runtime. It accepts
    no credentials or caller-controlled headers, performs no archive extraction,
    and stages one reviewed object at a time under the ephemeral incoming cache.
    Production transport pins TCP connections to the exact public IP addresses
    that passed the current DNS policy check, eliminating DNS-rebinding TOCTOU.
    """

    def __init__(
        self,
        manager: NetworkDatasetManager,
        *,
        resolver: Callable[..., Iterable[tuple[Any, ...]]] = socket.getaddrinfo,
        opener: Any | None = None,
        connection_factory: Callable[..., http.client.HTTPSConnection] = _PinnedHTTPSConnection,
    ):
        self.manager = manager
        self._resolver = resolver
        self._connection_factory = connection_factory
        network = manager.policy.raw.get("network", {})
        if not isinstance(network, dict):
            raise PublicCorpusAcquisitionError("NETWORK_POLICY_INVALID", "policy.network must be an object")
        if network.get("https_only") is not True:
            raise PublicCorpusAcquisitionError("NETWORK_POLICY_INVALID", "public corpus acquisition requires HTTPS-only")
        if network.get("deny_private_special_destinations") is not True:
            raise PublicCorpusAcquisitionError(
                "NETWORK_POLICY_INVALID",
                "public corpus acquisition requires private/special destination denial",
            )
        if network.get("credentials_allowed") is not False:
            raise PublicCorpusAcquisitionError("NETWORK_POLICY_INVALID", "credentials must remain disabled")
        if network.get("caller_headers_allowed") is not False:
            raise PublicCorpusAcquisitionError("NETWORK_POLICY_INVALID", "caller headers must remain disabled")
        self._deny_private = True
        self._allow_redirects = network.get("allow_redirects") is True
        try:
            self._max_redirects = int(network.get("max_redirects", 0))
        except (TypeError, ValueError) as exc:
            raise PublicCorpusAcquisitionError("NETWORK_POLICY_INVALID", "max_redirects must be an integer") from exc
        if self._max_redirects < 0 or self._max_redirects > 5:
            raise PublicCorpusAcquisitionError("NETWORK_POLICY_INVALID", "max_redirects must be 0..5")
        self._opener_override = opener

    def _source_suffixes(self, plan: AcquisitionPlan) -> tuple[str, ...]:
        try:
            record = self.manager.datasets[plan.dataset_id]
        except KeyError as exc:
            raise PublicCorpusAcquisitionError("DATASET_UNKNOWN", "dataset disappeared from reviewed registry") from exc
        acquisition = record.raw.get("acquisition", {})
        if not isinstance(acquisition, dict):
            raise PublicCorpusAcquisitionError("REGISTRY_ACQUISITION_INVALID", "dataset acquisition metadata is invalid")
        raw_suffixes = acquisition.get("allowlisted_source_suffixes", [])
        if not isinstance(raw_suffixes, list):
            raise PublicCorpusAcquisitionError(
                "REGISTRY_SUFFIX_ALLOWLIST_INVALID",
                "allowlisted_source_suffixes must be a list",
            )
        suffixes: list[str] = []
        for raw in raw_suffixes:
            suffix = str(raw or "").strip().casefold()
            if not suffix or len(suffix) > 32 or not suffix.startswith("."):
                raise PublicCorpusAcquisitionError(
                    "REGISTRY_SUFFIX_ALLOWLIST_INVALID",
                    "source suffix allowlist entries must be bounded dot-prefixed suffixes",
                )
            if any(char in suffix for char in ("/", "\\", "?", "#")):
                raise PublicCorpusAcquisitionError(
                    "REGISTRY_SUFFIX_ALLOWLIST_INVALID",
                    "source suffix allowlist entry contains forbidden characters",
                )
            if suffix not in suffixes:
                suffixes.append(suffix)
        return tuple(suffixes)

    def _resolve_public_addresses(self, host: str) -> tuple[str, ...]:
        try:
            answers = tuple(self._resolver(host, 443, type=socket.SOCK_STREAM))
        except OSError as exc:
            raise PublicCorpusAcquisitionError("DNS_RESOLUTION_FAILED", "dataset host could not be resolved") from exc
        if not answers:
            raise PublicCorpusAcquisitionError("DNS_RESOLUTION_FAILED", "dataset host resolved to no addresses")

        addresses: list[str] = []
        for answer in answers:
            sockaddr = answer[4]
            if not sockaddr:
                raise PublicCorpusAcquisitionError("DNS_ADDRESS_INVALID", "resolver returned no socket address")
            ip_text = str(sockaddr[0])
            _validate_public_ip(ip_text)
            if ip_text not in addresses:
                addresses.append(ip_text)
        return tuple(addresses)

    def _validate_source(self, plan: AcquisitionPlan, raw_url: str) -> _ValidatedSource:
        try:
            parsed = urllib.parse.urlsplit(raw_url)
        except ValueError as exc:
            raise PublicCorpusAcquisitionError("SOURCE_URL_INVALID", "source URL is invalid") from exc
        if parsed.scheme.casefold() != "https":
            raise PublicCorpusAcquisitionError("HTTPS_REQUIRED", "dataset source must use HTTPS")
        if not parsed.hostname or parsed.username is not None or parsed.password is not None:
            raise PublicCorpusAcquisitionError("SOURCE_URL_INVALID", "URL host must be explicit and contain no userinfo")
        if parsed.port not in {None, 443}:
            raise PublicCorpusAcquisitionError("SOURCE_PORT_DENIED", "only HTTPS default port 443 is allowed")
        if parsed.query or parsed.fragment:
            raise PublicCorpusAcquisitionError(
                "SOURCE_URL_QUERY_DENIED",
                "query strings/fragments are not admitted for credential-free reviewed corpus acquisition",
            )
        host = parsed.hostname.casefold().rstrip(".")
        if host not in set(plan.allowlisted_hosts):
            raise PublicCorpusAcquisitionError("SOURCE_HOST_DENIED", "source host is not in the reviewed dataset allowlist")
        path = _canonical_source_path(parsed.path or "/")
        if plan.allowlisted_path_prefixes and not any(
            path.startswith(prefix) for prefix in plan.allowlisted_path_prefixes
        ):
            raise PublicCorpusAcquisitionError("SOURCE_PATH_DENIED", "source path is outside the reviewed dataset allowlist")
        suffixes = self._source_suffixes(plan)
        if suffixes and not path.casefold().endswith(suffixes):
            raise PublicCorpusAcquisitionError(
                "SOURCE_SUFFIX_DENIED",
                "source path does not end with a reviewed dataset file suffix",
            )
        addresses = self._resolve_public_addresses(host)
        return _ValidatedSource(parsed=parsed, host=host, public_addresses=addresses)

    def _validate_url(self, plan: AcquisitionPlan, raw_url: str) -> urllib.parse.SplitResult:
        return self._validate_source(plan, raw_url).parsed

    def _opener(self, plan: AcquisitionPlan):
        if self._opener_override is not None:
            return self._opener_override
        return _PinnedHTTPSOpener(self, plan)

    @staticmethod
    def _commit_no_overwrite(part: Path, target: Path) -> None:
        # A pre-check alone is racy. Hard-link creation is atomic and fails if
        # the target appeared after validation; both paths are in the same dir.
        try:
            os.link(part, target, follow_symlinks=False)
        except FileExistsError as exc:
            raise PublicCorpusAcquisitionError(
                "DESTINATION_EXISTS", "refusing to overwrite existing staged source"
            ) from exc
        except OSError as exc:
            raise PublicCorpusAcquisitionError(
                "ATOMIC_STAGE_COMMIT_FAILED", "could not atomically commit staged source"
            ) from exc
        part.unlink()

    def fetch(
        self,
        *,
        plan: AcquisitionPlan,
        source_url: str,
        output_name: str,
    ) -> AcquisitionReceipt:
        if plan.registry_fingerprint != self.manager.registry_fingerprint:
            raise PublicCorpusAcquisitionError("REGISTRY_FINGERPRINT_MISMATCH", "acquisition plan registry is stale")
        if plan.policy_fingerprint != self.manager.policy_fingerprint:
            raise PublicCorpusAcquisitionError("POLICY_FINGERPRINT_MISMATCH", "acquisition plan policy is stale")
        if plan.object_count != 1 or plan.full_sync:
            raise PublicCorpusAcquisitionError("BOUNDED_SINGLE_OBJECT_REQUIRED", "v1 fetch accepts one bounded object only")

        self._validate_url(plan, source_url)
        name = _safe_output_name(output_name)
        suffixes = self._source_suffixes(plan)
        if suffixes and not name.casefold().endswith(suffixes):
            raise PublicCorpusAcquisitionError(
                "OUTPUT_SUFFIX_DENIED",
                "output filename does not end with a reviewed dataset file suffix",
            )
        root = self.manager.policy.incoming_cache_root
        root.mkdir(parents=True, exist_ok=True)
        root = root.resolve(strict=True)
        variant = plan.variant or "default"
        target_dir = root / plan.dataset_id / variant
        target_dir.mkdir(parents=True, exist_ok=True)
        resolved_dir = target_dir.resolve(strict=True)
        if root not in resolved_dir.parents and resolved_dir != root:
            raise PublicCorpusAcquisitionError("CACHE_PATH_ESCAPE", "staging directory escaped incoming cache root")
        target = resolved_dir / name
        if target.exists() or target.is_symlink():
            raise PublicCorpusAcquisitionError("DESTINATION_EXISTS", "refusing to overwrite existing staged source")
        part = resolved_dir / f".{name}.part.{os.getpid()}"
        if part.exists() or part.is_symlink():
            raise PublicCorpusAcquisitionError("TEMP_DESTINATION_EXISTS", "temporary staging path already exists")

        request = urllib.request.Request(
            source_url, headers={"User-Agent": "WorkSpace-Public-Corpus/0.1"}, method="GET"
        )
        digest = hashlib.sha256()
        written = 0
        opener = self._opener(plan)
        try:
            with opener.open(request, timeout=30) as response:
                final_url = str(response.geturl())
                self._validate_url(plan, final_url)
                content_length = response.headers.get("Content-Length")
                if content_length is not None:
                    try:
                        announced = int(content_length)
                    except ValueError as exc:
                        raise PublicCorpusAcquisitionError("CONTENT_LENGTH_INVALID", "invalid Content-Length") from exc
                    if announced < 0 or announced > plan.estimated_bytes:
                        raise PublicCorpusAcquisitionError(
                            "SOURCE_BYTE_BUDGET_EXCEEDED",
                            "announced source size exceeds the approved acquisition plan",
                        )
                with part.open("xb") as handle:
                    while True:
                        chunk = response.read(CHUNK_BYTES)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > plan.estimated_bytes:
                            raise PublicCorpusAcquisitionError(
                                "SOURCE_BYTE_BUDGET_EXCEEDED",
                                "streamed source exceeded the approved acquisition plan",
                            )
                        digest.update(chunk)
                        handle.write(chunk)
                    handle.flush()
                    os.fsync(handle.fileno())
            if written <= 0:
                raise PublicCorpusAcquisitionError("SOURCE_EMPTY", "downloaded source object is empty")
            self._commit_no_overwrite(part, target)
        except PublicCorpusAcquisitionError:
            part.unlink(missing_ok=True)
            raise
        except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
            part.unlink(missing_ok=True)
            raise PublicCorpusAcquisitionError("FETCH_FAILED", "public corpus fetch failed") from exc

        source_sha256 = "sha256:" + digest.hexdigest()
        fetched_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        return AcquisitionReceipt(
            dataset_id=plan.dataset_id,
            variant=plan.variant,
            purpose=plan.purpose,
            source_url=source_url,
            source_sha256=source_sha256,
            source_size_bytes=written,
            destination_path=str(target),
            fetched_at=fetched_at,
            plan_fingerprint=_canonical_sha256(plan.as_dict()),
            registry_fingerprint=plan.registry_fingerprint,
            policy_fingerprint=plan.policy_fingerprint,
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="workspace-network-fetch",
        description=(
            "Operator-only bounded HTTPS acquisition for reviewed public network corpora. "
            "No credentials, custom headers, archive extraction, full-corpus sync, or model authority."
        ),
    )
    parser.add_argument("dataset_id")
    parser.add_argument("source_url")
    parser.add_argument("output_name")
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument(
        "--purpose",
        choices=("experience_extraction", "training", "evaluation", "research"),
        default="training",
    )
    parser.add_argument("--variant")
    parser.add_argument("--estimated-bytes", type=int, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        manager = NetworkDatasetManager.load(policy_path=args.policy, registry_path=args.registry)
        plan = manager.plan(
            args.dataset_id,
            purpose=args.purpose,
            estimated_bytes=args.estimated_bytes,
            object_count=1,
            variant=args.variant,
            full_sync=False,
        )
        receipt = PublicCorpusFetcher(manager).fetch(
            plan=plan, source_url=args.source_url, output_name=args.output_name
        )
        print(json.dumps(receipt.as_dict(), ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    except (
        PublicCorpusAcquisitionError,
        NetworkDatasetDenied,
        NetworkDatasetPolicyError,
        OSError,
        json.JSONDecodeError,
    ) as exc:
        reason = getattr(exc, "reason_code", exc.__class__.__name__)
        print(
            json.dumps(
                {"allowed": False, "reason_code": reason, "error": str(exc)},
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
