from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import socket
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


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, validator: Callable[[str], None], max_redirects: int):
        super().__init__()
        self._validator = validator
        self.max_redirections = max_redirects

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        self._validator(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class PublicCorpusFetcher:
    """Bounded operator-side HTTPS acquisition for reviewed public datasets.

    This component is deliberately separate from model/agent runtime. It accepts
    no credentials or caller-controlled headers, performs no archive extraction,
    and stages one reviewed object at a time under the ephemeral incoming cache.
    """

    def __init__(
        self,
        manager: NetworkDatasetManager,
        *,
        resolver: Callable[..., Iterable[tuple[Any, ...]]] = socket.getaddrinfo,
        opener: Any | None = None,
    ):
        self.manager = manager
        self._resolver = resolver
        network = manager.policy.raw.get("network", {})
        if not isinstance(network, dict):
            raise PublicCorpusAcquisitionError("NETWORK_POLICY_INVALID", "policy.network must be an object")
        if network.get("https_only") is not True:
            raise PublicCorpusAcquisitionError("NETWORK_POLICY_INVALID", "public corpus acquisition requires HTTPS-only")
        if network.get("credentials_allowed") is not False:
            raise PublicCorpusAcquisitionError("NETWORK_POLICY_INVALID", "credentials must remain disabled")
        if network.get("caller_headers_allowed") is not False:
            raise PublicCorpusAcquisitionError("NETWORK_POLICY_INVALID", "caller headers must remain disabled")
        self._deny_private = network.get("deny_private_special_destinations") is True
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

    def _validate_url(self, plan: AcquisitionPlan, raw_url: str) -> urllib.parse.SplitResult:
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
        path = parsed.path or "/"
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
        if self._deny_private:
            try:
                answers = tuple(self._resolver(host, 443, type=socket.SOCK_STREAM))
            except OSError as exc:
                raise PublicCorpusAcquisitionError("DNS_RESOLUTION_FAILED", "dataset host could not be resolved") from exc
            if not answers:
                raise PublicCorpusAcquisitionError("DNS_RESOLUTION_FAILED", "dataset host resolved to no addresses")
            for answer in answers:
                sockaddr = answer[4]
                if not sockaddr:
                    raise PublicCorpusAcquisitionError("DNS_ADDRESS_INVALID", "resolver returned no socket address")
                _validate_public_ip(str(sockaddr[0]))
        return parsed

    def _opener(self, plan: AcquisitionPlan):
        if self._opener_override is not None:
            return self._opener_override
        if not self._allow_redirects:
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
                    raise PublicCorpusAcquisitionError("REDIRECT_DENIED", "redirects are disabled by policy")
            return urllib.request.build_opener(NoRedirect())
        handler = _SafeRedirectHandler(lambda url: self._validate_url(plan, url), self._max_redirects)
        return urllib.request.build_opener(handler)

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
        except (urllib.error.URLError, OSError) as exc:
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
