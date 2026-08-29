from __future__ import annotations

import html
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Iterable, Protocol
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from .gateways import InternetGateway
from .privacy import sanitize_research_query
from .runtime_efficiency import sanitize_untrusted_payload

_RETRIEVAL_SANITIZER_VERSION = "workspace-retrieval-sanitizer/v1"
_RISK_ORDER = {"low": 0, "medium": 1, "high": 2}


@dataclass(frozen=True)
class SearchResult:
    title: str
    url: str
    snippet: str = ""


@dataclass(frozen=True)
class ResearchSource:
    """Textual research evidence classified as untrusted before Agent 1 consumes it.

    Provenance fields (source_id/url/fetch_status) are supplied by trusted code paths.
    Human/web/document/tool text is normalized and risk-classified as data only. Risk
    metadata can inform validators/auditing but never grants model/tool authority.
    """

    source_id: str
    title: str
    url: str
    search_snippet: str
    extracted_text: str
    fetch_status: str
    error: str = ""
    trust: str = ""
    risk_level: str = "low"
    sanitizer_version: str = _RETRIEVAL_SANITIZER_VERSION
    sanitization_findings: tuple[dict, ...] = ()

    def __post_init__(self) -> None:
        textual_payload = {
            "title": self.title,
            "search_snippet": self.search_snippet,
            "extracted_text": self.extracted_text,
            "error": self.error,
        }
        sanitized, findings = sanitize_untrusted_payload(textual_payload)

        object.__setattr__(self, "title", str(sanitized["title"]))
        object.__setattr__(self, "search_snippet", str(sanitized["search_snippet"]))
        object.__setattr__(self, "extracted_text", str(sanitized["extracted_text"]))
        object.__setattr__(self, "error", str(sanitized["error"]))

        compact_findings: list[dict] = []
        seen: set[tuple[str, str, tuple[str, ...]]] = set()
        for finding in (*self.sanitization_findings, *findings):
            path = str(finding.get("path", ""))
            risk = str(finding.get("risk", "low"))
            raw_signals = finding.get("signals", [])
            signals = tuple(
                str(signal) for signal in raw_signals
            ) if isinstance(raw_signals, (list, tuple)) else ()
            key = (path, risk, signals)
            if key in seen:
                continue
            seen.add(key)
            compact_findings.append(
                {"path": path, "risk": risk, "signals": list(signals)}
            )
        object.__setattr__(self, "sanitization_findings", tuple(compact_findings))

        inferred_trust = (
            "untrusted_upload" if self.url.startswith("upload://") else "untrusted_external"
        )
        object.__setattr__(self, "trust", str(self.trust or inferred_trust))

        highest = str(self.risk_level or "low")
        if highest not in _RISK_ORDER:
            highest = "low"
        for finding in compact_findings:
            candidate = str(finding.get("risk", "low"))
            if _RISK_ORDER.get(candidate, 0) > _RISK_ORDER[highest]:
                highest = candidate
        object.__setattr__(self, "risk_level", highest)
        object.__setattr__(
            self,
            "sanitizer_version",
            str(self.sanitizer_version or _RETRIEVAL_SANITIZER_VERSION),
        )

    def to_dict(self) -> dict:
        return {
            "source_id": self.source_id,
            "title": self.title,
            "url": self.url,
            "search_snippet": self.search_snippet,
            "extracted_text": self.extracted_text,
            "fetch_status": self.fetch_status,
            "error": self.error,
            "trust": self.trust,
            "sanitization": {
                "sanitizer_version": self.sanitizer_version,
                "risk_level": self.risk_level,
                "finding_count": len(self.sanitization_findings),
                "findings": [dict(item) for item in self.sanitization_findings],
                "raw_content_logged": False,
            },
        }


class SearchProvider(Protocol):
    name: str

    def search(
        self,
        agent_id: str,
        task_id: str,
        query: str,
        max_results: int = 5,
    ) -> list[SearchResult]:
        ...


def _clean_space(value: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(value)).strip()


def _canonical_url(value: str) -> str:
    parsed = urlparse(value)
    filtered_query = []
    for part in parsed.query.split("&"):
        if not part:
            continue
        key = part.split("=", 1)[0].casefold()
        if key.startswith("utm_") or key in {
            "fbclid",
            "gclid",
            "mc_cid",
            "mc_eid",
            "msclkid",
        }:
            continue
        filtered_query.append(part)
    return urlunparse(
        (
            parsed.scheme.casefold(),
            parsed.netloc.casefold(),
            parsed.path or "/",
            parsed.params,
            "&".join(filtered_query),
            "",
        )
    )


def _normalize_result_url(value: str) -> str:
    url = html.unescape(value).strip()
    if url.startswith("//"):
        url = "https:" + url
    parsed = urlparse(url)
    if "duckduckgo.com" in parsed.netloc and parsed.path.startswith("/l/"):
        target = parse_qs(parsed.query).get("uddg", [""])[0]
        if target:
            url = target
    if url.startswith(("http://", "https://")):
        return _canonical_url(url)
    return url


def _dedupe_results(
    results: Iterable[SearchResult],
    max_results: int,
) -> list[SearchResult]:
    unique: list[SearchResult] = []
    seen: set[str] = set()
    for result in results:
        canonical = _canonical_url(result.url)
        if canonical in seen:
            continue
        seen.add(canonical)
        unique.append(SearchResult(result.title, canonical, result.snippet))
        if len(unique) >= max_results:
            break
    return unique


class DuckDuckGoHTMLParser(HTMLParser):
    TITLE_CLASSES = {"result__a", "result-link"}
    SNIPPET_CLASSES = {"result__snippet", "result-snippet"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.results: list[SearchResult] = []
        self._capture_title = False
        self._capture_snippet = False
        self._title_parts: list[str] = []
        self._snippet_parts: list[str] = []
        self._pending_url = ""

    @staticmethod
    def _classes(attrs: list[tuple[str, str | None]]) -> set[str]:
        raw = dict(attrs).get("class") or ""
        return set(raw.split())

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        classes = self._classes(attrs)
        attr_map = dict(attrs)
        if tag == "a" and classes.intersection(self.TITLE_CLASSES):
            self._capture_title = True
            self._title_parts = []
            self._pending_url = _normalize_result_url(attr_map.get("href") or "")
        elif classes.intersection(self.SNIPPET_CLASSES):
            self._capture_snippet = True
            self._snippet_parts = []

    def handle_data(self, data: str) -> None:
        if self._capture_title:
            self._title_parts.append(data)
        if self._capture_snippet:
            self._snippet_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._capture_title:
            title = _clean_space(" ".join(self._title_parts))
            url = self._pending_url
            self._capture_title = False
            self._title_parts = []
            self._pending_url = ""
            if title and url.startswith(("http://", "https://")):
                self.results.append(SearchResult(title=title, url=url))
        if self._capture_snippet and tag in {"a", "div", "span", "td"}:
            snippet = _clean_space(" ".join(self._snippet_parts))
            self._capture_snippet = False
            self._snippet_parts = []
            if snippet and self.results:
                last = self.results[-1]
                self.results[-1] = SearchResult(last.title, last.url, snippet)


class BingHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.results: list[SearchResult] = []
        self._in_algo = 0
        self._in_h2 = 0
        self._capture_title = False
        self._capture_snippet = False
        self._title_parts: list[str] = []
        self._snippet_parts: list[str] = []
        self._pending_url = ""

    @staticmethod
    def _classes(attrs: list[tuple[str, str | None]]) -> set[str]:
        raw = dict(attrs).get("class") or ""
        return set(raw.split())

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        classes = self._classes(attrs)
        attr_map = dict(attrs)
        if tag == "li" and "b_algo" in classes:
            self._in_algo += 1
        if self._in_algo and tag == "h2":
            self._in_h2 += 1
        if self._in_algo and self._in_h2 and tag == "a" and not self._capture_title:
            self._capture_title = True
            self._title_parts = []
            self._pending_url = _normalize_result_url(attr_map.get("href") or "")
        if self._in_algo and tag == "p" and self.results:
            self._capture_snippet = True
            self._snippet_parts = []

    def handle_data(self, data: str) -> None:
        if self._capture_title:
            self._title_parts.append(data)
        if self._capture_snippet:
            self._snippet_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._capture_title:
            title = _clean_space(" ".join(self._title_parts))
            url = self._pending_url
            self._capture_title = False
            self._title_parts = []
            self._pending_url = ""
            if title and url.startswith(("http://", "https://")):
                self.results.append(SearchResult(title=title, url=url))
        if tag == "p" and self._capture_snippet:
            snippet = _clean_space(" ".join(self._snippet_parts))
            self._capture_snippet = False
            self._snippet_parts = []
            if snippet and self.results:
                last = self.results[-1]
                self.results[-1] = SearchResult(last.title, last.url, snippet)
        if tag == "h2" and self._in_h2:
            self._in_h2 -= 1
        if tag == "li" and self._in_algo:
            self._in_algo -= 1


class VisibleTextParser(HTMLParser):
    SKIP_TAGS = {
        "script",
        "style",
        "noscript",
        "svg",
        "canvas",
        "template",
        "nav",
        "footer",
        "aside",
        "form",
        "button",
        "iframe",
    }

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._skip_depth = 0
        self._in_title = False
        self._title_parts: list[str] = []
        self._text_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        if tag in self.SKIP_TAGS:
            self._skip_depth += 1
        if tag == "title" and self._skip_depth == 0:
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        if tag in self.SKIP_TAGS and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        cleaned = _clean_space(data)
        if not cleaned:
            return
        if self._in_title:
            self._title_parts.append(cleaned)
        self._text_parts.append(cleaned)

    @property
    def title(self) -> str:
        return _clean_space(" ".join(self._title_parts))

    @property
    def text(self) -> str:
        unique_parts: list[str] = []
        seen: set[str] = set()
        for part in self._text_parts:
            key = part.casefold()
            if key in seen:
                continue
            seen.add(key)
            unique_parts.append(part)
        return _clean_space(" ".join(unique_parts))


class DuckDuckGoSearchProvider:
    def __init__(
        self,
        gateway: InternetGateway,
        *,
        endpoint: str = "https://html.duckduckgo.com/html/",
        name: str = "duckduckgo-html",
    ):
        self.gateway = gateway
        self.endpoint = endpoint
        self.name = name

    def search(
        self,
        agent_id: str,
        task_id: str,
        query: str,
        max_results: int = 5,
    ) -> list[SearchResult]:
        safe_query = sanitize_research_query(query)
        url = self.endpoint + "?" + urlencode({"q": safe_query})
        raw = self.gateway.get(agent_id, task_id, url, timeout=30)
        parser = DuckDuckGoHTMLParser()
        parser.feed(raw.decode("utf-8", errors="replace"))
        return _dedupe_results(parser.results, max_results)


class BingSearchProvider:
    name = "bing-html"

    def __init__(self, gateway: InternetGateway):
        self.gateway = gateway

    def search(
        self,
        agent_id: str,
        task_id: str,
        query: str,
        max_results: int = 5,
    ) -> list[SearchResult]:
        safe_query = sanitize_research_query(query)
        url = "https://www.bing.com/search?" + urlencode(
            {"q": safe_query, "count": max_results}
        )
        raw = self.gateway.get(agent_id, task_id, url, timeout=30)
        parser = BingHTMLParser()
        parser.feed(raw.decode("utf-8", errors="replace"))
        return _dedupe_results(parser.results, max_results)


class WebResearchClient:
    def __init__(
        self,
        gateway: InternetGateway,
        search_provider: SearchProvider | None = None,
        *,
        search_providers: Iterable[SearchProvider] | None = None,
    ):
        self.gateway = gateway
        if search_provider is not None and search_providers is not None:
            raise ValueError("Use search_provider or search_providers, not both")
        if search_provider is not None:
            providers = [search_provider]
        elif search_providers is not None:
            providers = list(search_providers)
        else:
            providers = [
                DuckDuckGoSearchProvider(gateway),
                DuckDuckGoSearchProvider(
                    gateway,
                    endpoint="https://lite.duckduckgo.com/lite/",
                    name="duckduckgo-lite",
                ),
                BingSearchProvider(gateway),
            ]
        if not providers:
            raise ValueError("At least one search provider is required")
        self.search_providers = providers
        self.search_provider = providers[0]

    @staticmethod
    def _provider_name(provider: SearchProvider) -> str:
        value = getattr(provider, "name", "")
        return str(value or provider.__class__.__name__)

    def search_many(
        self,
        agent_id: str,
        task_id: str,
        queries: Iterable[str],
        *,
        max_results_per_query: int = 4,
        max_unique_results: int = 8,
    ) -> tuple[list[SearchResult], list[str]]:
        results: list[SearchResult] = []
        diagnostics: list[str] = []
        seen: set[str] = set()
        for query in queries:
            safe_query = sanitize_research_query(query)
            found_for_query: list[SearchResult] = []
            for provider in self.search_providers:
                provider_name = self._provider_name(provider)
                try:
                    found = provider.search(
                        agent_id,
                        task_id,
                        safe_query,
                        max_results=max_results_per_query,
                    )
                except Exception as exc:
                    diagnostics.append(
                        f"search_failed provider={provider_name} query={safe_query!r}: "
                        f"{type(exc).__name__}: {exc}"
                    )
                    continue
                if not found:
                    diagnostics.append(
                        f"search_empty provider={provider_name} query={safe_query!r}"
                    )
                    continue
                found_for_query = found
                break

            for result in found_for_query:
                canonical = _canonical_url(result.url)
                if canonical in seen:
                    continue
                seen.add(canonical)
                results.append(SearchResult(result.title, canonical, result.snippet))
                if len(results) >= max_unique_results:
                    return results, diagnostics
        return results, diagnostics

    def fetch_sources(
        self,
        agent_id: str,
        task_id: str,
        results: Iterable[SearchResult],
        *,
        max_sources: int = 6,
        max_chars_per_source: int = 12000,
    ) -> list[ResearchSource]:
        sources: list[ResearchSource] = []
        for result in list(results)[:max_sources]:
            source_id = f"S{len(sources) + 1}"
            try:
                raw = self.gateway.get(agent_id, task_id, result.url, timeout=30)
                parser = VisibleTextParser()
                parser.feed(raw.decode("utf-8", errors="replace"))
                text = parser.text[:max_chars_per_source]
                if not text:
                    raise ValueError("no readable text extracted")
                sources.append(
                    ResearchSource(
                        source_id=source_id,
                        title=parser.title or result.title,
                        url=result.url,
                        search_snippet=result.snippet,
                        extracted_text=text,
                        fetch_status="ok",
                    )
                )
            except Exception as exc:
                sources.append(
                    ResearchSource(
                        source_id=source_id,
                        title=result.title,
                        url=result.url,
                        search_snippet=result.snippet,
                        extracted_text="",
                        fetch_status="failed",
                        error=f"{type(exc).__name__}: {exc}",
                    )
                )
        return sources
