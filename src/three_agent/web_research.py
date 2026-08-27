from __future__ import annotations

import html
import re
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from typing import Iterable
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from .gateways import InternetGateway
from .privacy import sanitize_research_query


@dataclass(frozen=True)
class SearchResult:
    title: str
    url: str
    snippet: str = ""


@dataclass(frozen=True)
class ResearchSource:
    source_id: str
    title: str
    url: str
    search_snippet: str
    extracted_text: str
    fetch_status: str
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _clean_space(value: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(value)).strip()


def _canonical_url(value: str) -> str:
    parsed = urlparse(value)
    filtered_query = []
    for part in parsed.query.split("&"):
        if not part:
            continue
        key = part.split("=", 1)[0].casefold()
        if key.startswith("utm_") or key in {"fbclid", "gclid", "mc_cid", "mc_eid"}:
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


class DuckDuckGoHTMLParser(HTMLParser):
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
        if tag == "a" and "result__a" in classes:
            self._capture_title = True
            self._title_parts = []
            self._pending_url = _normalize_result_url(attr_map.get("href") or "")
        elif "result__snippet" in classes:
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
        if self._capture_snippet and tag in {"a", "div", "span"}:
            snippet = _clean_space(" ".join(self._snippet_parts))
            self._capture_snippet = False
            self._snippet_parts = []
            if snippet and self.results:
                last = self.results[-1]
                self.results[-1] = SearchResult(last.title, last.url, snippet)


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
    def __init__(self, gateway: InternetGateway):
        self.gateway = gateway

    def search(self, agent_id: str, task_id: str, query: str, max_results: int = 5) -> list[SearchResult]:
        safe_query = sanitize_research_query(query)
        url = "https://html.duckduckgo.com/html/?" + urlencode({"q": safe_query})
        raw = self.gateway.get(agent_id, task_id, url, timeout=30)
        parser = DuckDuckGoHTMLParser()
        parser.feed(raw.decode("utf-8", errors="replace"))
        unique: list[SearchResult] = []
        seen: set[str] = set()
        for result in parser.results:
            canonical = _canonical_url(result.url)
            if canonical in seen:
                continue
            seen.add(canonical)
            unique.append(SearchResult(result.title, canonical, result.snippet))
            if len(unique) >= max_results:
                break
        return unique


class WebResearchClient:
    def __init__(self, gateway: InternetGateway, search_provider: DuckDuckGoSearchProvider | None = None):
        self.gateway = gateway
        self.search_provider = search_provider or DuckDuckGoSearchProvider(gateway)

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
        errors: list[str] = []
        seen: set[str] = set()
        for query in queries:
            try:
                found = self.search_provider.search(
                    agent_id,
                    task_id,
                    query,
                    max_results=max_results_per_query,
                )
            except Exception as exc:
                safe_query = sanitize_research_query(query)
                errors.append(f"search_failed query={safe_query!r}: {exc}")
                continue
            for result in found:
                canonical = _canonical_url(result.url)
                if canonical in seen:
                    continue
                seen.add(canonical)
                results.append(SearchResult(result.title, canonical, result.snippet))
                if len(results) >= max_unique_results:
                    return results, errors
        return results, errors

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
                        error=str(exc),
                    )
                )
        return sources
