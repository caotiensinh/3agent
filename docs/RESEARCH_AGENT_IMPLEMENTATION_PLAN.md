# Research Agent Implementation Plan

This document tracks the first real agent implementation after the local AI stack bootstrap.

## Goal

Turn the existing Research Agent skeleton into an autonomous local-first research worker that can:

1. accept a task request;
2. ask the local Ollama model for a concise search plan;
3. perform web searches without a paid cloud LLM API;
4. fetch and normalize source pages through the application Internet Gateway;
5. preserve source URLs, titles, snippets and retrieved evidence;
6. ask the local LLM to synthesize only from collected evidence;
7. explicitly separate verified facts, inference and unresolved items;
8. write auditable JSON and Markdown artifacts for downstream Presentation Agent use.

## Constraints

- Local LLM: Ollama on the dual-RTX5090 workstation.
- Internet access must go through the project Internet Gateway.
- No direct GitHub credential handling inside the agent.
- No NVIDIA driver or kernel mutation.
- No paid search API is required for V1.
- Every factual claim in the final research artifact must reference at least one collected source ID.

## Initial search backend

V1 uses the `ddgs` package for web search. It is replaceable behind a search-provider interface so SearXNG, Brave Search, Bing or another provider can be added later without changing agent logic.

## Output contract

`research_result.json` contains:

- task_id
- objective
- search_queries
- sources[]
- verified_facts[]
- inferences[]
- unresolved[]
- conclusion
- recommended_next_actions[]
- generated_at

`research_result.md` is a human-readable rendering with numbered source references.

## Acceptance

The first Research Agent implementation is accepted when:

- unit tests pass;
- dry-run behavior remains compatible;
- live Ollama generation supports Qwen thinking models safely;
- the agent can search and collect at least one source when Internet is available;
- malformed/unreachable pages are recorded rather than crashing the whole task;
- source lineage is preserved in JSON and Markdown.
