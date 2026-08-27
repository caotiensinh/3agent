# Research Agent V1 Acceptance Checklist

- [ ] Existing harness tests pass.
- [ ] Ollama Qwen3 health check uses non-thinking mode for deterministic output.
- [ ] Local LLM client can request JSON output and parse it safely.
- [ ] Research Agent creates a search plan from the task request.
- [ ] Search is performed through a replaceable provider abstraction.
- [ ] Web page retrieval goes through InternetGateway.
- [ ] At least title, URL, snippet and extracted text are retained for each usable source.
- [ ] Fetch failures are recorded and do not abort unrelated sources.
- [ ] Final synthesis references source IDs.
- [ ] Facts, inference and unresolved items are separate fields.
- [ ] JSON and Markdown research artifacts are created.
- [ ] CI covers parsing, citations and failure tolerance.
