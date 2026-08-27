# Ollama/Qwen3 validation note

The application installer originally required `.response` from `/api/generate` to be non-empty after a very short generation. Qwen3 supports thinking mode in Ollama, so short generations can spend the token budget in the separate `thinking` field and leave `response` empty.

The project must therefore disable thinking for installer health checks and ordinary structured agent calls unless a specific agent mode explicitly requests thinking. For `/api/generate`, send `"think": false` and allow a reasonable output budget.

This is a validation/harness correction, not a GPU or NVIDIA driver failure.
