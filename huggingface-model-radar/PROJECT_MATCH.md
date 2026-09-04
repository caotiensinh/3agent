# AI modules phù hợp với các dự án hiện tại

_Seed snapshot: **2026-09-04 JST**. Subsequent updates are automatic._

## WorkSpace — Network / Security Analyst

| Model | Nổi bật | Dùng vào đâu |
|---|---|---|
| [sentence-transformers/all-MiniLM-L6-v2](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2) | Top download · rất nhẹ | Log embedding, similarity, RAG. |
| [BAAI/bge-m3](https://huggingface.co/BAAI/bge-m3) | Multilingual embedding | Search log/tài liệu Nhật-Anh-Việt. |
| [cross-encoder/ms-marco-MiniLM-L6-v2](https://huggingface.co/cross-encoder/ms-marco-MiniLM-L6-v2) | Reranker phổ biến | Rerank evidence/log sau vector search. |
| [BAAI/bge-reranker-v2-m3](https://huggingface.co/BAAI/bge-reranker-v2-m3) | Multilingual reranker | Tăng precision cho analyst/RAG. |
| [amazon/chronos-2](https://huggingface.co/amazon/chronos-2) | Time-series forecasting | Bandwidth/load/capacity prediction. |
| [Qwen/Qwen3-8B](https://huggingface.co/Qwen/Qwen3-8B) | Local LLM | Analyst summarization/reasoning. |

## CameraOps AI / Bear Detection / VMS

| Model | Nổi bật | Dùng vào đâu |
|---|---|---|
| [openai/clip-vit-base-patch32](https://huggingface.co/openai/clip-vit-base-patch32) | Zero-shot vision | Tìm camera/event bằng câu tự nhiên. |
| [Qwen/Qwen3.5-9B](https://huggingface.co/Qwen/Qwen3.5-9B) | Vision-language | Mô tả và hỏi đáp về frame/snapshot. |
| [Qwen/Qwen3.6-35B-A3B-FP8](https://huggingface.co/Qwen/Qwen3.6-35B-A3B-FP8) | VLM lớn | Visual reasoning ở server GPU. |
| [timm/efficientnet_b3.ra2_in1k](https://huggingface.co/timm/efficientnet_b3.ra2_in1k) | Efficient classifier | Edge image classification. |

## EIR / Container Document AI

| Model | Nổi bật | Dùng vào đâu |
|---|---|---|
| [Qwen/Qwen3.5-9B](https://huggingface.co/Qwen/Qwen3.5-9B) | VLM | Đọc/hiểu ảnh tài liệu, OCR hậu xử lý. |
| [BAAI/bge-m3](https://huggingface.co/BAAI/bge-m3) | Multilingual embedding | Search EIR/document fields và knowledge. |
| [cross-encoder/ms-marco-MiniLM-L6-v2](https://huggingface.co/cross-encoder/ms-marco-MiniLM-L6-v2) | Reranker | Xếp lại kết quả tìm tài liệu. |

## SuperConnect / RTSP / Network QoS

| Model | Nổi bật | Dùng vào đâu |
|---|---|---|
| [amazon/chronos-2](https://huggingface.co/amazon/chronos-2) | Time-series forecasting | Dự báo bandwidth, latency, load. |
| [sentence-transformers/all-MiniLM-L6-v2](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2) | Tiny embedding | Cluster/similarity cho log sự cố. |
| [Qwen/Qwen3-8B](https://huggingface.co/Qwen/Qwen3-8B) | Local LLM | Giải thích RCA và đề xuất vận hành. |

## Japanese Field Assistant

| Model | Nổi bật | Dùng vào đâu |
|---|---|---|
| [jonatasgrosman/wav2vec2-large-xlsr-53-japanese](https://huggingface.co/jonatasgrosman/wav2vec2-large-xlsr-53-japanese) | Japanese ASR | Chuyển giọng nói tiếng Nhật thành text. |
| [sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2](https://huggingface.co/sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2) | Multilingual embedding | Search hướng dẫn Nhật/Anh/Việt. |
| [intfloat/multilingual-e5-small](https://huggingface.co/intfloat/multilingual-e5-small) | Small multilingual embedding | RAG nhẹ cho mini-PC/server. |
| [hexgrad/Kokoro-82M](https://huggingface.co/hexgrad/Kokoro-82M) | Small TTS | Voice feedback sau khi kiểm tra language support. |

## Local LLM / Agent / Coding

| Model | Nổi bật | Dùng vào đâu |
|---|---|---|
| [Qwen/Qwen3-8B](https://huggingface.co/Qwen/Qwen3-8B) | 8B local LLM | General local agent. |
| [unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF](https://huggingface.co/unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF) | GGUF coding model | Local coding/automation agent. |
| [Qwen/Qwen3.5-9B](https://huggingface.co/Qwen/Qwen3.5-9B) | Multimodal | Agent cần hiểu screenshot/image. |

## Quy tắc chọn production

Downloads/trending chỉ là tín hiệu sàng lọc. Production vẫn phải PASS: **license → security → hardware → benchmark → real-data test**.
