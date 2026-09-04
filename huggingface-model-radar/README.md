# Hugging Face Model Radar

Một radar nhỏ để theo dõi các model AI nổi bật nhất trên Hugging Face mà không phải đọc hàng triệu repository.

## Mục tiêu

- Theo dõi một **elite pool: Top 300 model theo downloads**.
- Đánh dấu model trong elite pool nếu đồng thời đang **trending**.
- Giữ file ngắn: chỉ hiển thị **Top 50** trong `TOP_MODELS.md`.
- Tự ghép model phù hợp với các dự án hiện tại vào `PROJECT_MATCH.md`.
- Tự cập nhật bằng GitHub Actions **2 lần/ngày**.

Vì Hugging Face có hơn 3 triệu model, Top 300 nằm rất sâu bên trong nhóm Top 1.5%; đây là watchlist gọn chứ không cố liệt kê hàng chục nghìn model.

## File chính

- [`TOP_MODELS.md`](./TOP_MODELS.md) — tên model, điểm nổi bật, cách dùng.
- [`PROJECT_MATCH.md`](./PROJECT_MATCH.md) — model phù hợp với WorkSpace, CameraOps AI, EIR, SuperConnect, Japanese assistant và local agent.
- [`update_radar.py`](./update_radar.py) — script cập nhật.

## Cập nhật

GitHub Actions chạy lúc khoảng:

- `00:17 UTC` = `09:17 JST`
- `12:17 UTC` = `21:17 JST`

Ngoài ra có thể chạy thủ công bằng **Run workflow**.

## Chạy local

```bash
python huggingface-model-radar/update_radar.py
```

Không cần cài package ngoài Python standard library.

## Tiêu chí

Radar ưu tiên:

1. Downloads.
2. Trending overlap.
3. Task/pipeline phù hợp.
4. Likes chỉ dùng như tín hiệu phụ.

Radar **không tự coi model nổi tiếng là production-ready**. Trước khi tích hợp phải kiểm tra license, model card, remote code, file format, hardware và benchmark trên dữ liệu thật.
