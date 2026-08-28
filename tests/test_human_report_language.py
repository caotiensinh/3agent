import unittest

from three_agent.human_report import build_report_data, compose_expert_report, render_markdown


class FakeLLM:
    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.calls = 0

    def generate_json(self, *args, **kwargs):
        del args, kwargs
        self.calls += 1
        return self.outputs[min(self.calls - 1, len(self.outputs) - 1)]


class HumanReportLanguageTests(unittest.TestCase):
    @staticmethod
    def handoff():
        return {
            "presentation_ready": True,
            "blockers": [],
            "key_facts": [{"claim": "Verified product fact.", "source_ids": ["S1"]}],
            "inferences": [{"claim": "The product may fit the use case.", "source_ids": ["S1"]}],
            "conflicts": [],
            "unresolved_items": ["Market share was not verified."],
            "conclusion": "The available primary evidence confirms the product specification.",
            "recommended_next_actions": ["Collect a direct competitor source."],
            "sources": [{"source_id": "S1", "title": "Official source", "url": "https://example.com"}],
        }

    @staticmethod
    def vi_output():
        return {
            "report_title": "Đánh giá chuyên sâu về sản phẩm",
            "executive_summary": (
                "Báo cáo này tổng hợp bằng chứng đã được xác minh về đặc tính của sản phẩm. "
                "Nguồn chính thức xác nhận dữ kiện cốt lõi, tạo cơ sở để đánh giá khả năng áp dụng "
                "trong nghiên cứu và phát triển. Tuy nhiên, mức độ phù hợp thực tế vẫn cần được kiểm chứng thêm."
            ),
            "scope_and_method": (
                "Phân tích chỉ sử dụng các bằng chứng đã được Agent 1 xác minh, đồng thời phân biệt rõ "
                "dữ kiện, suy luận và nội dung chưa được xác nhận."
            ),
            "findings": [{
                "heading": "Dữ kiện đã được xác minh",
                "text": "Nguồn chính thức xác nhận dữ kiện cốt lõi của sản phẩm và cung cấp cơ sở cho đánh giá kỹ thuật tiếp theo.",
                "source_ids": ["S1"],
            }],
            "analysis": [{
                "heading": "Hàm ý đối với R&D",
                "text": "Dựa trên bằng chứng hiện có, sản phẩm có tiềm năng phù hợp với trường hợp sử dụng nhưng cần thử nghiệm trong môi trường mục tiêu.",
                "source_ids": ["S1"],
            }],
            "limitations": ["Thị phần chưa được xác minh từ nguồn hiện có và không nên được suy đoán."],
            "recommendations": [{
                "priority": "P1",
                "text": "Thu thập thêm nguồn trực tiếp về đối thủ và thực hiện đánh giá so sánh trước khi quyết định triển khai.",
                "source_ids": ["S1"],
            }],
        }

    @staticmethod
    def ja_output():
        return {
            "report_title": "製品適合性に関する専門評価",
            "executive_summary": (
                "本レポートは、検証済みの情報源に基づいて製品の主要な特性を整理し、研究開発での適用可能性を評価したものである。"
                "公式情報から中核となる事実は確認できている一方、実運用環境への適合性については追加検証が必要である。"
                "したがって、現時点では導入判断を確定せず、比較評価と実証試験を段階的に進めることが妥当である。"
            ),
            "scope_and_method": (
                "分析対象はAgent 1が検証した根拠に限定し、確認済み事実、推論、未確認事項を明確に分離した。"
                "有効な情報源を参照できない主張は採用せず、判断に必要な不確実性を残したまま評価している。"
            ),
            "findings": [{
                "heading": "確認済みの製品情報",
                "text": "公式情報源により製品の中核的な事実が確認されており、用途適合性を検討するための基礎情報として利用できる。",
                "source_ids": ["S1"],
            }],
            "analysis": [{
                "heading": "研究開発への示唆",
                "text": "現時点の根拠からは対象用途への適合可能性が示されるが、実環境での性能まで確認されたわけではなく、追加評価が必要である。",
                "source_ids": ["S1"],
            }],
            "limitations": ["市場シェアは現在の情報源では確認できず、根拠のない推定は行わない。"],
            "recommendations": [{"priority": "P1", "text": "競合製品の一次情報を追加収集し、同一条件で比較評価を実施する。", "source_ids": ["S1"]}],
        }

    def test_vietnamese_is_full_body_not_heading_only(self):
        base = build_report_data("TASK-1", "Product review", "Compare", self.handoff(), "vi")
        llm = FakeLLM([self.vi_output()])
        text = render_markdown(compose_expert_report(base, self.handoff(), llm))
        self.assertEqual(llm.calls, 1)
        self.assertIn("## Tóm tắt điều hành", text)
        self.assertIn("## Phạm vi và phương pháp", text)
        self.assertIn("## Phân tích chuyên gia và hàm ý", text)
        self.assertIn("### 1. Dữ kiện đã được xác minh", text)
        self.assertIn("**P1**", text)
        self.assertNotIn("Verified product fact.", text)
        self.assertNotIn("The product may fit the use case.", text)
        self.assertNotIn("Market share was not verified.", text)

    def test_japanese_is_full_body_not_heading_only(self):
        base = build_report_data("TASK-1", "Product review", "Compare", self.handoff(), "ja")
        llm = FakeLLM([self.ja_output()])
        text = render_markdown(compose_expert_report(base, self.handoff(), llm))
        self.assertIn("## エグゼクティブサマリー", text)
        self.assertIn("## 調査範囲・方法", text)
        self.assertIn("## 専門的分析・示唆", text)
        self.assertIn("### 1. 確認済みの製品情報", text)
        self.assertNotIn("Verified product fact.", text)
        self.assertNotIn("The product may fit the use case.", text)

    def test_mixed_language_retries_once_then_fails_closed(self):
        bad = {
            "report_title": "Báo cáo sản phẩm",
            "executive_summary": "The available primary evidence confirms the product specification and this report remains in English.",
            "scope_and_method": "The report uses verified evidence only.",
            "findings": [{"heading": "Kết quả", "text": "The verified product fact is supported by the official source.", "source_ids": ["S1"]}],
            "analysis": [{"heading": "Phân tích", "text": "The product may fit the use case but further validation is required.", "source_ids": ["S1"]}],
            "limitations": ["Market share was not verified."],
            "recommendations": [{"priority": "P1", "text": "Collect a direct competitor source.", "source_ids": ["S1"]}],
        }
        base = build_report_data("TASK-1", "Product review", "Compare", self.handoff(), "vi")
        llm = FakeLLM([bad, bad])
        with self.assertRaisesRegex(ValueError, "mixed-language"):
            compose_expert_report(base, self.handoff(), llm)
        self.assertEqual(llm.calls, 2)

    def test_unknown_source_reference_cannot_enter_expert_report(self):
        bad_ref = self.vi_output()
        bad_ref["findings"] = [{"heading": "Không hợp lệ", "text": "Nội dung này viện dẫn nguồn không tồn tại.", "source_ids": ["S999"]}]
        base = build_report_data("TASK-1", "Product review", "Compare", self.handoff(), "vi")
        llm = FakeLLM([bad_ref, bad_ref])
        with self.assertRaises(ValueError):
            compose_expert_report(base, self.handoff(), llm)


if __name__ == "__main__":
    unittest.main()
