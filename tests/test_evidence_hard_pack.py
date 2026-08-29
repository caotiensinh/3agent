import unittest

from three_agent.evidence_packing import (
    EvidencePackingPolicy,
    PACKING_ALGORITHM_VERSION,
    pack_evidence_sources,
)


class Source:
    def __init__(self, source_id: str, text: str, *, title: str = "Title"):
        self.source_id = source_id
        self.title = title
        self.url = f"https://example.test/{source_id}"
        self.extracted_text = text


def header(source: Source) -> str:
    return (
        f"[{source.source_id}]\n"
        f"TITLE: {source.title}\n"
        f"URL: {source.url}\n"
        "TEXT:\n"
    )


class EvidenceHardPackTests(unittest.TestCase):
    def test_large_budget_preserves_historical_rendering(self):
        sources = [Source("S1", "alpha"), Source("S2", "beta")]
        expected = "\n---\n".join(
            header(source) + source.extracted_text + "\n" for source in sources
        )
        rendered, receipt = pack_evidence_sources(
            sources,
            policy=EvidencePackingPolicy(mode="legacy_v1", budget_chars=48000),
        )
        self.assertEqual(rendered, expected)
        self.assertEqual(receipt["packing_algorithm_version"], PACKING_ALGORITHM_VERSION)
        self.assertTrue(receipt["hard_budget_respected"])
        self.assertFalse(receipt["critical_provenance_header_truncated"])

    def test_separator_is_counted_inside_hard_budget(self):
        first = Source("S1", "a")
        second = Source("S2", "b" * 50)
        first_block = header(first) + "a\n"
        # Enough for source 1 and most of source 2 only when the separator is
        # correctly charged to the same hard budget.
        budget = len(first_block) + len("\n---\n") + len(header(second)) + 7
        rendered, receipt = pack_evidence_sources(
            [first, second],
            policy=EvidencePackingPolicy(mode="quality_ranked_v1", budget_chars=budget),
        )
        self.assertLessEqual(len(rendered), budget)
        self.assertEqual(receipt["packed_output_chars"], len(rendered))
        self.assertEqual(receipt["separator_chars"], len("\n---\n"))
        self.assertTrue(receipt["hard_budget_respected"])

    def test_partial_provenance_header_is_never_emitted(self):
        source = Source("S1", "evidence")
        budget = len(header(source))
        rendered, receipt = pack_evidence_sources(
            [source],
            policy=EvidencePackingPolicy(mode="quality_ranked_v1", budget_chars=budget),
        )
        self.assertEqual(rendered, "")
        item = receipt["sources"][0]
        self.assertFalse(item["supplied"])
        self.assertFalse(item["provenance_header_preserved"])
        self.assertEqual(
            item["skip_reason"],
            "provenance_header_or_first_text_char_does_not_fit",
        )
        self.assertFalse(receipt["critical_provenance_header_truncated"])

    def test_when_header_fits_body_is_truncated_not_header(self):
        source = Source("S1", "abcdefghij", title="A")
        budget = len(header(source)) + 4
        rendered, receipt = pack_evidence_sources(
            [source],
            policy=EvidencePackingPolicy(mode="quality_ranked_v1", budget_chars=budget),
        )
        self.assertEqual(rendered, header(source) + "abcd")
        self.assertEqual(receipt["sources"][0]["supplied_text_chars"], 4)
        self.assertTrue(receipt["sources"][0]["provenance_header_preserved"])
        self.assertEqual(len(rendered), budget)

    def test_later_source_is_skipped_when_separator_plus_header_cannot_fit(self):
        first = Source("S1", "alpha")
        second = Source("S2", "beta")
        first_block = header(first) + "alpha\n"
        budget = len(first_block) + len("\n---\n") + len(header(second))
        rendered, receipt = pack_evidence_sources(
            [first, second],
            policy=EvidencePackingPolicy(mode="quality_ranked_v1", budget_chars=budget),
        )
        self.assertEqual(rendered, first_block)
        self.assertEqual(receipt["supplied_source_count"], 1)
        self.assertEqual(receipt["sources_skipped_for_header_budget"], 1)
        self.assertLessEqual(len(rendered), budget)

    def test_receipt_remains_metadata_only(self):
        secret = "CONFIDENTIAL-BUSINESS-CONTENT"
        source = Source("S1", secret, title="SECRET-TITLE")
        _, receipt = pack_evidence_sources(
            [source],
            policy=EvidencePackingPolicy(mode="legacy_v1", budget_chars=48000),
        )
        serialized = repr(receipt)
        self.assertNotIn(secret, serialized)
        self.assertNotIn("SECRET-TITLE", serialized)
        self.assertNotIn("example.test", serialized)
        self.assertFalse(receipt["raw_content_logged"])


if __name__ == "__main__":
    unittest.main()
