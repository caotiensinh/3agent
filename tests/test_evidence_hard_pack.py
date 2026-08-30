import unittest

from three_agent.evidence_packing import (
    EvidencePackingPolicy,
    PACKING_ALGORITHM_VERSION,
    pack_evidence_sources,
)


class Source:
    def __init__(
        self,
        source_id: str,
        text: str,
        *,
        title: str = "Title",
        url: str | None = None,
    ):
        self.source_id = source_id
        self.title = title
        self.url = url or f"https://example.test/{source_id}"
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
        self.assertFalse(receipt["exact_body_dedupe_enabled"])
        self.assertEqual(receipt["exact_duplicate_bodies_suppressed"], 0)

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
        self.assertFalse(receipt["sources"][0]["body_fully_supplied"])
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

    def test_exact_duplicate_body_is_suppressed_only_when_opted_in(self):
        body = "same cleaned evidence body"
        first = Source("S1", body, url="https://a.example/report")
        second = Source("S2", body, url="https://b.example/mirror")

        baseline, baseline_receipt = pack_evidence_sources(
            [first, second],
            policy=EvidencePackingPolicy(
                mode="legacy_v1",
                budget_chars=48000,
                exact_body_dedupe=False,
            ),
        )
        candidate, candidate_receipt = pack_evidence_sources(
            [first, second],
            policy=EvidencePackingPolicy(
                mode="legacy_v1",
                budget_chars=48000,
                exact_body_dedupe=True,
            ),
        )

        self.assertIn("https://a.example/report", baseline)
        self.assertIn("https://b.example/mirror", baseline)
        self.assertIn("https://a.example/report", candidate)
        self.assertNotIn("https://b.example/mirror", candidate)
        self.assertGreater(len(baseline), len(candidate))
        self.assertEqual(baseline_receipt["exact_duplicate_bodies_suppressed"], 0)
        self.assertEqual(candidate_receipt["exact_duplicate_bodies_suppressed"], 1)
        self.assertEqual(candidate_receipt["exact_duplicate_text_chars_saved"], len(body))

        first_item, second_item = candidate_receipt["sources"]
        self.assertTrue(first_item["body_fully_supplied"])
        self.assertFalse(first_item["exact_body_duplicate_suppressed"])
        self.assertFalse(second_item["supplied"])
        self.assertTrue(second_item["exact_body_duplicate_suppressed"])
        self.assertEqual(second_item["duplicate_of_source_id"], "S1")
        self.assertEqual(
            second_item["skip_reason"],
            "exact_body_duplicate_of_fully_supplied_source",
        )

    def test_truncated_body_never_establishes_duplicate_canonical(self):
        body = "abcdefghij"
        first = Source("S1", body)
        second = Source("S2", body)
        first_budget = len(header(first)) + 4

        rendered, receipt = pack_evidence_sources(
            [first, second],
            policy=EvidencePackingPolicy(
                mode="legacy_v1",
                budget_chars=first_budget,
                exact_body_dedupe=True,
            ),
        )

        self.assertEqual(rendered, header(first) + "abcd")
        self.assertFalse(receipt["sources"][0]["body_fully_supplied"])
        self.assertFalse(receipt["sources"][1]["exact_body_duplicate_suppressed"])
        self.assertIsNone(receipt["sources"][1]["duplicate_of_source_id"])
        self.assertEqual(receipt["exact_duplicate_bodies_suppressed"], 0)

    def test_skipped_oversized_header_never_establishes_duplicate_canonical(self):
        body = "same body"
        first = Source("S1", body, title="X" * 200)
        second = Source("S2", body, title="B")
        budget = len(header(second)) + len(body) + 1

        rendered, receipt = pack_evidence_sources(
            [first, second],
            policy=EvidencePackingPolicy(
                mode="legacy_v1",
                budget_chars=budget,
                exact_body_dedupe=True,
            ),
        )

        self.assertNotIn("[S1]", rendered)
        self.assertIn("[S2]", rendered)
        self.assertEqual(receipt["sources"][0]["skip_reason"], "provenance_header_or_first_text_char_does_not_fit")
        self.assertTrue(receipt["sources"][1]["body_fully_supplied"])
        self.assertFalse(receipt["sources"][1]["exact_body_duplicate_suppressed"])

    def test_receipt_remains_metadata_only_and_does_not_emit_body_hash(self):
        secret = "CONFIDENTIAL-BUSINESS-CONTENT"
        sources = [
            Source("S1", secret, title="SECRET-TITLE"),
            Source("S2", secret, title="OTHER-TITLE"),
        ]
        _, receipt = pack_evidence_sources(
            sources,
            policy=EvidencePackingPolicy(
                mode="legacy_v1",
                budget_chars=48000,
                exact_body_dedupe=True,
            ),
        )
        serialized = repr(receipt)
        self.assertNotIn(secret, serialized)
        self.assertNotIn("SECRET-TITLE", serialized)
        self.assertNotIn("example.test", serialized)
        self.assertFalse(receipt["body_hashes_logged"])
        self.assertFalse(receipt["raw_content_logged"])


if __name__ == "__main__":
    unittest.main()
