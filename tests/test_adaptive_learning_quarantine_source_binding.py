import unittest

from three_agent.adaptive_learning_curation import ACTION_DOMAIN_REVISE_OR_ARCHIVE_REVIEW
from three_agent.adaptive_learning_effectiveness import SIGNAL_REVIEW
from three_agent.adaptive_learning_maintenance import (
    TYPE_DOMAIN_REVISION_OR_RETIREMENT_REVIEW,
    AdaptiveMaintenanceRecommendation,
)
from three_agent.adaptive_learning_quarantine import (
    AdaptiveLearningQuarantineError,
    QuarantineReviewRecommendation,
)


class AdaptiveLearningQuarantineSourceBindingTests(unittest.TestCase):
    def test_domain_review_label_with_non_domain_signal_is_rejected(self):
        forged_source = AdaptiveMaintenanceRecommendation(
            proposal_id="curation:" + "1" * 64,
            item_id="knowledge:quarantine:forged-signal",
            knowledge_sha256="sha256:" + "2" * 64,
            candidate_sha256="sha256:" + "3" * 64,
            active_level="approved",
            domain="network",
            advisory_signal=SIGNAL_REVIEW,
            curation_action=ACTION_DOMAIN_REVISE_OR_ARCHIVE_REVIEW,
            recommendation_type=TYPE_DOMAIN_REVISION_OR_RETIREMENT_REVIEW,
            human_review_required=True,
            domain_review_required=True,
            reason_codes=("FORGED_DOMAIN_REVIEW_LABEL",),
        ).validate()

        with self.assertRaisesRegex(
            AdaptiveLearningQuarantineError,
            "QUARANTINE_SOURCE_SIGNAL_INVALID",
        ):
            QuarantineReviewRecommendation.create(
                source_receipt_sha256="sha256:" + "4" * 64,
                source=forged_source,
            )


if __name__ == "__main__":
    unittest.main()
