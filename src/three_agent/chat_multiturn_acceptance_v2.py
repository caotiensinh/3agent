from __future__ import annotations

# Keep the authoritative P2 corpus/evaluator unchanged.  This wrapper only swaps
# the ordinary-chat service implementation under test to the current production
# ContractAwareProjectChatService before delegating to the existing CLI.
from . import chat_multiturn_acceptance as acceptance
from .chat_service_fidelity_v2 import ContractAwareProjectChatService


def main() -> int:
    acceptance.ContextAwareProjectChatService = ContractAwareProjectChatService
    return acceptance.main()


if __name__ == "__main__":
    raise SystemExit(main())
