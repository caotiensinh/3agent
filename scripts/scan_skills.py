from __future__ import annotations

from pathlib import Path

from three_agent.skills import ApprovedSkillLoader


def main() -> int:
    root = Path(__file__).resolve().parents[1] / "skills"
    audited = ApprovedSkillLoader(root).audit_registry()
    print(f"skill-security-scan: PASS ({len(audited)} enabled skills)")
    for name in audited:
        print(f"  - {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
