from __future__ import annotations

# V4 starts the new user-facing release line requested for WorkSpace.
#
# The PEP 440 epoch is intentionally retained only in Python package metadata so
# upgrades remain monotonic from the historical 0.16.0 line. Product/UI/API
# surfaces use DISPLAY_VERSION and never expose the epoch as the product label.
PACKAGE_VERSION = "1!0.0.1"
DISPLAY_VERSION = "ver.0.0.1"
RELEASE_GENERATION = "v4"
VERSION_SCHEME = "workspace-release/v2"
