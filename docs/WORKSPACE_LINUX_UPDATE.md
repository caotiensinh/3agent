# WorkSpace Linux In-Place Update

This update path is for an already-installed Linux WorkSpace node with an existing repository and `.venv`.
It is intentionally application-only.

## Safety contract

The updater:

- fast-forwards the existing `main` checkout from `origin/main`;
- refreshes the editable Python package in the existing `.venv`;
- restarts only the WorkSpace user chat service when that service is installed;
- verifies the chat service and health endpoint;
- snapshots NVIDIA GPU inventory before and after;
- observes GitHub self-hosted runner service listings but never stops, restarts, installs, removes, or reconfigures them.

The updater does **not** run APT, change the kernel, install/remove NVIDIA drivers, reboot the host, recreate the Python environment, reinstall Ollama/model workers, or rerun the full machine bootstrap.

## Command

From an existing deployment at `$HOME/3agent`:

```bash
cd "$HOME/3agent" && \
WORKSPACE_EXPECTED_GPU_COUNT=2 bash scripts/update_workspace_linux.sh
```

`WORKSPACE_EXPECTED_GPU_COUNT=2` makes the update fail before package refresh when the expected dual-GPU inventory is not present. The script also requires the GPU name/UUID inventory to remain unchanged after the application update.

## Manual equivalent

The minimal source/package update remains:

```bash
cd "$HOME/3agent" && \
git fetch origin main && \
git checkout main && \
git merge --ff-only origin/main && \
./.venv/bin/python -m pip install -e . && \
systemctl --user restart 3agent-chat.service
```

Use the scripted path when possible because it additionally validates branch state, GPU inventory, service health, and runner-service stability.
