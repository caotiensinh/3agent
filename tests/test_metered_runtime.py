import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from three_agent.inference_scope import inference_scope
from three_agent.llm import LocalLLMError
from three_agent.metered_runtime import (
    MeteredAdaptiveOllamaClient,
    MeteredExecutionGateway,
    MeteredInternetGateway,
)
from three_agent.resource_budget import ResourceAdmissionError
from three_agent.resource_events import ResourceEventRecorder


class FakeInternet:
    def get(self, agent_id, task_id, url, timeout=30):
        del agent_id, task_id, timeout
        return url.encode("utf-8")

    def search_get(self, agent_id, task_id, endpoint, params, timeout=30):
        del agent_id, task_id, params, timeout
        return endpoint.encode("utf-8")

    def grant_public_fetch(self, agent_id, task_id, url):
        del agent_id, task_id, url
        return "opaque-grant"

    def fetch_granted(self, agent_id, task_id, grant_token, timeout=30):
        del agent_id, task_id, grant_token, timeout
        return b"ok"

    def post_json(self, agent_id, task_id, url, payload, timeout=30):
        del agent_id, task_id, url, payload, timeout
        return b"ok"


class FakeExecution:
    def run(self, agent_id, task_id, argv, cwd=None):
        del agent_id, task_id, cwd
        return SimpleNamespace(returncode=0, stdout=" ".join(argv), stderr="")


class FakeModel:
    def __init__(self, model, outcomes):
        self.config = SimpleNamespace(model=model)
        self.outcomes = list(outcomes)

    def generate(self, *args, **kwargs):
        del args, kwargs
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def generate_json(self, *args, **kwargs):
        return self.generate(*args, **kwargs)

    def unload(self):
        return None


class MeteredRuntimeTests(unittest.TestCase):
    def _rows(self, path):
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]

    def test_gateway_metrics_never_store_url_or_command_argv(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "resource.jsonl"
            recorder = ResourceEventRecorder(path)
            internet = MeteredInternetGateway(FakeInternet(), recorder)
            execution = MeteredExecutionGateway(FakeExecution(), recorder)
            secret_url = "https://example.com/private?token=SECRET_URL_TOKEN"
            secret_argv = ["echo", "SECRET_ARG_VALUE"]
            internet.get("research", "TASK-1", secret_url)
            execution.run("research", "TASK-1", secret_argv)
            raw = path.read_text(encoding="utf-8")
            self.assertNotIn("SECRET_URL_TOKEN", raw)
            self.assertNotIn("SECRET_ARG_VALUE", raw)
            rows = self._rows(path)
            self.assertEqual([row["event_type"] for row in rows], ["tool_call", "tool_call"])
            self.assertEqual([row["task_id"] for row in rows], ["TASK-1", "TASK-1"])

    def test_primary_failure_records_one_retry_and_one_escalation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "resource.jsonl"
            recorder = ResourceEventRecorder(path)
            primary = FakeModel("small", [LocalLLMError("secret failure detail")])
            deep = FakeModel("deep", ["ok"])
            client = MeteredAdaptiveOllamaClient(
                primary,
                deep=deep,
                deep_escalation=True,
                role="research",
                resource_events=recorder,
            )
            with inference_scope("TASK-2", agent_id="research", stage="research"):
                self.assertEqual(client.generate("system", "short prompt"), "ok")
            raw = path.read_text(encoding="utf-8")
            self.assertNotIn("secret failure detail", raw)
            rows = self._rows(path)
            self.assertEqual([row["event_type"] for row in rows], ["model_retry", "model_escalation"])
            self.assertEqual([row["task_id"] for row in rows], ["TASK-2", "TASK-2"])
            self.assertEqual(rows[0]["model"], "small")
            self.assertEqual(rows[0]["target"], "deep")

    def test_resource_denial_never_creates_upward_escalation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "resource.jsonl"
            recorder = ResourceEventRecorder(path)
            primary = FakeModel("small", [ResourceAdmissionError("too busy")])
            deep = FakeModel("deep", ["must-not-run"])
            client = MeteredAdaptiveOllamaClient(
                primary,
                deep=deep,
                deep_escalation=True,
                role="research",
                resource_events=recorder,
            )
            with inference_scope("TASK-3", agent_id="research", stage="research"):
                with self.assertRaises(ResourceAdmissionError):
                    client.generate("system", "short prompt")
            self.assertFalse(path.exists())

    def test_preferred_deep_failure_falls_back_with_retry_but_no_escalation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "resource.jsonl"
            recorder = ResourceEventRecorder(path)
            primary = FakeModel("small", ["primary-ok"])
            deep = FakeModel("deep", [LocalLLMError("deep failed")])
            client = MeteredAdaptiveOllamaClient(
                primary,
                deep=deep,
                deep_escalation=True,
                deep_prompt_chars=2000,
                role="research",
                resource_events=recorder,
            )
            with inference_scope("TASK-4", agent_id="research", stage="research"):
                result = client.generate("system", "x" * 2200)
            self.assertEqual(result, "primary-ok")
            rows = self._rows(path)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["event_type"], "model_retry")
            self.assertEqual(rows[0]["action"], "deep_to_primary")


if __name__ == "__main__":
    unittest.main()
