from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

from .prompt_compiler import PromptCompilation, PromptCompilationError, PromptCompiler

TZ = ZoneInfo("Asia/Tokyo")


class PromptCompilationLedger:
    """Persist only prompt compiler provenance/digests, never another raw prompt copy."""

    def __init__(self, store: Any) -> None:
        self.store = store
        self.db_path = store.db_path

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def initialize(self) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS task_prompt_compilations (
                    task_id TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    compiler_version TEXT NOT NULL,
                    original_sha256 TEXT NOT NULL,
                    compiled_sha256 TEXT NOT NULL,
                    original_chars INTEGER NOT NULL,
                    compiled_chars INTEGER NOT NULL,
                    original_utf8_bytes INTEGER NOT NULL,
                    compiled_utf8_bytes INTEGER NOT NULL,
                    duplicate_blocks_removed INTEGER NOT NULL,
                    repeated_block_occurrences INTEGER NOT NULL,
                    token_savings_measured INTEGER NOT NULL DEFAULT 0 CHECK(token_savings_measured IN (0,1)),
                    bound_at TEXT NOT NULL,
                    FOREIGN KEY(task_id) REFERENCES tasks(task_id)
                )
                """
            )

    def get(self, task_id: str) -> dict[str, Any] | None:
        self.initialize()
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM task_prompt_compilations WHERE task_id=?", (task_id,)
            ).fetchone()
        return dict(row) if row is not None else None

    def bind(self, task_id: str, compilation: PromptCompilation) -> dict[str, Any]:
        self.store.get_task(task_id)
        self.initialize()
        metadata = compilation.metadata()
        now = datetime.now(TZ).isoformat()
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT * FROM task_prompt_compilations WHERE task_id=?", (task_id,)
            ).fetchone()
            if existing is not None:
                record = dict(existing)
                for field in ("schema_version", "compiler_version", "original_sha256", "compiled_sha256"):
                    if str(record.get(field)) != str(metadata.get(field)):
                        raise PromptCompilationError(
                            f"Prompt compilation receipt is immutable: {field} mismatch"
                        )
                return record
            conn.execute(
                """
                INSERT INTO task_prompt_compilations(
                    task_id,schema_version,compiler_version,original_sha256,compiled_sha256,
                    original_chars,compiled_chars,original_utf8_bytes,compiled_utf8_bytes,
                    duplicate_blocks_removed,repeated_block_occurrences,token_savings_measured,bound_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,0,?)
                """,
                (
                    task_id,
                    compilation.schema_version,
                    compilation.compiler_version,
                    compilation.original_sha256,
                    compilation.compiled_sha256,
                    compilation.original_chars,
                    compilation.compiled_chars,
                    compilation.original_utf8_bytes,
                    compilation.compiled_utf8_bytes,
                    compilation.duplicate_blocks_removed,
                    compilation.repeated_block_occurrences,
                    now,
                ),
            )
        self.store.record_activity(
            task_id,
            "prompt_compiler",
            "prompt_compilation_bound",
            "ok",
            (
                f"compiler={compilation.compiler_version} "
                f"original_sha256={compilation.original_sha256} "
                f"compiled_sha256={compilation.compiled_sha256} "
                f"original_bytes={compilation.original_utf8_bytes} "
                f"compiled_bytes={compilation.compiled_utf8_bytes} "
                f"duplicates_removed={compilation.duplicate_blocks_removed} "
                "token_savings_measured=false raw_prompt_logged=false"
            ),
        )
        record = self.get(task_id)
        if record is None:
            raise RuntimeError("Prompt compilation receipt was not persisted")
        return record

    def compile_and_bind(self, task_id: str) -> PromptCompilation:
        task = self.store.get_task(task_id)
        compilation = PromptCompiler.compile(task.request)
        record = self.bind(task_id, compilation)
        if str(record["original_sha256"]) != compilation.original_sha256:
            raise PromptCompilationError("Original prompt changed after compiler binding")
        if str(record["compiled_sha256"]) != compilation.compiled_sha256:
            raise PromptCompilationError("Compiled prompt no longer matches immutable receipt")
        return compilation
