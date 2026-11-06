"""Private, durable single-host issuance state; no automatic retry after uncertainty."""
from __future__ import annotations

import json
import os
import sqlite3
import stat
from contextlib import closing
from pathlib import Path
from typing import Any


class ArtifactExecutionStateError(RuntimeError):
    pass


class SQLiteArtifactExecutionStore:
    def __init__(self, path: Path) -> None:
        path = path.absolute()
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        parent = path.parent.stat()
        if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) & 0o077:
            raise ArtifactExecutionStateError("issuance directory must be private to its owner")
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) & 0o077 or info.st_nlink != 1):
                raise ArtifactExecutionStateError("issuance state must be a private regular file")
        finally:
            os.close(fd)
        self.path = path
        with closing(self._connect()) as db, db:
            db.execute("""CREATE TABLE IF NOT EXISTS artifact_execution (
                job_key TEXT PRIMARY KEY, job_sha256 TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('issuing','admitted','authorizing','authorized','failed')),
                documents TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )""")

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=5)
        db.execute("PRAGMA synchronous=FULL")
        return db

    def begin(self, job_key: str, job_sha256: str, *, create: bool = True) -> tuple[bool, dict[str, Any]]:
        with closing(self._connect()) as db, db:
            inserted = create and db.execute(
                "INSERT INTO artifact_execution(job_key,job_sha256,status) VALUES(?,?,'issuing') "
                "ON CONFLICT(job_key) DO NOTHING", (job_key, job_sha256),
            ).rowcount == 1
            row = db.execute("SELECT job_sha256,status,documents FROM artifact_execution WHERE job_key=?",
                             (job_key,)).fetchone()
            if row is None or row[0] != job_sha256:
                raise ArtifactExecutionStateError("claimed job changed its immutable issuance material")
            if not inserted and row[1] != "admitted":
                raise ArtifactExecutionStateError("job already consumed or requires explicit recovery")
            return inserted, json.loads(row[2])

    def transition(
        self, job_key: str, *, before: str, after: str, documents: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        encoded = None if documents is None else json.dumps(
            documents, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
        )
        if encoded is not None and len(encoded.encode()) > 512 * 1024:
            raise ArtifactExecutionStateError("issuance documents exceed their bound")
        with closing(self._connect()) as db, db:
            updated = db.execute(
                "UPDATE artifact_execution SET status=?,documents=COALESCE(?,documents),"
                "updated_at=CURRENT_TIMESTAMP WHERE job_key=? AND status=?",
                (after, encoded, job_key, before),
            ).rowcount
            if updated != 1:
                raise ArtifactExecutionStateError("issuance state already consumed or unavailable")
            row = db.execute("SELECT documents FROM artifact_execution WHERE job_key=?", (job_key,)).fetchone()
            if row is None:
                raise ArtifactExecutionStateError("issuance state disappeared")
            result: dict[str, Any] = json.loads(row[0])
            return result
