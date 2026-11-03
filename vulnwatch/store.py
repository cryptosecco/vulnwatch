"""Local archive (sqlite). Its content is untrusted data: nothing here is a cached security verdict."""
import fcntl
import json
import os
import sqlite3
import uuid
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from .i18n import t
from .model import (
    Advisory,
    AuditResult,
    Finding,
    advisory_from_dict,
    audit_from_dict,
    finding_from_dict,
    to_dict,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS advisories (source TEXT NOT NULL, id TEXT NOT NULL, doc TEXT NOT NULL,
    fetched_at TEXT NOT NULL, PRIMARY KEY (source, id));
CREATE TABLE IF NOT EXISTS cursors (name TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pending (kind TEXT NOT NULL, key TEXT NOT NULL, seq INTEGER NOT NULL,
    PRIMARY KEY (kind, key));
CREATE TABLE IF NOT EXISTS runs (run_id TEXT PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT,
    status TEXT, summary TEXT);
CREATE TABLE IF NOT EXISTS findings (run_id TEXT NOT NULL, finding_id TEXT NOT NULL, doc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audits (run_id TEXT NOT NULL, finding_id TEXT NOT NULL, doc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ignores (finding_id TEXT PRIMARY KEY, reason TEXT NOT NULL, created_at TEXT NOT NULL);
"""


class Store:
    def __init__(self, path: str):
        self._db = sqlite3.connect(path)
        try:
            self._db.executescript(_SCHEMA)
            self._db.commit()
        except sqlite3.DatabaseError:
            self._db.close()
            raise

    def close(self) -> None:
        self._db.close()

    # advisories
    def put_advisory(self, adv: Advisory, fetched_at: str) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO advisories (source, id, doc, fetched_at) VALUES (?, ?, ?, ?)",
            (adv.source, adv.id, json.dumps(to_dict(adv)), fetched_at),
        )
        self._db.commit()

    def put_advisories(self, advs: Iterable[Advisory], fetched_at: str) -> None:
        self._db.executemany(
            "INSERT OR REPLACE INTO advisories (source, id, doc, fetched_at) VALUES (?, ?, ?, ?)",
            ((a.source, a.id, json.dumps(to_dict(a)), fetched_at) for a in advs),
        )
        self._db.commit()

    def get_advisory(self, source: str, id_: str) -> Optional[Advisory]:
        row = self._db.execute("SELECT doc FROM advisories WHERE source = ? AND id = ?", (source, id_)).fetchone()
        return advisory_from_dict(json.loads(row[0])) if row else None

    def has_advisory(self, source: str, id_: str) -> bool:
        return self._db.execute("SELECT 1 FROM advisories WHERE source = ? AND id = ?", (source, id_)).fetchone() is not None

    def advisories(self, source: Optional[str] = None, id_prefix: Optional[str] = None) -> Iterator[Advisory]:
        if source is None:
            cur = self._db.execute("SELECT doc FROM advisories ORDER BY source, id")
        elif id_prefix:
            cur = self._db.execute("SELECT doc FROM advisories WHERE source = ? AND substr(id, 1, ?) = ? ORDER BY id",
                                   (source, len(id_prefix), id_prefix))
        else:
            cur = self._db.execute("SELECT doc FROM advisories WHERE source = ? ORDER BY id", (source,))
        for (doc,) in cur:
            yield advisory_from_dict(json.loads(doc))

    # cursors
    def get_cursor(self, name: str) -> Optional[str]:
        row = self._db.execute("SELECT value FROM cursors WHERE name = ?", (name,)).fetchone()
        return row[0] if row else None

    def set_cursor(self, name: str, value: str) -> None:
        self._db.execute("INSERT OR REPLACE INTO cursors (name, value) VALUES (?, ?)", (name, value))
        self._db.commit()

    # pending queue
    def queue(self, kind: str, key: str) -> None:
        self._db.execute(
            "INSERT OR IGNORE INTO pending (kind, key, seq) "
            "VALUES (?, ?, (SELECT COALESCE(MAX(seq), 0) + 1 FROM pending))",
            (kind, key),
        )
        self._db.commit()

    def pending(self, kind: str, limit: int) -> List[str]:
        rows = self._db.execute("SELECT key FROM pending WHERE kind = ? ORDER BY seq LIMIT ?", (kind, limit))
        return [r[0] for r in rows]

    def done(self, kind: str, key: str) -> None:
        self._db.execute("DELETE FROM pending WHERE kind = ? AND key = ?", (kind, key))
        self._db.commit()

    # runs and findings
    def start_run(self, started_at: str) -> str:
        run_id = uuid.uuid4().hex[:12]
        self._db.execute("INSERT INTO runs (run_id, started_at) VALUES (?, ?)", (run_id, started_at))
        self._db.commit()
        return run_id

    def finish_run(self, run_id: str, status: str, summary: dict) -> None:
        self._db.execute(
            "UPDATE runs SET finished_at = datetime('now'), status = ?, summary = ? WHERE run_id = ?",
            (status, json.dumps(summary), run_id),
        )
        self._db.commit()

    def save_findings(self, run_id: str, findings: List[Finding], audits: Dict[str, AuditResult]) -> None:
        self._db.executemany(
            "INSERT INTO findings (run_id, finding_id, doc) VALUES (?, ?, ?)",
            [(run_id, f.id, json.dumps(to_dict(f))) for f in findings],
        )
        self._db.executemany(
            "INSERT INTO audits (run_id, finding_id, doc) VALUES (?, ?, ?)",
            [(run_id, fid, json.dumps(to_dict(a))) for fid, a in audits.items()],
        )
        self._db.commit()

    def last_run(self) -> Optional[Dict[str, Optional[str]]]:
        row = self._db.execute(
            "SELECT started_at, finished_at, status FROM runs ORDER BY rowid DESC LIMIT 1").fetchone()
        return None if row is None else {"started_at": row[0], "finished_at": row[1], "status": row[2]}

    def has_completed_run(self) -> bool:
        return self._latest_run() is not None

    def pending_count(self) -> int:
        return int(self._db.execute("SELECT COUNT(*) FROM pending").fetchone()[0])

    def _latest_run(self) -> Optional[str]:
        row = self._db.execute(
            "SELECT run_id FROM runs WHERE status IN ('ok', 'partial') ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else None

    def latest_findings(self) -> Tuple[Optional[str], List[Finding], Dict[str, AuditResult]]:
        run_id = self._latest_run()
        if run_id is None:
            return None, [], {}
        fs = [finding_from_dict(json.loads(d)) for (d,) in
              self._db.execute("SELECT doc FROM findings WHERE run_id = ? ORDER BY rowid", (run_id,))]
        audits = {fid: audit_from_dict(json.loads(d)) for fid, d in
                  self._db.execute("SELECT finding_id, doc FROM audits WHERE run_id = ?", (run_id,))}
        return run_id, fs, audits

    def find(self, fid: str) -> Optional[Finding]:
        _, fs, _ = self.latest_findings()
        return next((f for f in fs if f.id == fid), None)

    # ignores
    def add_ignore(self, fid: str, reason: str, created_at: str) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO ignores (finding_id, reason, created_at) VALUES (?, ?, ?)",
            (fid, reason, created_at),
        )
        self._db.commit()

    def ignores(self) -> Dict[str, str]:
        return {fid: reason for fid, reason in self._db.execute("SELECT finding_id, reason FROM ignores")}


class AlreadyRunning(Exception):
    pass


class RunLock:
    def __init__(self, path: str):
        self.path = path
        self._fd: Optional[int] = None

    def __enter__(self):
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            raise AlreadyRunning(t("already running", "già in esecuzione"))
        self._fd = fd
        try:
            os.utime(self.path, None)  # the lock's age tells how long the current run has been going
        except OSError:
            pass
        return self

    def __exit__(self, *exc):
        if self._fd is not None:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            os.close(self._fd)
            self._fd = None
        return False
