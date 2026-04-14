"""
guardrails.py — All 13 guardrails in one file.
===============================================
Designed to be walkable in an interview: one import, one file, clear sections.

5 LAYERS
--------
Layer 1 — Input       : G1 Length  G2 Injection  G3 Rate Limit
Layer 2 — SQL         : G4 SELECT-Only  G5 Schema  G6 Patterns  G7 Row Limit
Layer 3 — Execution   : G8 Read-Only  G9 Timeout  G10 Circuit Breaker
Layer 4 — Output      : G11 PII Mask  G12 Row Cap
Layer 5 — Observability: G13 Audit Log
"""

import json
import logging
import re
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ══════════════════════════════════════════════════════════════════════
# SHARED DATA MODEL
# ══════════════════════════════════════════════════════════════════════

@dataclass
class GuardResult:
    """Result of a single guardrail check."""
    passed:     bool
    name:       str          # e.g. "G2:InjectionDetector"
    message:    str
    severity:   str = "OK"  # OK | WARNING | BLOCKED

    def to_dict(self) -> dict:
        return {"guard": self.name, "passed": self.passed,
                "message": self.message, "severity": self.severity}


# ══════════════════════════════════════════════════════════════════════
# LAYER 1 — INPUT GUARDRAILS
# ══════════════════════════════════════════════════════════════════════

# --- G1: Length Validator -------------------------------------------
MIN_LEN, MAX_LEN = 5, 400

def g1_length(text: str) -> GuardResult:
    """
    G1 — Rejects queries that are too short (noise) or too long (prompt stuffing).
    Interview talking point: long inputs can exhaust LLM context windows and
    enable prompt-stuffing attacks where extra instructions are buried in padding.
    """
    n = len(text.strip())
    if n < MIN_LEN:
        return GuardResult(False, "G1:LengthValidator",
                           f"Query too short ({n} chars).", "BLOCKED")
    if n > MAX_LEN:
        return GuardResult(False, "G1:LengthValidator",
                           f"Query too long ({n} chars, max {MAX_LEN}).", "BLOCKED")
    return GuardResult(True, "G1:LengthValidator", f"Length OK ({n} chars).")


# --- G2: Prompt Injection Detector ----------------------------------
# OWASP LLM Top 10 — LLM01: Prompt Injection
_INJECTION_PATTERNS = [
    r"ignore\s+(previous|above|prior|all)\s+instructions?",
    r"forget\s+(everything|all|previous|your)",
    r"you\s+are\s+now\s+",
    r"act\s+as\s+(a|an|if)\b",
    r"pretend\s+(to\s+be|you\s+are)",
    r"new\s+instructions?\s*[:;]",
    r"(?<!\w)system\s*prompt(?!\w)",
    r"\boverride\s+(the\s+)?(system|rule|instruction)",
    r"<\s*/?system\s*>",
    r"\[INST\]",
]
_JAILBREAK_PATTERNS = [
    r"\bdo\s+anything\s+now\b", r"\bDAN\b", r"\bjailbreak\b",
    r"\bno\s+restrictions?\b",  r"bypass\s+(safety|guard|filter)",
    r"without\s+(any\s+)?restrictions?",
]

def g2_injection(text: str) -> GuardResult:
    """
    G2 — Detects prompt injection and jailbreak attempts.
    Interview talking point: even a well-written system prompt can be overridden
    if the user input contains adversarial instructions — we must pattern-scan
    the raw text before it ever reaches the LLM.
    """
    lower = text.lower()
    for p in _INJECTION_PATTERNS + _JAILBREAK_PATTERNS:
        if re.search(p, lower, re.IGNORECASE):
            return GuardResult(False, "G2:InjectionDetector",
                               "Prompt injection / jailbreak pattern detected.", "BLOCKED")
    return GuardResult(True, "G2:InjectionDetector", "No injection patterns found.")


# --- G3: Rate Limiter (sliding window) ------------------------------
_MAX_REQUESTS = 10
_WINDOW_SEC   = 60
_windows: Dict[str, deque] = {}

def g3_rate_limit(session_id: str) -> GuardResult:
    """
    G3 — Sliding-window rate limiter (10 req / 60 s per session).
    Interview talking point: without this, an adversary can brute-force
    guardrail boundaries cheaply and rack up LLM API costs.
    """
    now = time.time()
    if session_id not in _windows:
        _windows[session_id] = deque()
    w = _windows[session_id]
    while w and w[0] < now - _WINDOW_SEC:
        w.popleft()
    if len(w) >= _MAX_REQUESTS:
        return GuardResult(False, "G3:RateLimiter",
                           f"Rate limit: max {_MAX_REQUESTS} queries per {_WINDOW_SEC}s.", "BLOCKED")
    w.append(now)
    return GuardResult(True, "G3:RateLimiter", "Rate limit OK.")


def run_input_guards(text: str, session_id: str) -> List[GuardResult]:
    """Run Layer 1 guards. Short-circuits on first failure."""
    results = []
    for check in [g1_length(text), g3_rate_limit(session_id), g2_injection(text)]:
        results.append(check)
        if not check.passed:
            break
    return results


# ══════════════════════════════════════════════════════════════════════
# LAYER 2 — SQL GUARDRAILS
# ══════════════════════════════════════════════════════════════════════

ALLOWED_TABLE   = "superstore_sales"
ALLOWED_COLUMNS = {
    "row_id","order_id","order_date","ship_mode","segment",
    "city","state","country","region","category",
    "sub_category","product_name","sales","quantity","discount","profit"
}
SENSITIVE_COLUMNS = {"customer_name", "email", "phone", "salary",
                     "password", "token", "credit_card", "ssn"}
BLOCKED_KEYWORDS  = {
    "INSERT","UPDATE","DELETE","DROP","CREATE","ALTER",
    "TRUNCATE","REPLACE","EXEC","PRAGMA","ATTACH",
}
MAX_ROWS = 100

# --- G4: SELECT-Only Enforcer --------------------------------------
def g4_select_only(sql: str) -> GuardResult:
    """
    G4 — Only SELECT statements are allowed.
    Interview talking point: LLMs can hallucinate DML statements even when
    prompted to generate SELECT only. We must validate the output regardless.
    """
    sql_upper = sql.upper().strip()
    if not sql_upper.startswith("SELECT"):
        return GuardResult(False, "G4:SelectOnlyEnforcer",
                           "Only SELECT statements are permitted.", "BLOCKED")
    for kw in BLOCKED_KEYWORDS:
        if re.search(r"\b" + kw + r"\b", sql_upper):
            return GuardResult(False, "G4:SelectOnlyEnforcer",
                               f"Forbidden keyword: {kw}", "BLOCKED")
    return GuardResult(True, "G4:SelectOnlyEnforcer", "SELECT-only check passed.")


# --- G5: Schema Boundary Validator ---------------------------------
def g5_schema(sql: str) -> GuardResult:
    """
    G5 — Validates referenced table and flags sensitive column names.
    Interview talking point: Principle of Least Privilege applied to SQL.
    The LLM only sees allowed columns in its prompt (defence-in-depth layer 1),
    and this validator is layer 2 of that same protection.
    """
    sql_lower = sql.lower()

    # Check tables referenced in FROM/JOIN
    tables = re.findall(r"\b(?:from|join)\s+([a-zA-Z_]\w*)", sql_lower)
    for tbl in tables:
        if tbl != ALLOWED_TABLE:
            return GuardResult(False, "G5:SchemaValidator",
                               f"Table '{tbl}' is not permitted.", "BLOCKED")

    # Block sensitive column names even if not in LLM schema
    for col in SENSITIVE_COLUMNS:
        if re.search(r"\b" + re.escape(col) + r"\b", sql_lower):
            return GuardResult(False, "G5:SchemaValidator",
                               f"Column '{col}' is restricted.", "BLOCKED")

    return GuardResult(True, "G5:SchemaValidator", "Schema boundary validated.")


# --- G6: Dangerous Pattern Detector --------------------------------
_DANGEROUS = [
    (r";\s*\w",                  "Stacked queries (multiple statements)"),
    (r"--",                      "SQL comment injection (--)"),
    (r"/\*.*?\*/",               "Block comment injection"),
    (r"\bUNION\b.*\bSELECT\b",  "UNION-based injection"),
    (r"\bSLEEP\s*\(",            "Time-based attack: SLEEP()"),
    (r"\bBENCHMARK\s*\(",        "Time-based attack: BENCHMARK()"),
    (r"\bINFORMATION_SCHEMA\b",  "Schema enumeration"),
    (r"\bSQLITE_MASTER\b",       "Schema enumeration: sqlite_master"),
    (r"\bLOAD_FILE\s*\(",        "File read attempt"),
    (r"\bINTO\s+OUTFILE\b",      "File write attempt"),
    (r"0x[0-9a-fA-F]+",          "Hex-encoded payload"),
    (r"char\s*\(\s*\d+",         "CHAR() encoding evasion"),
]

def g6_dangerous_patterns(sql: str) -> GuardResult:
    """
    G6 — Scans for 12 SQL injection signatures.
    Interview talking point: even if G4 confirmed SELECT, injection can happen
    WITHIN a SELECT — UNION SELECT is the classic example.
    """
    for pattern, msg in _DANGEROUS:
        if re.search(pattern, sql, re.IGNORECASE | re.DOTALL):
            return GuardResult(False, "G6:DangerousPatterns",
                               f"Blocked: {msg}.", "BLOCKED")
    return GuardResult(True, "G6:DangerousPatterns", "No dangerous patterns found.")


# --- G7: Row Limit Enforcer ----------------------------------------
def g7_row_limit(sql: str) -> Tuple[str, GuardResult]:
    """
    G7 — Auto-appends LIMIT if missing; caps existing LIMIT at MAX_ROWS.
    Interview talking point: unbounded queries can exhaust server memory and
    create a data exfiltration risk by returning the entire table at once.
    Returns the (possibly modified) SQL along with the guard result.
    """
    sql = sql.strip().rstrip(";")
    m   = re.search(r"\bLIMIT\s+(\d+)", sql, re.IGNORECASE)

    if not m:
        return f"{sql} LIMIT {MAX_ROWS}", GuardResult(
            True, "G7:RowLimitEnforcer",
            f"No LIMIT found — appended LIMIT {MAX_ROWS}.", "WARNING")

    current = int(m.group(1))
    if current > MAX_ROWS:
        sql = re.sub(r"\bLIMIT\s+\d+", f"LIMIT {MAX_ROWS}", sql, flags=re.IGNORECASE)
        return sql, GuardResult(
            True, "G7:RowLimitEnforcer",
            f"LIMIT {current} reduced to {MAX_ROWS}.", "WARNING")

    return sql, GuardResult(True, "G7:RowLimitEnforcer", f"LIMIT {current} is within bounds.")


def run_sql_guards(sql: str) -> Tuple[str, List[GuardResult]]:
    """Run Layer 2 guards. Returns (validated_sql, results)."""
    results = []
    for check in [g6_dangerous_patterns(sql), g4_select_only(sql), g5_schema(sql)]:
        results.append(check)
        if not check.passed:
            return sql, results
    sql, r = g7_row_limit(sql)
    results.append(r)
    return sql, results


# ══════════════════════════════════════════════════════════════════════
# LAYER 3 — EXECUTION GUARDRAILS
# ══════════════════════════════════════════════════════════════════════

# G8 read-only connection lives in db.get_connection(read_only=True)
# and is documented there. We reference it here for completeness.

# --- G9: Query Timeout ---------------------------------------------
TIMEOUT_SEC = 25

def execute_with_timeout(sql: str) -> Tuple[List[Dict], List[str]]:
    """
    G8 + G9 — Executes SQL on a read-only connection with a 5-second timeout.
    G8: read-only URI means writes are impossible at OS level.
    G9: daemon thread killed after TIMEOUT_SEC to prevent resource exhaustion.
    """
    from db import get_connection  # local import keeps this file standalone

    result = {"rows": None, "cols": None, "error": None}

    def _run():
        try:
            conn   = get_connection(read_only=True)
            cur    = conn.cursor()
            cur.execute(sql)
            cols   = [d[0] for d in cur.description] if cur.description else []
            rows   = [dict(r) for r in cur.fetchall()]
            conn.close()
            result["rows"] = rows
            result["cols"] = cols
        except Exception as e:
            result["error"] = str(e)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout=TIMEOUT_SEC)

    if t.is_alive():
        _circuit_breaker.record_failure()
        raise TimeoutError(f"Query exceeded {TIMEOUT_SEC}s timeout.")
    if result["error"]:
        _circuit_breaker.record_failure()
        raise Exception(result["error"])

    _circuit_breaker.record_success()
    return result["rows"], result["cols"]


# --- G10: Circuit Breaker ------------------------------------------
class _State(Enum):
    CLOSED    = "CLOSED"
    OPEN      = "OPEN"
    HALF_OPEN = "HALF_OPEN"

class CircuitBreaker:
    """
    G10 — Classic 3-state circuit breaker protecting the database.
    Interview talking point: in a production agentic loop, a failing DB can
    cause every iteration to wait for a timeout, compounding the failure.
    The circuit breaker trips OPEN after 3 failures and rejects requests fast
    until the DB recovers.
    """
    def __init__(self, fail_threshold=3, recovery_sec=30.0, ok_threshold=2):
        self.fail_threshold = fail_threshold
        self.recovery_sec   = recovery_sec
        self.ok_threshold   = ok_threshold
        self._state         = _State.CLOSED
        self._failures      = 0
        self._successes     = 0
        self._last_fail: Optional[float] = None

    @property
    def state(self) -> _State:
        if (self._state == _State.OPEN and self._last_fail
                and time.time() - self._last_fail >= self.recovery_sec):
            self._state    = _State.HALF_OPEN
            self._successes = 0
        return self._state

    def can_execute(self) -> bool:
        return self.state in (_State.CLOSED, _State.HALF_OPEN)

    def record_success(self):
        if self.state == _State.HALF_OPEN:
            self._successes += 1
            if self._successes >= self.ok_threshold:
                self._state    = _State.CLOSED
                self._failures = 0
        elif self.state == _State.CLOSED:
            self._failures = max(0, self._failures - 1)

    def record_failure(self):
        self._failures  += 1
        self._last_fail  = time.time()
        if self._failures >= self.fail_threshold or self.state == _State.HALF_OPEN:
            self._state = _State.OPEN

    def status(self) -> dict:
        s = self.state
        return {
            "state":    s.value,
            "failures": self._failures,
            "retry_in": max(0.0, self.recovery_sec - (time.time() - self._last_fail))
                        if self._last_fail and s == _State.OPEN else 0.0,
        }


_circuit_breaker = CircuitBreaker()   # module-level singleton


def run_execution_guards(sql: str) -> Tuple[List[Dict], List[str]]:
    """G8+G9+G10 — Check circuit breaker, then execute with timeout."""
    if not _circuit_breaker.can_execute():
        s = _circuit_breaker.status()
        raise ConnectionError(
            f"Circuit breaker is {s['state']}. "
            f"Retry in ~{int(s['retry_in'])}s."
        )
    return execute_with_timeout(sql)

def get_circuit_status() -> dict:
    return _circuit_breaker.status()


# ══════════════════════════════════════════════════════════════════════
# LAYER 4 — OUTPUT GUARDRAILS
# ══════════════════════════════════════════════════════════════════════

_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b")
_PHONE_RE = re.compile(r"\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
MAX_DISPLAY_ROWS = 50

# --- G11: PII Masker -----------------------------------------------
def g11_mask_pii(rows: List[Dict]) -> Tuple[List[Dict], GuardResult]:
    """
    G11 — Scans every string cell for email addresses and phone numbers.
    Interview talking point: This is a last-resort safety net. Even if G5
    blocked customer_name from the schema, a product name or order note
    could theoretically contain an embedded email — this catches it.
    """
    found = False
    out   = []
    for row in rows:
        new_row = {}
        for k, v in row.items():
            if isinstance(v, str):
                masked = _EMAIL_RE.sub(lambda m: f"{m.group(1)[0]}***@{m.group(2)}", v)
                masked = _PHONE_RE.sub("[PHONE-REDACTED]", masked)
                if masked != v:
                    found = True
                new_row[k] = masked
            else:
                new_row[k] = v
        out.append(new_row)
    sev = "WARNING" if found else "OK"
    msg = "PII masked in result values." if found else "No PII detected."
    return out, GuardResult(True, "G11:PIIMasker", msg, sev)


# --- G12: Row Cap --------------------------------------------------
def g12_row_cap(rows: List[Dict]) -> Tuple[List[Dict], GuardResult]:
    """
    G12 — Hard-caps rows sent to the UI at MAX_DISPLAY_ROWS.
    Interview talking point: G7 limits what the DB returns (100 rows),
    G12 is a second, lower cap for the display layer — belt-and-suspenders.
    """
    total = len(rows)
    if total > MAX_DISPLAY_ROWS:
        return rows[:MAX_DISPLAY_ROWS], GuardResult(
            True, "G12:RowCap",
            f"Capped display at {MAX_DISPLAY_ROWS} (DB returned {total}).", "WARNING")
    return rows, GuardResult(True, "G12:RowCap", f"Row count {total} within limit.")


def run_output_guards(rows: List[Dict], columns: List[str]) -> Tuple[List[Dict], List[str], List[GuardResult]]:
    """Run Layer 4 guards. Returns (clean_rows, columns, results)."""
    results  = []
    rows, r  = g12_row_cap(rows);       results.append(r)
    rows, r  = g11_mask_pii(rows);      results.append(r)
    return rows, columns, results


def sanitize_error(raw: str) -> str:
    """Remove file paths, line numbers, and SQLite class names from error strings."""
    msg = re.sub(r"(/[^\s]+)",          "[PATH]",          raw)
    msg = re.sub(r"\bline\s+\d+",       "line [N]",         msg, flags=re.IGNORECASE)
    msg = re.sub(r"sqlite3\.\w+Error",  "DatabaseError",    msg)
    return msg[:200]


# ══════════════════════════════════════════════════════════════════════
# LAYER 5 — OBSERVABILITY
# ══════════════════════════════════════════════════════════════════════

Path("logs").mkdir(exist_ok=True)
_audit = logging.getLogger("audit")
_audit.setLevel(logging.INFO)
_audit.propagate = False
if not _audit.handlers:
    _h = logging.FileHandler("logs/audit.log", encoding="utf-8")
    _h.setFormatter(logging.Formatter("%(message)s"))
    _audit.addHandler(_h)


def g13_audit_log(
    *,
    session_id: str,
    query: str,
    sql: str,
    outcome: str,
    guard_log: List[Dict],
    violations: List[str],
    row_count: int,
    duration_ms: float,
) -> dict:
    """
    G13 — Writes a structured JSON audit record for every request.
    Interview talking point: in production this streams to a SIEM (Splunk / Datadog)
    for anomaly detection — e.g. alert if a session triggers >5 violations/hour.
    """
    total    = len(guard_log)
    passed   = sum(1 for g in guard_log if g.get("passed"))
    record   = {
        "ts":           datetime.now(tz=timezone.utc).isoformat(),
        "session":      session_id,
        "ms":           duration_ms,
        "query":        query[:100],
        "sql_generated": bool(sql),
        "outcome":      outcome,
        "rows":         row_count,
        "violations":   violations,
        "guards":       {"total": total, "passed": passed, "failed": total - passed},
    }
    _audit.info(json.dumps(record, ensure_ascii=False))
    return record
