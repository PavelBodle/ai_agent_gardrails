import operator
import time
from typing import Annotated, Dict, List

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.graph import END, StateGraph
from typing_extensions import TypedDict

from db import SCHEMA_FOR_LLM
from guardrails import (
    g13_audit_log,
    run_execution_guards,
    run_input_guards,
    run_output_guards,
    run_sql_guards,
    sanitize_error,
)

# ─── System prompt 

SYSTEM_PROMPT = f"""You are a read-only SQL generator for a retail analytics database.

{SCHEMA_FOR_LLM}

Rules:
1. Output ONLY the raw SQL SELECT — no markdown, no backticks, no semicolon.
2. Use ONLY the table and columns listed above.
3. If the question cannot be answered from the schema, output exactly: CANNOT_ANSWER
4. Never generate INSERT, UPDATE, DELETE, DROP, or any non-SELECT statement.
"""


# ─── State ───

class AgentState(TypedDict):
    # Core I/O
    query:       str
    session_id:  str
    outcome:     str                            # SUCCESS | BLOCKED | ERROR

    # Processing
    generated_sql: str
    validated_sql: str

    # Results
    rows:    List[Dict]
    columns: List[str]

    # Guardrail tracking (lists auto-append with operator.add)
    guard_log:  Annotated[List[Dict], operator.add]
    violations: Annotated[List[str],  operator.add]
    trace:      Annotated[List[str],  operator.add]

    # Flow control
    blocked:   bool
    error_msg: str
    start_ts:  float


def initial_state(query: str, session_id: str) -> AgentState:
    return AgentState(
        query=query, session_id=session_id, outcome="",
        generated_sql="", validated_sql="",
        rows=[], columns=[],
        guard_log=[], violations=[], trace=[],
        blocked=False, error_msg="", start_ts=time.time(),
    )


# ─── Nodes ───

def node_input_guard(state: AgentState) -> dict:
    """Layer 1 — G1 Length, G2 Injection, G3 Rate Limit."""
    results = run_input_guards(state["query"], state["session_id"])
    log     = [r.to_dict() for r in results]
    for r in results:
        if not r.passed:
            return {
                "trace":      ["input_guard"],
                "guard_log":  log,
                "violations": [f"[INPUT] {r.name}: {r.message}"],
                "blocked":    True,
                "error_msg":  r.message,
            }
    return {"trace": ["input_guard"], "guard_log": log}


def node_generate_sql(state: AgentState, llm) -> dict:
    """LLM call — Gemini at temperature=0 for deterministic SQL."""
    try:
        # resp = llm.invoke([
        #     SystemMessage(content=SYSTEM_PROMPT),
        #     HumanMessage(content=f"Question: {state['query']}\n\nSQL:"),
        # ])
        resp = llm.invoke([
        HumanMessage(content=f"{SYSTEM_PROMPT}\n\nQuestion: {state['query']}\n\nSQL:"),
            ])
        sql = resp.content.strip()

        # Strip accidental markdown fences
        if sql.startswith("```"):
            lines = sql.split("\n")
            sql   = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:]).strip()

        if sql.upper() == "CANNOT_ANSWER":
            return {
                "trace":     ["generate_sql"],
                "blocked":   True,
                "error_msg": "This question cannot be answered with the available data.",
            }

        return {"trace": ["generate_sql"], "generated_sql": sql}

    except Exception as exc:
        return {"trace": ["generate_sql"], "blocked": True,
                "error_msg": f"LLM error: {exc}"}


def node_sql_guard(state: AgentState) -> dict:
    """Layer 2 — G4 SELECT-Only, G5 Schema, G6 Patterns, G7 Row Limit."""
    validated, results = run_sql_guards(state["generated_sql"])
    log = [r.to_dict() for r in results]
    for r in results:
        if not r.passed:
            return {
                "trace":      ["sql_guard"],
                "guard_log":  log,
                "violations": [f"[SQL] {r.name}: {r.message}"],
                "blocked":    True,
                "error_msg":  "The generated SQL was blocked by safety validation.",
            }
    return {"trace": ["sql_guard"], "guard_log": log, "validated_sql": validated}


def node_execute(state: AgentState) -> dict:
    """Layer 3 — G8 Read-Only, G9 Timeout, G10 Circuit Breaker."""
    try:
        rows, columns = run_execution_guards(state["validated_sql"])
        return {"trace": ["execute"], "rows": rows, "columns": columns}
    except Exception as exc:
        safe = sanitize_error(str(exc))
        return {
            "trace":      ["execute"],
            "violations": [f"[EXEC] {str(exc)}"],
            "blocked":    True,
            "error_msg":  safe,
        }


def node_output_guard(state: AgentState) -> dict:
    """Layer 4 — G11 PII Mask, G12 Row Cap."""
    rows, columns, results = run_output_guards(state["rows"], state["columns"])
    log = [r.to_dict() for r in results]
    warnings = [f"[OUTPUT] {r.name}: {r.message}"
                for r in results if r.severity == "WARNING"]
    return {
        "trace":      ["output_guard"],
        "guard_log":  log,
        "violations": warnings,
        "rows":       rows,
        "columns":    columns,
        "outcome":    "SUCCESS",
    }


def node_error(state: AgentState) -> dict:
    """Terminal node for all blocked / failed paths."""
    return {"trace": ["error"], "outcome": "BLOCKED"}


# ─── Routing ─

def _route(state: AgentState, next_ok: str) -> str:
    return "error" if state.get("blocked") else next_ok


# ─── Graph builder 

def build_graph(llm: ChatGoogleGenerativeAI):
    g = StateGraph(AgentState)

    g.add_node("input_guard",   node_input_guard)
    g.add_node("generate_sql",  lambda s: node_generate_sql(s, llm))
    g.add_node("sql_guard",     node_sql_guard)
    g.add_node("execute",       node_execute)
    g.add_node("output_guard",  node_output_guard)
    g.add_node("error",         node_error)

    g.set_entry_point("input_guard")

    edges = [
        ("input_guard",  "generate_sql"),
        ("generate_sql", "sql_guard"),
        ("sql_guard",    "execute"),
        ("execute",      "output_guard"),
    ]
    for src, dst in edges:
        g.add_conditional_edges(
            src, lambda s, d=dst: _route(s, d),
            {d: d for d in [dst, "error"]},  # type: ignore[misc]
        )

    g.add_edge("output_guard", END)
    g.add_edge("error",        END)

    return g.compile()


# ─── Main runner ──

def run_agent(query: str, session_id: str, llm) -> AgentState:
    """
    Build graph, run it, write audit log, return final state.
    Layer 5 (G13 audit) runs here so it always fires regardless of outcome.
    """
    graph  = build_graph(llm)
    state  = graph.invoke(initial_state(query, session_id))
    dur_ms = round((time.time() - state["start_ts"]) * 1000, 1)

    g13_audit_log(
        session_id  = state["session_id"],
        query       = state["query"],
        sql         = state.get("validated_sql", ""),
        outcome     = state.get("outcome", "BLOCKED"),
        guard_log   = state.get("guard_log", []),
        violations  = state.get("violations", []),
        row_count   = len(state.get("rows", [])),
        duration_ms = dur_ms,
    )
    return state
