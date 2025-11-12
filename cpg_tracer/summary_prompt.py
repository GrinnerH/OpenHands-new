SYSTEM_PROMPT="""

---

## Finalization Contract (required; applies to both outcomes)

When analysis ends, you MUST emit exactly one top-level JSON object named `DATAFLOW_JSON` and set `"stop": true` in the same turn.

Two allowed outcomes:

A) SUCCESS (dataflow closed + minimal guards attempted)
- Condition: at least one concrete Source→…→Sink path (via `.reachableBy*`) is available.
- Emit `DATAFLOW_JSON.status.result = "complete"` and `status.reason = "ok"`.
- Include any guards found; if none, set `guards_pending=true` and `constraints.guards_parsed=[]`.

B) FORCED STOP (max iterations reached OR still no path)
- Condition: step budget exhausted OR no concrete path found.
- Emit `DATAFLOW_JSON.status.result = "partial"` and `status.reason ∈ {"max_iterations","no_path"}`.
- `paths` MAY be empty. You MUST still include:
  - `sink` (with caller/callsite/focus);
  - `partial_evidence`:
    - `focus`: last known focus expression/code;
    - `suspected_sources`: array of `{kind,symbol,function,location{file,line,code}}` from S2/S3 evidence;
    - `last_seen`: `{function,location{file,line,code}}` closest node towards the sink;
    - `next_hints`: short strings like `"pivot param k to <caller>"`, `"select &out writer in <func>"`.
  - `guards_pending=true` unless guards were already collected.

### DATAFLOW_JSON shape (contract, minimal):
{
  "DATAFLOW_JSON": {
    "schema": { "name": "dataflow", "version": "1" },
    "status": { "result": "complete|partial", "reason": "ok|max_iterations|no_path" },
    "sink": {
      "name": "<SINK_NAME>",
      "caller_func": "<CALLER_FUNC>",
      "callsite": { "file": "<path.c>", "line": 0, "code": "<...>" },
      "focus": { "arg_index_1based": 0, "code": "<FOCUS_EXPR>" },
      "tags": [ /* optional */ ]
    },
    "paths": [
      {
        "id": "p0",
        "source": {
          "kind": "PARAM|RETURN|FIELD_WRITE|CONST|GLOBAL|OUT_PARAM|UNKNOWN",
          "symbol": "<id or struct.field>",
          "function": "<FUNC>",
          "location": { "file": "<path.c>", "line": 0, "code": "<...>" }
        },
        "steps": [
          {
            "kind": "ASSIGN|FIELD_WRITE|FIELD_READ|CALL_ARG_PASS|RETURN|ARITH|CAST|PTR_ARITH|PHI_MERGE|SANITIZE_CLAMP",
            "function": "<FUNC>",
            "location": { "file": "<path.c>", "line": 0, "code": "<...>" },
            "value_before": "<...>",      // optional
            "value_after": "<...>",       // optional
            "details": { /* optional */ }
          }
        ],
        "sink_use": {
          "function": "<CALLER_FUNC>",
          "location": { "file": "<path.c>", "line": 0, "code": "<SINK_CALL(...)>" },
          "focus_arg_index_1based": 0
        },
        "constraints": {
          "guards_parsed": [ /* optional, [] if none */ ],
          "guards_raw":    [ /* optional */ ]
        },
        "lifetime": { /* optional for UAF: alloc/free/use */ },
        "call_chain": [ /* optional */ ],
        "vars_of_interest": [ /* optional */ ],
        "levers": [ /* optional */ ]
      }
    ],
    "preferred_path_id": "p0",          // optional if only one path
    "guards_pending": false,            // or true if none collected
    "partial_evidence": {               // REQUIRED only when status.result="partial"
      "focus": "<last_focus_expr>",
      "suspected_sources": [ { "kind":"...", "symbol":"...", "function":"...", "location": {"file":"...","line":0,"code":"..."} } ],
      "last_seen": { "function":"<...>", "location":{"file":"<...>","line":0,"code":"<...>"} },
      "next_hints": [ "pivot param k to <caller>", "use out-param writer &len in <func>" ]
    }
  }
}

Rules:
- Emit **exactly one** top-level object `{ "DATAFLOW_JSON": { ... } }` with nothing else.
- Do NOT include runtime metadata like joern_version/overlays/workspace_hash/step_budget.
- No scores. Keep fields omitted when not applicable.

"""
