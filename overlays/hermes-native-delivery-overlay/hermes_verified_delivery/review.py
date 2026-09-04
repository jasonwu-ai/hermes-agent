"""Inert CommonMark review surface and authenticated decision handler."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from html import escape
import json
from pathlib import Path
from typing import Any, Mapping

from markdown_it import MarkdownIt

from .contracts import ContractError, Decision, GraphSpec, parse_utc, sha256_hex


_AUTHORITY_ROOT = Path(__file__).resolve().parents[1] / "authority"
_CSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; img-src 'none'"


@dataclass(frozen=True)
class ReviewEnvelope:
    spec_id: str
    revision: int
    spec_sha256: str
    actor: str
    nonce: str
    issued_at: str
    expires_at: str
    allowed_actions: tuple[str, ...]
    exclusions: tuple[str, ...]
    planner_assignee: str = "planner"


def _exact_object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ContractError(f"{label} fields must be exact")
    return value


def _receipt_second(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ContractError(f"{label} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError(f"{label} must be a UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ContractError(f"{label} must be UTC")
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _string_tuple(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or any(not isinstance(item, str) or not item for item in value):
        raise ContractError(f"{label} must be a non-empty string list")
    if len(value) != len(set(value)):
        raise ContractError(f"{label} contains duplicates")
    return tuple(value)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def load_accepted_authority() -> ReviewEnvelope:
    """Load and cross-check the accepted spec, approval receipt, and predecessor."""
    predecessor_path = _AUTHORITY_ROOT / "accepted-predecessor.json"
    receipt_path = _AUTHORITY_ROOT / "approval-receipt.json"
    spec_path = _AUTHORITY_ROOT / "accepted-specification.md"
    try:
        predecessor = json.loads(predecessor_path.read_bytes())
        receipt_raw = receipt_path.read_bytes()
        receipt = json.loads(receipt_raw)
        specification = spec_path.read_bytes()
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError("accepted authority closure is unreadable") from exc

    predecessor = _exact_object(predecessor, {
        "schema", "decision", "spec_sha256", "approval_receipt_sha256",
        "accepted_at", "expires_at", "authority", "live_effects",
    }, "accepted predecessor")
    receipt = _exact_object(receipt, {
        "schema", "status", "source", "actor", "acceptance_text", "accepted_at_utc",
        "expires_at_utc", "specification", "authority", "implementation_start",
        "protected_profile_config_sha256", "authority_notes",
    }, "approval receipt")
    receipt_spec = _exact_object(receipt["specification"], {"path", "bytes", "sha256"}, "receipt specification")
    receipt_authority = _exact_object(receipt["authority"], {
        "name", "implementer", "workspace", "branch", "remote_permitted",
        "cash_spend_permitted", "repair_round_limit", "terminal_state",
        "allowed_actions", "excluded_actions",
    }, "receipt authority")

    spec_digest = sha256_hex(specification)
    receipt_digest = sha256_hex(receipt_raw)
    _require(predecessor["schema"] == "hvd-accepted-predecessor/v1" and predecessor["decision"] == "ACCEPT_LOCAL_BOOTSTRAP_V1", "accepted predecessor identity mismatch")
    _require(predecessor["authority"] == "LOCAL_BOOTSTRAP_V1_ONLY" and predecessor["live_effects"] is False, "accepted predecessor scope mismatch")
    _require(receipt["schema"] == "hermes-local-bootstrap-approval/v1" and receipt["status"] == "ACCEPTED_LOCAL_BOOTSTRAP_V1", "approval receipt identity mismatch")
    _require(receipt["source"] == "telegram/current_authenticated_chat" and receipt["actor"] == "current_authenticated_user", "approval actor binding mismatch")
    _require(receipt_authority["implementer"] == "00-cos directly with ordinary tools", "approval implementer binding mismatch")
    _require(receipt_authority["remote_permitted"] is False and receipt_authority["cash_spend_permitted"] is False, "approval effects boundary mismatch")
    _require(receipt_spec["bytes"] == len(specification), "accepted specification size mismatch")
    _require(spec_digest == receipt_spec["sha256"] == predecessor["spec_sha256"], "accepted specification digest mismatch")
    _require(receipt_digest == predecessor["approval_receipt_sha256"], "approval receipt digest mismatch")
    issued_at = _receipt_second(receipt["accepted_at_utc"], "accepted_at_utc")
    expires_at = _receipt_second(receipt["expires_at_utc"], "expires_at_utc")
    _require(issued_at == predecessor["accepted_at"] and expires_at == predecessor["expires_at"], "predecessor and receipt time bounds differ")
    _require(receipt["acceptance_text"] == f"ACCEPT LOCAL BOOTSTRAP v1 SHA256 {spec_digest}", "approval acceptance text mismatch")

    return ReviewEnvelope(
        spec_id="two-gate-v1", revision=1, spec_sha256=spec_digest,
        actor=receipt["actor"], nonce="", issued_at=issued_at, expires_at=expires_at,
        allowed_actions=_string_tuple(receipt_authority["allowed_actions"], "allowed actions"),
        exclusions=_string_tuple(receipt_authority["excluded_actions"], "excluded actions"),
        planner_assignee="planner",
    )


def _render_markdown(markdown: str) -> str:
    parser = MarkdownIt("commonmark", {"html": False, "linkify": False})
    parser.renderer.rules["image"] = lambda tokens, idx, _options, _env: escape(tokens[idx].content)
    return parser.render(markdown)


def render_review(markdown: str, envelope: ReviewEnvelope) -> str:
    """Render untrusted specification Markdown with raw HTML disabled."""
    rendered = _render_markdown(markdown)
    scope = "".join(f"<li>{escape(item)}</li>" for item in envelope.allowed_actions)
    exclusions = "".join(f"<li>{escape(item)}</li>" for item in envelope.exclusions)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="{_CSP}">
<title>Review · {escape(envelope.spec_id)}</title>
<style>
:root{{--bg:#0c111b;--panel:#151c29;--text:#edf3ff;--muted:#9eabc0;--accent:#76a8ff;--warn:#ffd37a;--danger:#ff8b8b;--line:#2a3445}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:16px/1.58 system-ui,sans-serif}}
main{{width:min(980px,calc(100% - 28px));margin:28px auto 160px}}article,.gate{{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:clamp(18px,4vw,38px);margin:18px 0}}
h1,h2,h3{{line-height:1.2;overflow-wrap:anywhere}}code,pre{{overflow-wrap:anywhere}}pre{{overflow:auto;padding:14px;border:1px solid var(--line)}}
.badge{{display:inline-block;color:var(--accent);border:1px solid var(--accent);padding:3px 9px;border-radius:999px;font-weight:700}}.muted{{color:var(--muted)}}
textarea{{width:100%;min-height:110px;background:var(--bg);color:var(--text);border:1px solid var(--line);border-radius:10px;padding:12px}}
.actions{{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}}button{{min-height:46px;padding:10px 18px;border-radius:10px;border:1px solid var(--line);font-weight:750;cursor:pointer}}.approve{{background:var(--accent);color:#07111f}}.revise{{background:transparent;color:var(--warn);border-color:var(--warn)}}.reject{{background:transparent;color:var(--danger);border-color:var(--danger)}}
@media(max-width:520px){{main{{width:min(100% - 18px,980px);margin-top:12px}}article,.gate{{border-radius:12px;padding:16px}}.actions button{{width:100%}}}}
</style></head><body><main>
<section class="gate"><span class="badge">LOCAL BOOTSTRAP ONLY</span><h1>Human decision gate</h1>
<p class="muted">Spec SHA-256: <code>{escape(envelope.spec_sha256)}</code></p>
<h2>Approval permits</h2><ul>{scope}</ul><h2>Still excluded</h2><ul>{exclusions}</ul>
<p><strong>No button launches a worker, writes GitHub, modifies live Hermes, installs, restarts, deploys, or activates anything.</strong></p></section>
<article>{rendered}</article>
<section class="gate"><h2>Decision</h2><p><strong>Approval records one held local-planning intent. It does not execute the intent or launch anything.</strong></p>
<form method="post" action="/decision" aria-label="Local bootstrap decision">
<input type="hidden" name="nonce" value="{escape(envelope.nonce)}">
<label for="feedback">Revision feedback</label><p class="muted" id="feedback-help">Required only when requesting changes.</p>
<textarea id="feedback" name="feedback" maxlength="4000" aria-describedby="feedback-help" placeholder="Describe the required revision"></textarea>
<div class="actions"><button type="submit" class="approve" name="action" value="APPROVE">Approve — record held intent</button>
<button type="submit" class="revise" name="action" value="REQUEST_CHANGES">Request changes</button>
<button type="submit" class="reject" name="action" value="REJECT">Reject</button></div></form></section>
</main></body></html>"""


def render_evidence(markdown: str, *, status: str, commit: str) -> str:
    """Render a view-only evidence page with no decision or launch surface."""
    rendered = _render_markdown(markdown)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="{_CSP}">
<title>Bootstrap evidence · {escape(status)}</title>
<style>
:root{{--bg:#0c111b;--panel:#151c29;--text:#edf3ff;--muted:#9eabc0;--accent:#76a8ff;--line:#2a3445}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:16px/1.58 system-ui,sans-serif}}
main{{width:min(980px,calc(100% - 28px));margin:28px auto 100px}}article,.summary{{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:clamp(18px,4vw,38px);margin:18px 0}}
h1,h2,h3{{line-height:1.2;overflow-wrap:anywhere}}code,pre{{overflow-wrap:anywhere}}pre{{overflow:auto;padding:14px;border:1px solid var(--line)}}
.badge{{display:inline-block;color:var(--accent);border:1px solid var(--accent);padding:3px 9px;border-radius:999px;font-weight:700}}.muted{{color:var(--muted)}}
@media(max-width:520px){{main{{width:min(100% - 18px,980px);margin-top:12px}}article,.summary{{border-radius:12px;padding:16px}}}}
</style></head><body><main><section class="summary"><span class="badge">VIEW-ONLY EVIDENCE</span>
<h1>{escape(status)}</h1><p class="muted">Candidate commit: <code>{escape(commit)}</code></p>
<p><strong>This page grants no authority and exposes no action handler.</strong></p></section>
<article>{rendered}</article></main></body></html>"""


def handle_submission(
    form: Mapping[str, Any], *, authenticated_actor: str, envelope: ReviewEnvelope,
    store: Any, now: datetime | None = None, failpoint: str | None = None,
) -> Decision:
    """Record a decision; never reconcile, launch, or touch Kanban."""
    if set(form) != {"action", "nonce", "feedback"}:
        raise ContractError(f"submission fields must be exact, got {sorted(form)}")
    if not authenticated_actor:
        raise ContractError("authenticated actor is required")
    if any(not isinstance(form[field], str) for field in ("action", "nonce", "feedback")):
        raise ContractError("submission values must be strings")
    authority = load_accepted_authority()
    expected = (
        authority.spec_id, authority.revision, authority.spec_sha256, authority.actor,
        authority.issued_at, authority.expires_at, authority.allowed_actions,
        authority.exclusions, authority.planner_assignee,
    )
    actual = (
        envelope.spec_id, envelope.revision, envelope.spec_sha256, envelope.actor,
        envelope.issued_at, envelope.expires_at, envelope.allowed_actions,
        envelope.exclusions, envelope.planner_assignee,
    )
    if actual != expected:
        raise ContractError("review envelope does not match sealed authority")
    if authenticated_actor != authority.actor:
        raise ContractError("authenticated actor does not match sealed authority")
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ContractError("now must be timezone-aware")
    if form["nonce"] != envelope.nonce:
        raise ContractError("nonce mismatch")
    if not (parse_utc(envelope.issued_at) <= now < parse_utc(envelope.expires_at)):
        raise ContractError("decision envelope is outside its admitted interval")
    action = form["action"]
    feedback = form["feedback"].strip() or None
    decision = Decision.from_dict({
        "schema": "hvd-decision/v1", "spec_id": envelope.spec_id,
        "revision": envelope.revision, "spec_sha256": envelope.spec_sha256,
        "actor": authenticated_actor, "action": action, "nonce": envelope.nonce,
        "replay_key": f"gate1:{envelope.spec_id}:{envelope.nonce}",
        "issued_at": envelope.issued_at, "expires_at": envelope.expires_at,
        "allowed_actions": list(envelope.allowed_actions), "exclusions": list(envelope.exclusions),
        "feedback": feedback,
    })
    graph = None
    if action == "APPROVE":
        graph = GraphSpec.from_dict({
            "schema": "hvd-inert-graph/v1", "run_id": f"run:{decision.decision_id}",
            "approval_id": decision.decision_id,
            "tasks": [{"key": "planner", "title": f"Plan approved spec {envelope.spec_id}",
                       "assignee": envelope.planner_assignee, "parents": []}],
        })
    store.record_decision(decision, graph=graph, failpoint=failpoint)
    return decision


def write_review(path: Path, markdown: str, envelope: ReviewEnvelope) -> str:
    html = render_review(markdown, envelope)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return html


def write_evidence(path: Path, markdown: str, *, status: str, commit: str) -> str:
    html = render_evidence(markdown, status=status, commit=commit)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return html
