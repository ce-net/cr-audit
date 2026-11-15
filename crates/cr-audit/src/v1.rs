//! Major 1 (frozen contract `cr_audit_api::versions::v1`): the first edition's rows, filter and scope rule, unchanged;
//! the v1 ops answer from the same projection as major 2.
use cr_audit_api::versions::v1::*;
use crate::{CELL, MAX};
use ui_chain as cr_view;

use cr_sources::audit_log::Row;





pub fn kind(app: &str, op: &str) -> AuditKind {
    let op = op.to_lowercase();
    if app == "keys" {
        AuditKind::KeyEvent
    } else if op.contains("revoke") {
        AuditKind::Revoke
    } else if app == "root.approve" || app == "feed.approve" || op.contains("approve") || op.contains("sign") {
        AuditKind::Approval
    } else if app == "access.grant" || app.starts_with("cap.") || op.contains("grant") || op.contains("mint") {
        AuditKind::Grant
    } else {
        AuditKind::Call
    }
}

/// `grant=<hex>` or `grant:<hex>` in a detail line: the chain id the call came in with.
pub fn grant_of(detail: &str) -> Option<String> {
    detail.split([' ', ',', ';', '(', ')']).find_map(|w| w.strip_prefix("grant=").or_else(|| w.strip_prefix("grant:")))
        .map(|g| g.trim_matches(|c: char| !c.is_ascii_hexdigit()).to_string()).filter(|g| g.len() >= 8 && g.chars().all(|c| c.is_ascii_hexdigit()))
}

pub fn from_log(node: &str, r: &Row) -> AuditRow {
    let e = &r.event;
    AuditRow {
        seq: r.seq, at_ms: r.at_ms, node: node.into(), writer: r.writer.clone(), actor: e.actor.clone(), app: e.app.clone(),
        op: e.op.clone(), target: e.target.clone(), ok: e.ok, detail: e.detail.clone(), grant: grant_of(&e.detail),
        kind: kind(&e.app, &e.op), refs: vec![format!("node:{node}"), format!("cell:{}", e.app)],
    }
}

pub fn from_keys(node: &str, r: &cr_sources::keys::AuditRow) -> AuditRow {
    AuditRow {
        seq: 0, at_ms: (r.t.max(0) as u64) * 1000, node: node.into(), writer: r.caller.clone(), actor: r.caller.clone(), app: "keys".into(),
        op: r.op.clone(), target: r.name.clone(), ok: r.ok, detail: r.note.clone(), grant: grant_of(&r.note),
        kind: AuditKind::KeyEvent, refs: vec![format!("node:{node}"), "cell:keys".into(), format!("key:{}", r.name)],
    }
}

/// The apps a scoped caller may see (empty: every app) and whether keys rows are among them.
pub fn app_scope(c: &ce_wire::Caller) -> Vec<String> {
    cr_view::scopes(c, CELL, "app")
}

/// The apps to ask audit.log for: the viewer's app filter if set, else each of their exact scopes, else all ("*").
pub fn source_apps(ask: &AuditAsk, scopes: &[String]) -> Vec<String> {
    if let Some(a) = ask.app.as_ref().filter(|a| !a.is_empty()) {
        return vec![a.clone()];
    }
    if !scopes.is_empty() && scopes.iter().all(|s| !s.contains('*')) {
        return scopes.to_vec();
    }
    vec!["*".into()]
}

/// Filter, scope, merge newest first and cut to the limit. Returns the rows and whether the chain removed any.
pub fn view(c: &ce_wire::Caller, ask: &AuditAsk, mut all: Vec<AuditRow>) -> (Vec<AuditRow>, bool) {
    let scopes = app_scope(c);
    let q = ask.q.to_lowercase();
    let limit = if ask.limit == 0 { 100 } else { ask.limit.min(MAX) } as usize;
    let mut narrowed = !scopes.is_empty();
    all.retain(|r| {
        if !cr_view::in_scope(&scopes, &r.app) {
            narrowed = true;
            return false;
        }
        ask.app.as_ref().is_none_or(|a| a.is_empty() || &r.app == a)
            && ask.actor.as_ref().is_none_or(|a| a.is_empty() || &r.actor == a)
            && ask.op.as_ref().is_none_or(|o| o.is_empty() || &r.op == o)
            && ask.target_prefix.as_ref().is_none_or(|t| r.target.starts_with(t.as_str()))
            && (!ask.only_failed || !r.ok)
            && ask.before_ms.is_none_or(|b| r.at_ms < b)
            && (q.is_empty() || [&r.op, &r.target, &r.detail, &r.actor].iter().any(|s| s.to_lowercase().contains(&q)))
    });
    all.sort_by(|a, b| b.at_ms.cmp(&a.at_ms).then(b.seq.cmp(&a.seq)));
    all.truncate(limit);
    (all, narrowed)
}

/// A v2 row as v1 had it (detail always there for a v1 reader with cr.audit:read, as v1 did).
pub fn to_v1(r: &cr_audit_api::AuditRow) -> AuditRow {
    use cr_audit_api::AuditKind as K;
    AuditRow {
        seq: r.seq, at_ms: r.at_ms, node: r.node.clone(), writer: r.writer.clone(), actor: r.actor.clone(), app: r.app.clone(),
        op: r.op.clone(), target: r.target.clone(), ok: r.ok, detail: r.detail.clone().unwrap_or_default(), grant: r.chain_id.clone(),
        kind: match r.kind { K::Call => AuditKind::Call, K::Grant => AuditKind::Grant, K::Revoke => AuditKind::Revoke, K::Approval => AuditKind::Approval, K::KeyEvent => AuditKind::KeyEvent },
        refs: r.refs.clone(),
    }
}
