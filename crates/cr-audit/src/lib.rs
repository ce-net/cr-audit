//! The one function of `cr.audit`: one live trail of the audit rows of every node and the keys audit, filtered by the
//! caller's chain. A background round (every [`EVERY_S`] s) asks `audit.log` on every mesh node at once and this
//! node's `keys` `Audit`, newest [`KEEP`] rows kept; each round is one trace in ui.trace whose spans cross every
//! source it asked (cr.audit -> audit.log on each node -> keys). `Search` and `Watch` read that projection.
#![forbid(unsafe_code)]

pub mod v1;

use cr_audit_api::*;
use cr_sources::audit_log::Row;
use std::collections::BTreeMap;
use ui_chain::{layer_view, Caveats};
use ui_part::Parts;

pub const CELL: &str = "cr.audit";
pub const AUDIT_ABILITIES: &[&str] = &["audit:read"];
pub const KEYS_ABILITIES: &[&str] = &["keys:audit"];
/// The one grant this cell's own key holds, minted by the node for exactly what it reads (`ce-iam grant --to <cell key>
/// --action <each>`, kept with the key in `<ce data dir>/cell-keys/cr.audit/`); every source token is attenuated from it
/// ([`ui_chain::source_token`]). A taken backend holds this, never the node's root.
pub const GRANT: &[&str] = &["audit:read", "keys:audit", "ui.trace:write", "delegate:1"];
pub const MAX: u32 = 500;
pub const KEEP: usize = 1200;
pub const EVERY_S: u64 = 10;
pub const STREAM_MAX_S: u64 = 30;

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
        id: format!("{node}:{}", r.seq), seq: r.seq, at_ms: r.at_ms, node: node.into(), writer: r.writer.clone(), actor: e.actor.clone(),
        app: e.app.clone(), op: e.op.clone(), target: e.target.clone(), ok: e.ok, kind: kind(&e.app, &e.op),
        chain_id: grant_of(&e.detail), detail: Some(e.detail.clone()), refs: vec![format!("node:{node}"), format!("cell:{}", e.app)],
    }
}

pub fn from_keys(node: &str, n: usize, r: &cr_sources::keys::AuditRow) -> AuditRow {
    AuditRow {
        id: format!("keys:{node}:{}:{n}", r.t), seq: 0, at_ms: (r.t.max(0) as u64) * 1000, node: node.into(), writer: r.caller.clone(),
        actor: r.caller.clone(), app: "keys".into(), op: r.op.clone(), target: r.name.clone(), ok: r.ok, kind: AuditKind::KeyEvent,
        chain_id: grant_of(&r.note), detail: Some(r.note.clone()), refs: vec![format!("node:{node}"), "cell:keys".into(), format!("key:{}", r.name)],
    }
}

fn caveat(r: &AuditRow, k: &str) -> Option<String> {
    match k {
        "app" => Some(r.app.clone()),
        "node" => Some(r.node.clone()),
        "actor" => Some(r.actor.clone()),
        _ => None,
    }
}

/// What one caller gets of the projection: rows their caveats and query let through, newest first, at most MAX,
/// `detail` withheld without `cr.audit:detail` (and then not searched either).
pub fn for_caller(c: &ce_wire::Caller, q: &AuditQuery, rows: &BTreeMap<String, AuditRow>) -> Vec<AuditRow> {
    let cv = Caveats::of(c, CELL);
    let text = q.q.as_deref().unwrap_or("").to_lowercase();
    let mut out: Vec<AuditRow> = rows
        .values()
        .filter(|r| layer_view::visible_by(&cv, |k| caveat(r, k)))
        .map(|r| {
            let mut r = r.clone();
            r.withhold(&|right| ui_chain::holds(c, right));
            r
        })
        .filter(|r| {
            q.app.as_ref().is_none_or(|a| a.is_empty() || &r.app == a)
                && (q.only_failed != Some(true) || !r.ok)
                && (text.is_empty() || [&r.op, &r.target, &r.actor].iter().any(|s| s.to_lowercase().contains(&text)) || r.detail.as_ref().is_some_and(|d| d.to_lowercase().contains(&text)))
        })
        .collect();
    out.sort_by(|a, b| b.at_ms.cmp(&a.at_ms).then(b.seq.cmp(&a.seq)));
    out.truncate(MAX as usize);
    out
}

pub fn delta(before: &[AuditRow], now: &[AuditRow], hlc: u64) -> Option<AuditDelta> {
    let old: BTreeMap<&str, &AuditRow> = before.iter().map(|r| (r.id.as_str(), r)).collect();
    let new: BTreeMap<&str, &AuditRow> = now.iter().map(|r| (r.id.as_str(), r)).collect();
    let put: Vec<AuditRow> = now.iter().filter(|r| old.get(r.id.as_str()) != Some(r)).cloned().collect();
    let del: Vec<String> = before.iter().filter(|r| !new.contains_key(r.id.as_str())).map(|r| r.id.clone()).collect();
    (!put.is_empty() || !del.is_empty()).then_some(AuditDelta { reset: false, put, del, hlc })
}

/// Keep the newest `KEEP` rows.
pub fn keep(rows: Vec<AuditRow>) -> BTreeMap<String, AuditRow> {
    let mut v = rows;
    v.sort_by(|a, b| b.at_ms.cmp(&a.at_ms));
    v.truncate(KEEP);
    v.into_iter().map(|r| (r.id.clone(), r)).collect()
}

/// The source lines this caller may see: filtered by the same `node` caveat as the rows (a mesh-wide line, with no
/// node, is not shown to a caller caveated on nodes), so a narrow viewer does not learn other nodes' names.
pub fn sources_for(c: &ce_wire::Caller, all: Vec<Source>) -> Vec<Source> {
    let cv = Caveats::of(c, CELL);
    all.into_iter()
        .filter(|s| cv.0.get("node").is_none() || (!s.node.is_empty() && cv.allows("node", &s.node)))
        // the keys audit is a source of rows of app `keys` only: a viewer caveated away from that app is not told of it
        .filter(|s| s.cell != "keys" || cv.allows("app", "keys"))
        .collect()
}
