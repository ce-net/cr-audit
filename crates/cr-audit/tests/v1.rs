//! A scoped viewer gets only rows of their apps (and never key events unless keys is one of them); filters narrow.
use ce_wire::Caller;
use cr_audit::v1::*;
use cr_audit::{AUDIT_ABILITIES, KEYS_ABILITIES, MAX};
use cr_audit_api::versions::v1::*;
use cr_sources::audit_log::{Event, Row};

fn caller(abilities: &[&str]) -> Caller {
    let mut rights = vec!["cr.audit:read".to_string()];
    rights.extend(abilities.iter().map(|a| format!("ability:{a}")));
    Caller { name: "cd".repeat(32), rights }
}

fn row(seq: u64, at: u64, app: &str, op: &str, ok: bool) -> AuditRow {
    from_log("node-1", &Row { seq, at_ms: at, writer: "ab".repeat(8), event: Event { app: app.into(), actor: "ops".into(), op: op.into(), target: format!("{app}/x"), ok, detail: "grant=0011223344556677".into() } })
}

fn ask() -> AuditAsk {
    AuditAsk { q: String::new(), app: None, actor: None, op: None, target_prefix: None, only_failed: false, before_ms: None, limit: 0 }
}

#[test]
fn rows_are_merged_newest_first_and_typed() {
    let keys = from_keys("node-1", &cr_sources::keys::AuditRow { t: 5, caller: "lane".into(), op: "Get".into(), name: "K".into(), ok: true, note: String::new() });
    let (rows, narrowed) = view(&caller(&[]), &ask(), vec![row(1, 1000, "orch", "Up", true), keys, row(2, 9000, "access.grant", "Mint", true)]);
    assert!(!narrowed);
    assert_eq!(rows.iter().map(|r| r.at_ms).collect::<Vec<_>>(), [9000, 5000, 1000]);
    assert_eq!(rows[0].kind, AuditKind::Grant);
    assert_eq!(rows[1].kind, AuditKind::KeyEvent);
    assert_eq!(rows[2].grant.as_deref(), Some("0011223344556677"));
}

#[test]
fn an_app_scope_removes_other_apps_and_key_events() {
    let keys = from_keys("node-1", &cr_sources::keys::AuditRow { t: 5, caller: "lane".into(), op: "Get".into(), name: "K".into(), ok: true, note: String::new() });
    let c = caller(&["cr.audit:scope:app=orch"]);
    let (rows, narrowed) = view(&c, &ask(), vec![row(1, 1000, "orch", "Up", true), keys, row(2, 9000, "access.grant", "Mint", true)]);
    assert!(narrowed);
    assert!(rows.iter().all(|r| r.app == "orch"), "{rows:?}");
    assert_eq!(source_apps(&ask(), &app_scope(&c)), ["orch"]);
    assert_eq!(source_apps(&ask(), &[]), ["*"]);
    // asking for another app does not widen the scope
    let mut a = ask();
    a.app = Some("access.grant".into());
    assert!(view(&c, &a, vec![row(2, 9000, "access.grant", "Mint", true)]).0.is_empty());
}

#[test]
fn filters_narrow_and_limit_holds() {
    let all: Vec<_> = (0..700).map(|i| row(i, i, "orch", if i % 2 == 0 { "Up" } else { "Down" }, i % 7 != 0)).collect();
    let mut a = ask();
    a.limit = 10_000;
    assert_eq!(view(&caller(&[]), &a, all.clone()).0.len(), MAX as usize);
    a.only_failed = true;
    a.op = Some("Up".into());
    let (rows, _) = view(&caller(&[]), &a, all);
    assert!(rows.iter().all(|r| !r.ok && r.op == "Up"));
}

#[test]
fn the_cell_reads_audit_without_append_and_keys_without_values() {
    assert_eq!(AUDIT_ABILITIES, ["audit:read"]);
    assert_eq!(KEYS_ABILITIES, ["keys:audit"]);
}

#[test]
fn major_1_is_frozen_byte_for_byte() {
    use ce_wire::Api;
    assert_eq!(<cr_audit_api::versions::v1::CrAudit as Api>::SCHEMA, 0xde036fc7839ed9d7, "the schema the first edition's clients speak");
    assert_eq!(<cr_audit_api::CrAudit as Api>::VERSION, 2);
}
