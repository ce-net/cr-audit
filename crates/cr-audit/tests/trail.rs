//! cr.audit@2 as `#[cell_test(sim, as = [operator, root])]` would run it: root sees every app with `detail`; the
//! operator (caveat app == orch) sees only orch rows and no `detail` field on the wire.
use ce_wire::Caller;
use cr_audit::*;
use cr_audit_api::*;
use cr_sources::audit_log::{Event, Row};

fn caller(abilities: &[&str]) -> Caller {
    let mut rights = vec!["cr.audit:read".to_string()];
    rights.extend(abilities.iter().map(|a| format!("ability:{a}")));
    Caller { name: "cd".repeat(32), rights }
}

fn row(node: &str, seq: u64, at: u64, app: &str, op: &str) -> AuditRow {
    from_log(node, &Row { seq, at_ms: at, writer: "ab".repeat(8), event: Event { app: app.into(), actor: "ops".into(), op: op.into(), target: format!("{app}/x"), ok: true, detail: "grant=0011223344556677 secret-ish detail".into() } })
}

const ALL: AuditQuery = AuditQuery { q: None, app: None, only_failed: None };

#[test]
fn two_viewers_two_trails() {
    let k = from_keys("ops-1", 0, &cr_sources::keys::AuditRow { t: 5, caller: "lane".into(), op: "Get".into(), name: "STRIPE_KEY".into(), ok: true, note: "n".into() });
    let p = keep(vec![row("ops-1", 1, 1000, "orch", "Up"), row("leif-desk", 7, 9000, "access.grant", "Mint"), k]);
    let root = for_caller(&caller(&["cr.audit:read", "cr.audit:detail"]), &ALL, &p);
    assert_eq!(root.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["leif-desk:7", "keys:ops-1:5:0", "ops-1:1"]);
    assert!(root.iter().all(|r| r.detail.is_some()));
    assert_eq!(root[2].chain_id.as_deref(), Some("0011223344556677"));
    let op = for_caller(&caller(&["cr.audit:read", "cr.audit:where:app=orch"]), &ALL, &p);
    assert_eq!(op.len(), 1);
    assert!(op[0].app == "orch" && op[0].detail.is_none());
    let wire = ce_wire::postcard::to_stdvec(&op).unwrap();
    for leak in ["STRIPE_KEY", "access.grant", "secret-ish"] {
        assert!(!wire.windows(leak.len()).any(|w| w == leak.as_bytes()), "{leak} on the operator's wire");
    }
    // without the detail right, detail is not searched either
    let q = AuditQuery { q: Some("secret-ish".into()), app: None, only_failed: None };
    assert!(for_caller(&caller(&["cr.audit:read"]), &q, &p).is_empty());
    assert_eq!(for_caller(&caller(&["cr.audit:read", "cr.audit:detail"]), &q, &p).len(), 2);
}

#[test]
fn new_rows_are_one_delta() {
    let c = caller(&["cr.audit:read"]);
    let a = for_caller(&c, &ALL, &keep(vec![row("n", 1, 1000, "orch", "Up")]));
    let b = for_caller(&c, &ALL, &keep(vec![row("n", 1, 1000, "orch", "Up"), row("n", 2, 2000, "orch", "Down")]));
    let d = delta(&a, &b, 1).unwrap();
    assert_eq!(d.put.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["n:2"]);
}
