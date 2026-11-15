//! `cr.audit@2`: the Audit panel's full-stack cell. The hash-chained `audit.log` of every node and the `keys` audit as
//! one live trail of typed rows, and each node's chain check.
//!
//! Rights: `cr.audit:read` (`Search`, `Watch`, `Sources` and the `AuditTrail` view), `cr.audit:verify` (`Chain`).
//! Field level: `detail` needs `cr.audit:detail`. Row level: `cr.audit:where:app=..` and `cr.audit:where:node=..`.
#![forbid(unsafe_code)]

pub mod versions {
    pub mod v1;
}

ce_wire::api! {
    api CrAudit = "cr.audit", version 2;
    types {
        /// Health contract: these three fields, in this order, in every cell.
        pub struct Health { pub ok: bool, pub version: String, pub uptime_s: u64 }
        pub enum SourceState { Live, Stale { age_s: u64 }, Down { why: String }, Refused { needs: String } }
        pub struct Source { pub cell: String, pub node: String, pub state: SourceState, pub ms: u32 }
        pub enum AuditKind { Call, Grant, Revoke, Approval, KeyEvent }
        /// id: `<node>:<seq>` (key events: `keys:<node>:<at>:<n>`). seq: the row's place in its node's chain (key
        /// events: 0). writer: who appended it as the cell's gate saw it. chain_id: the grant the caller came in with,
        /// when the row names one. `detail` is a Part (cr.audit:detail): None on the wire without that right.
        pub struct AuditRow {
            pub id: String, pub seq: u64, pub at_ms: u64, pub node: String, pub writer: String, pub actor: String,
            pub app: String, pub op: String, pub target: String, pub ok: bool, pub kind: AuditKind,
            pub chain_id: Option<String>, pub detail: Option<String>, pub refs: Vec<String>
        }
        /// q: substring of op, target, actor (and detail, when the viewer has it). app: exact. only_failed.
        pub struct AuditQuery { pub q: Option<String>, pub app: Option<String>, pub only_failed: Option<bool> }
        /// One item of `Watch`: reset = replace all rows; else put upserts (by id) and del removes.
        pub struct AuditDelta { pub reset: bool, pub put: Vec<AuditRow>, pub del: Vec<String>, pub hlc: u64 }
        /// One node's chain check: rows walked, the head, the last head anchored in state.store, the first bad row.
        pub struct ChainState {
            pub node: String, pub rows: u64, pub head_seq: u64, pub anchored_seq: u64, pub first_bad: Option<u64>,
            pub why: String, pub checked_ms: u64, pub state: SourceState
        }
    }
    ops {
        1 => HealthOp(()) -> Health, needs "cr.audit:health";
        2 => Search(AuditQuery) -> Vec<AuditRow>, needs "cr.audit:read", deadline_ms 15000;
        4 => Chain(()) -> Vec<ChainState>, needs "cr.audit:verify", deadline_ms 15000;
        6 => Sources(()) -> Vec<Source>, needs "cr.audit:read", deadline_ms 15000;
    }
    streams {
        3 => Watch(AuditQuery) -> stream AuditDelta, needs "cr.audit:read";
    }
}

ui_part::views! {
    api CrAudit;
    view AuditTrail {
        props { q: Option<String>, app: Option<String>, only_failed: Option<bool> }
        needs "cr.audit:read";
        events { trace(String); chain(String) }
        data { sources: Sources }
        streams { rows: Watch by id }
        slots {}
        speaks [2];
    }
    parts { AuditRow { detail: "cr.audit:detail" } }
}
