//! FROZEN: cr.audit major 1, the first edition's contract, byte for byte. Served beside major 2. Never edited.
//!
//! `cr.audit`: the Audit panel's view cell. Searches the hash-chained `audit.log` of every node and the `keys`
//! audit, merged newest first as one row type, and reports each node's chain check.
//!
//! Rights: `cr.audit:read` for `Search`, `cr.audit:verify` for `Chain`. Rows may be scoped with
//! `cr.audit:scope:app=<glob>` abilities in the same chain; key events are rows of app `keys`.

ce_wire::api! {
    api CrAudit = "cr.audit", version 1;
    types {
        /// Health contract: these three fields, in this order, in every cell.
        pub struct Health { pub ok: bool, pub version: String, pub uptime_s: u64 }
        pub enum SourceState { Live, Stale { age_s: u64 }, Down { why: String }, Refused { needs: String } }
        pub struct Source { pub cell: String, pub node: String, pub state: SourceState, pub ms: u32 }
        pub enum AuditKind { Call, Grant, Revoke, Approval, KeyEvent }
        /// seq: the row's place in its node's chain (key events: 0). writer: who appended it as the cell's gate saw
        /// it. grant: the chain id the caller came in with, when the row names one.
        pub struct AuditRow {
            pub seq: u64, pub at_ms: u64, pub node: String, pub writer: String, pub actor: String, pub app: String,
            pub op: String, pub target: String, pub ok: bool, pub detail: String, pub grant: Option<String>,
            pub kind: AuditKind, pub refs: Vec<String>
        }
        /// Every set field narrows: app exact (scoped viewers get only their apps), actor/op exact, target prefix, q a
        /// substring of op, target or detail, only_failed, before_ms (older than), limit (0 = 100, at most 500).
        pub struct AuditAsk {
            pub q: String, pub app: Option<String>, pub actor: Option<String>, pub op: Option<String>,
            pub target_prefix: Option<String>, pub only_failed: bool, pub before_ms: Option<u64>, pub limit: u32
        }
        pub struct AuditView {
            pub rows: Vec<AuditRow>, pub as_of_ms: u64, pub sources: Vec<Source>, pub narrowed: bool,
            pub can_ask: Vec<String>, pub call_id: String
        }
        /// One node's chain check: rows walked, the head, the last head anchored in state.store, the first bad row.
        pub struct ChainState {
            pub node: String, pub rows: u64, pub head_seq: u64, pub anchored_seq: u64, pub first_bad: Option<u64>,
            pub why: String, pub checked_ms: u64, pub state: SourceState
        }
        pub struct ChainView { pub nodes: Vec<ChainState>, pub as_of_ms: u64 }
        pub enum CrError { Refused { needs: String }, Source { cell: String, why: String }, Invalid { why: String }, NotFound { what: String } }
    }
    ops {
        1 => HealthOp(()) -> Health, needs "cr.audit:health";
        2 => Search(AuditAsk) -> Result<AuditView, CrError>, needs "cr.audit:read", deadline_ms 20000;
        3 => Chain(()) -> Result<ChainView, CrError>, needs "cr.audit:verify", deadline_ms 20000;
    }
}
