//! `cr-audit serve`: the cr.audit cell behind this machine's door (ce-cap, default deny), majors 2 and 1. A background
//! round every [`cr_audit::EVERY_S`] s asks `audit.log` on every mesh node at once (3 s each) and this node's `keys`
//! audit and keeps the newest rows; each source call is a span under the round's call id in ui.trace (one trace across
//! cr.audit, audit.log on each node and keys). `Chain` reports each node's `Verify`, run in the background at most every
//! 10 minutes (a walk can take 30 s and more).
use ce_wire::Server;
use cr_audit::*;
use cr_audit::v1;
use cr_audit_api::*;
use cr_sources::audit_log::{self as al, AuditLog, QueryReq};
use cr_sources::keys::{self as k, Keys};
use cr_sources::nodes::{mesh_nodes, Node};
use cr_sources::trace::Trace;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{watch, Mutex, RwLock};

const ASK: Duration = Duration::from_secs(3);

async fn connect<A: ce_wire::Api>(n: &Node, abilities: &[&str], prefix: Option<&str>) -> Result<ce_wire::Client<A>, String> {
    let mut why = String::from("no address");
    for a in &n.addrs {
        let tok = ui_chain::source_token::<A>(abilities, 120, prefix)?;
        match tokio::time::timeout(ASK, ce_wire::Client::<A>::connect_opts(format!("{a}:7700"), tok, false, ASK)).await {
            Ok(Ok(c)) => return Ok(c),
            Ok(Err(e)) => why = format!("{e}"),
            Err(_) => why = format!("no answer in {} s", ASK.as_secs()),
        }
    }
    Err(why)
}

fn state_of(why: &str) -> SourceState {
    if why.contains("Right") || why.contains("OutOfScope") || why.contains("Unauthorized") {
        SourceState::Refused { needs: "audit:read".into() }
    } else {
        SourceState::Down { why: why.chars().take(240).collect() }
    }
}

async fn query(n: Node, req: QueryReq, t: Trace) -> (Vec<AuditRow>, Source) {
    let span = t.start("audit.log", "Query", &n.name);
    let t0 = Instant::now();
    let got = async {
        let mut c = connect::<AuditLog>(&n, AUDIT_ABILITIES, Some("audit/*")).await?;
        c.deadline = Duration::from_secs(8);
        c.call::<al::Query>(&req).await.map_err(|e| e.to_string())?.map_err(|e| format!("{e:?}"))
    }
    .await;
    let ms = t0.elapsed().as_millis() as u32;
    match got {
        Ok(rows) => {
            t.end(span, "ok");
            (rows.iter().map(|r| from_log(&n.name, r)).collect(), Source { cell: "audit.log".into(), node: n.name.clone(), state: SourceState::Live, ms })
        }
        Err(why) => {
            t.end(span, &why);
            (vec![], Source { cell: "audit.log".into(), node: n.name.clone(), state: state_of(&why), ms })
        }
    }
}

async fn keys_audit(limit: u32, t: Trace) -> (Vec<AuditRow>, Source) {
    let node = ui_chain::hostname();
    let span = t.start("keys", "Audit", &node);
    let t0 = Instant::now();
    let got = async {
        let tok = ui_chain::source_token::<Keys>(KEYS_ABILITIES, 120, None)?;
        let mut c = tokio::time::timeout(ASK, ce_wire::Client::<Keys>::by_name(tok)).await.map_err(|_| "no answer".to_string())?.map_err(|e| e.to_string())?;
        c.deadline = Duration::from_secs(8);
        c.call::<k::Audit>(&limit).await.map_err(|e| e.to_string())
    }
    .await;
    let ms = t0.elapsed().as_millis() as u32;
    match got {
        Ok(rows) => {
            t.end(span, "ok");
            (rows.iter().enumerate().map(|(i, r)| from_keys(&node, i, r)).collect(), Source { cell: "keys".into(), node, state: SourceState::Live, ms })
        }
        Err(why) => {
            t.end(span, &why);
            (vec![], Source { cell: "keys".into(), node, state: state_of(&why), ms })
        }
    }
}

#[derive(Default)]
struct State {
    rows: BTreeMap<String, AuditRow>,
    sources: Vec<Source>,
    as_of_ms: u64,
    hlc: u64,
    last_call: String,
}

type Shared = Arc<RwLock<State>>;

/// One round: every node's audit.log and this node's keys audit, merged. One root span, one child per source call.
async fn round(st: &Shared, tx: &watch::Sender<u64>) {
    let start = ui_chain::now_ms();
    let t = Trace::root(&ui_chain::hostname());
    let mut hs = Vec::new();
    // the newest rows of every app, and the newest of each app a narrow viewer is usually caveated to (a busy app
    // would otherwise push them out of the newest 200)
    let apps: Vec<String> = std::env::var("CR_AUDIT_APPS").unwrap_or_else(|_| "orch,cell.install,access.grant,grant.bundle,root.approve".into())
        .split(',').map(str::trim).filter(|a| !a.is_empty()).map(String::from).collect();
    for n in mesh_nodes() {
        hs.push(tokio::spawn(query(n.clone(), QueryReq { app: "*".into(), target_prefix: None, before: None, limit: 200 }, t.clone())));
        for a in &apps {
            hs.push(tokio::spawn(query(n.clone(), QueryReq { app: a.clone(), target_prefix: None, before: None, limit: 50 }, t.clone())));
        }
    }
    let kh = tokio::spawn(keys_audit(200, t.clone()));
    let (mut rows, mut sources) = (Vec::new(), Vec::new());
    for h in hs {
        if let Ok((r, s)) = h.await {
            rows.extend(r);
            sources.push(s);
        }
    }
    if let Ok((r, s)) = kh.await {
        rows.extend(r);
        sources.push(s);
    }
    let mut seen: Vec<Source> = Vec::new();
    for s in sources {
        match seen.iter_mut().find(|x| x.cell == s.cell && x.node == s.node) {
            Some(x) if matches!(x.state, SourceState::Live) => *x = s,
            Some(_) => {}
            None => seen.push(s),
        }
    }
    let sources = seen;
    let call = t.root.clone();
    t.finish(CELL, "Round", start, "ok");
    let mut g = st.write().await;
    // a node that did not answer keeps its last rows (stale, its source says so), never an empty trail
    for s in sources.iter().filter(|s| !matches!(s.state, SourceState::Live)) {
        rows.extend(g.rows.values().filter(|r| r.node == s.node && (s.cell == "keys") == (r.app == "keys")).cloned());
    }
    let next = keep(rows);
    if next != g.rows {
        g.hlc = ui_chain::now_ms();
        g.rows = next;
        let _ = tx.send(g.hlc);
    }
    g.sources = sources;
    g.as_of_ms = ui_chain::now_ms();
    g.last_call = call;
}

fn sources(s: &State) -> Vec<Source> {
    let age = ui_chain::now_ms().saturating_sub(s.as_of_ms) / 1000;
    s.sources.iter().cloned().map(|mut x| {
        if matches!(x.state, SourceState::Live) && age > 2 * EVERY_S {
            x.state = SourceState::Stale { age_s: age };
        }
        x
    }).collect()
}

type Chains = Arc<Mutex<(Option<Instant>, Vec<ChainState>)>>;

async fn verify_all(chains: Chains) {
    let mut out = Vec::new();
    for n in mesh_nodes() {
        let t0 = ui_chain::now_ms();
        let got = async {
            let mut c = connect::<AuditLog>(&n, AUDIT_ABILITIES, Some("audit/*")).await?;
            c.deadline = Duration::from_secs(180);
            c.call::<al::Verify>(&()).await.map_err(|e| e.to_string())?.map_err(|e| format!("{e:?}"))
        }
        .await;
        out.push(match got {
            Ok(v) => ChainState { node: n.name.clone(), rows: v.rows, head_seq: v.head_seq, anchored_seq: v.anchored_seq, first_bad: v.first_bad, why: v.why, checked_ms: t0, state: SourceState::Live },
            Err(why) => ChainState { node: n.name.clone(), rows: 0, head_seq: 0, anchored_seq: 0, first_bad: None, why: String::new(), checked_ms: t0, state: state_of(&why) },
        });
    }
    let mut g = chains.lock().await;
    g.1 = out;
}

async fn chain(chains: Chains) -> Vec<ChainState> {
    let mut g = chains.lock().await;
    let due = g.0.is_none_or(|t| t.elapsed() > Duration::from_secs(600));
    if due {
        g.0 = Some(Instant::now());
        tokio::spawn(verify_all(chains.clone()));
    }
    let now = ui_chain::now_ms();
    let nodes: Vec<ChainState> = g.1.iter().cloned().map(|mut c| {
        if matches!(c.state, SourceState::Live) {
            c.state = SourceState::Stale { age_s: now.saturating_sub(c.checked_ms) / 1000 };
        }
        c
    }).collect();
    nodes
}

async fn serve() -> Result<(), String> {
    let me = ce_gate::node_identity().map_err(|e| e.to_string())?;
    let started = Instant::now();
    let st: Shared = Arc::default();
    let chains: Chains = Arc::new(Mutex::new((None, vec![])));
    let (tx, rx) = watch::channel(0u64);
    {
        let st = st.clone();
        tokio::spawn(async move {
            loop {
                round(&st, &tx).await;
                tokio::time::sleep(Duration::from_secs(EVERY_S)).await;
            }
        });
    }
    let (s1, s2, s3, s4) = (st.clone(), st.clone(), st.clone(), st.clone());
    let (c1, c2) = (chains.clone(), chains.clone());
    let gate = ce_gate::Gate::<CrAudit>::new(me.node_id(), ce_gate::mesh_roots()).into_fn();
    let v2 = Server::<CrAudit>::new(gate)
        .on::<HealthOp, _, _>(move |_: (), _| async move { Ok(Health { ok: true, version: env!("CARGO_PKG_VERSION").into(), uptime_s: started.elapsed().as_secs() }) })
        .on::<Search, _, _>(move |q: AuditQuery, who| {
            let st = s1.clone();
            async move {
                let t = Trace::root(&ui_chain::hostname());
                let start = ui_chain::now_ms();
                let rows = for_caller(&who, &q, &st.read().await.rows);
                t.finish(CELL, &format!("Search chain={}", ui_chain::chain_id(&who)), start, "ok");
                Ok(rows)
            }
        })
        .on::<Chain, _, _>(move |_: (), _| { let c = c1.clone(); async move { Ok(chain(c).await) } })
        .on::<Sources, _, _>(move |_: (), who| { let st = s2.clone(); async move { Ok(sources_for(&who, sources(&*st.read().await))) } })
        .stream::<Watch, _, _>(move |q: AuditQuery, who, sink| {
            let (st, mut rx) = (s3.clone(), rx.clone());
            async move {
                let end = Instant::now() + Duration::from_secs(STREAM_MAX_S);
                let (mut sent, hlc) = {
                    let g = st.read().await;
                    (for_caller(&who, &q, &g.rows), g.hlc)
                };
                sink.send(&AuditDelta { reset: true, put: sent.clone(), del: vec![], hlc }).map_err(|e| e.to_string())?;
                loop {
                    let left = end.saturating_duration_since(Instant::now());
                    match tokio::time::timeout(left, rx.changed()).await {
                        Err(_) | Ok(Err(_)) => return Ok(()),
                        Ok(Ok(())) => {}
                    }
                    let g = st.read().await;
                    let now = for_caller(&who, &q, &g.rows);
                    if let Some(d) = delta(&sent, &now, g.hlc) {
                        sink.send(&d).map_err(|e| e.to_string())?;
                        sent = now;
                    }
                }
            }
        })
        .audit(ce_gate::audit::file())
        .serve_door();

    // major 1, frozen: the first edition's envelope from the same projection
    use cr_audit_api::versions::v1 as old;
    let state1 = |s: SourceState| match s {
        SourceState::Live => old::SourceState::Live,
        SourceState::Stale { age_s } => old::SourceState::Stale { age_s },
        SourceState::Down { why } => old::SourceState::Down { why },
        SourceState::Refused { needs } => old::SourceState::Refused { needs },
    };
    let gate1 = ce_gate::Gate::<old::CrAudit>::new(me.node_id(), ce_gate::mesh_roots()).into_fn();
    let v1s = Server::<old::CrAudit>::new(gate1)
        .on::<old::HealthOp, _, _>(move |_: (), _| async move { Ok(old::Health { ok: true, version: env!("CARGO_PKG_VERSION").into(), uptime_s: started.elapsed().as_secs() }) })
        .on::<old::Search, _, _>(move |ask: old::AuditAsk, who| {
            let st = s4.clone();
            async move {
                let g = st.read().await;
                let all: Vec<old::AuditRow> = g.rows.values().map(v1::to_v1).collect();
                let (rows, narrowed) = v1::view(&who, &ask, all);
                let srcs = sources(&g).into_iter().map(|x| old::Source { cell: x.cell, node: x.node, ms: x.ms, state: state1(x.state) }).collect();
                let can_ask = if v1::app_scope(&who).is_empty() { vec![] } else { vec!["cr.audit:read (every app)".to_string()] };
                Ok(Ok(old::AuditView { rows, as_of_ms: g.as_of_ms, sources: srcs, narrowed, can_ask, call_id: g.last_call.clone() }))
            }
        })
        .on::<old::Chain, _, _>(move |_: (), _| {
            let c = c2.clone();
            async move {
                let nodes = chain(c).await.into_iter().map(|x| old::ChainState { node: x.node, rows: x.rows, head_seq: x.head_seq, anchored_seq: x.anchored_seq, first_bad: x.first_bad, why: x.why, checked_ms: x.checked_ms, state: state1(x.state) }).collect();
                Ok(Ok(old::ChainView { nodes, as_of_ms: ui_chain::now_ms() }))
            }
        })
        .audit(ce_gate::audit::file())
        .serve_door();
    let (a, b) = tokio::join!(v2, v1s);
    a.map_err(|e| e.to_string())?;
    b.map_err(|e| e.to_string())
}

fn main() {
    let r = match std::env::args().nth(1).as_deref() {
        Some("serve") => tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|e| e.to_string()).and_then(|rt| rt.block_on(serve())),
        _ => Err("usage: cr-audit serve".into()),
    };
    if let Err(e) = r {
        eprintln!("cr-audit: {e}");
        std::process::exit(1);
    }
}
