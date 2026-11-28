//! The helper's state machine (edge-firewall.md §4, §5): start-up step 1, `apply`, `disable`,
//! `enable`, and the re-assert pass that keeps Picket's sets, chains and jumps in place, checks
//! the port-53 redirect and reports conditions.
//!
//! The engine runs on one thread of its own ([`run`]) and does all of the slow work there:
//! `iptables-save`/`iptables-restore` (which may wait up to 5 s on the xtables lock), set
//! creation and the static sets' contents. `ensure` and `delete` never go through it.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use picket_api::edge_config::FwMode;
use picket_api::helper::{
    ApplyRequest, ApplyResponse, CatchAllFinding, Conditions, HelperError, LocalDst, MAX_LOCAL_DST_NETS,
    MAX_LOCAL_DST_TOTAL, RedirectCheck, RulesRepaired, SetStatus, error_code, sets,
};
use tokio::sync::oneshot;

use crate::backend::{Backend, SetOp};
use crate::ipset::{CreateSpec, Elem, SetFamily, SetHeader, SetType};
use crate::iptables::layout::{self, DNS6, FWD, Found, MON, Platform};
use crate::iptables::model::Table;
use crate::iptables::nat::{IfAddr, redirect_present};
use crate::iptables::plan::{self, IfFinding, Obj, ObjState, Want};
use crate::iptables::{Family, TableName};
use crate::rules::{Desired, RULES_FILE, RULES_MAX, RulesFile, STATIC_MAX};
use crate::shared::Shared;
use crate::snapshot::{self, SNAP_FILE};

/// The re-assert backstop (edge-firewall.md §4 "Re-assert").
pub const REASSERT: Duration = Duration::from_secs(2);
/// Shortest pause between two passes, however often inotify fires.
const MIN_GAP: Duration = Duration::from_millis(500);
/// Full comparison of the static and exempt sets' contents at least this often.
const STATIC_FULL_CHECK: Duration = Duration::from_secs(60);
/// The DNSFILTER check reads the nat table at least this often even without a redirect
/// (edge-unifi.md §7: "at start and every minute").
const NAT_CHECK: Duration = Duration::from_secs(60);
/// The redirect check reuses the gateway's addresses (`ip -j addr`) this long, so the 2 s check
/// doesn't run `ip` every time…
const ADDR_TTL: Duration = Duration::from_secs(60);
/// …but reads them again first, at most this often, when they would report a redirect
/// missing (the gateway may have been renumbered and the rule with it).
const ADDR_RETRY: Duration = Duration::from_secs(10);

/// One of Picket's sets (edge-firewall.md §2).
#[derive(Clone, Copy, Debug)]
pub struct SetDef {
    pub name: &'static str,
    pub set_type: SetType,
    pub family: SetFamily,
    pub timeout: Option<u32>,
    pub maxelem: u32,
}

impl SetDef {
    pub fn spec(&self) -> CreateSpec {
        CreateSpec {
            name: self.name.into(),
            set_type: self.set_type,
            family: self.family,
            revision: 0,
            timeout: self.timeout,
            maxelem: self.maxelem,
        }
    }
    pub fn timed(&self) -> bool {
        self.timeout.is_some()
    }
}

const fn def(name: &'static str, set_type: SetType, family: SetFamily, timed: bool) -> SetDef {
    SetDef {
        name,
        set_type,
        family,
        timeout: if timed {
            Some(sets::DEFAULT_TIMEOUT_S)
        } else {
            None
        },
        maxelem: if timed { sets::MAXELEM } else { STATIC_MAX },
    }
}

pub const SETS: [SetDef; 8] = [
    def(sets::PICKET4, SetType::HashNetNet, SetFamily::Inet, true),
    def(sets::PICKET6, SetType::HashNetNet, SetFamily::Inet6, true),
    def(sets::PICKET_G4, SetType::HashIp, SetFamily::Inet, true),
    def(sets::PICKET_G6, SetType::HashIp, SetFamily::Inet6, true),
    def(sets::STATIC4, SetType::HashNet, SetFamily::Inet, false),
    def(sets::STATIC6, SetType::HashNet, SetFamily::Inet6, false),
    def(sets::EXEMPT4, SetType::HashNet, SetFamily::Inet, false),
    def(sets::EXEMPT6, SetType::HashNet, SetFamily::Inet6, false),
];

pub fn set_def(name: &str) -> Option<&'static SetDef> {
    SETS.iter().find(|d| d.name == name)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Startup,
    Apply,
    Enable,
    Reassert,
}

/// What one pass did.
#[derive(Clone, Debug, Default)]
pub struct PassReport {
    pub repaired: Vec<String>,
    pub recreated: Vec<String>,
    pub gap: Duration,
    pub pending: Vec<String>,
    pub rules_ok: bool,
    pub conditions: Conditions,
}

enum SetCheck {
    Ok(SetHeader),
    Created,
    Failed(String),
}

pub struct Engine<B: Backend> {
    b: Arc<B>,
    shared: Arc<Shared>,
    platform: Platform,
    desired: Desired,
    has_rules: bool,
    /// The bytes of `rules.json` as last read or written: an unchanged file isn't rewritten
    /// (eMMC writes, README hard rule 8).
    persisted: Option<Vec<u8>>,
    /// `rules.json` lags the rules in force (a write failed): every pass retries it, and it is
    /// `pending` as `persist` until it succeeds, so a restart doesn't lose an `apply` or a
    /// `disable`.
    persist_due: bool,
    /// The current failure has been logged.
    persist_logged: bool,
    disabled: bool,
    /// When each object (internal key) was last seen in place.
    last_ok: HashMap<String, Duration>,
    counter_last: HashMap<(Family, &'static str), u64>,
    redirect_missing: BTreeMap<Family, bool>,
    /// The gateway's addresses and when they were read.
    addrs: Option<(Duration, Vec<IfAddr>)>,
    dnsfilter_nat: bool,
    findings: BTreeMap<Family, Vec<IfFinding>>,
    /// Each family's local destinations, read on every pass with its table; a family whose table
    /// can't be read has none (they would be stale).
    local_dst: BTreeMap<Family, Vec<LocalDst>>,
    shadowed: BTreeMap<Family, bool>,
    last_static_check: Option<Duration>,
    last_nat_check: Option<Duration>,
    set_alarm: HashMap<&'static str, bool>,
    last_emitted: Option<Conditions>,
}

fn internal_key(f: Family, o: &Obj, target: Option<&str>) -> String {
    match o {
        Obj::Chain(c) => format!("chain{}:{c}", f.digit()),
        Obj::Jump(i) => format!("jump{}:{i}:{}", f.digit(), target.unwrap_or("")),
        Obj::Dns6(i) => format!("dns6:{i}"),
    }
}

fn label(f: Family, o: &Obj, st: ObjState) -> String {
    match (o, st) {
        (Obj::Chain(c), _) => format!("chain{}:{c}", f.digit()),
        (Obj::Jump(i), ObjState::Misplaced) => format!("moved{}:{i}", f.digit()),
        (Obj::Jump(i), _) => format!("jump{}:{i}", f.digit()),
        (Obj::Dns6(i), ObjState::Misplaced) => format!("moved-dns6:{i}"),
        (Obj::Dns6(i), _) => format!("dns6:{i}"),
    }
}

fn compatible(h: &SetHeader, d: &SetDef) -> bool {
    h.type_name == d.set_type.name()
        && h.family == Some(d.family)
        && h.timeout.is_some() == d.timed()
        && h.maxelem.is_none_or(|m| m == d.maxelem)
}

impl<B: Backend> Engine<B> {
    pub fn new(b: Arc<B>, shared: Arc<Shared>, platform: Platform) -> Self {
        Self {
            b,
            shared,
            platform,
            desired: Desired::default(),
            has_rules: false,
            disabled: false,
            last_ok: HashMap::new(),
            counter_last: HashMap::new(),
            redirect_missing: BTreeMap::new(),
            addrs: None,
            dnsfilter_nat: false,
            findings: BTreeMap::new(),
            local_dst: BTreeMap::new(),
            shadowed: BTreeMap::new(),
            last_static_check: None,
            last_nat_check: None,
            set_alarm: HashMap::new(),
            last_emitted: None,
            persisted: None,
            persist_due: false,
            persist_logged: false,
        }
    }

    pub fn disabled(&self) -> bool {
        self.disabled
    }

    pub fn desired(&self) -> &Desired {
        &self.desired
    }

    fn mode_target(&self, iface: &str) -> Option<&'static str> {
        self.desired
            .interfaces
            .iter()
            .find(|(n, _)| n == iface)
            .and_then(|(_, m)| match m {
                FwMode::Enforce => Some(FWD),
                FwMode::Monitor => Some(MON),
                FwMode::Off => None,
            })
    }

    /// Start-up step 1 (edge-firewall.md §5): delete leftover temporary files, read
    /// `rules.json`, create the sets if missing and restore the snapshot into the ones it had
    /// to create, delete the snapshot, then apply the last rules. While `disable` is in force
    /// it creates no set and no rule.
    pub fn startup(&mut self) -> PassReport {
        for tmp in [format!("{RULES_FILE}.tmp"), format!("{SNAP_FILE}.tmp")] {
            let _ = self.b.remove_file(&tmp);
        }
        self.load_rules();
        if !self.disabled {
            let mut created = Vec::new();
            for d in &SETS {
                if let SetCheck::Created = self.check_set(d) {
                    created.push(d.name);
                }
            }
            let timed: Vec<&'static str> = created
                .iter()
                .copied()
                .filter(|n| sets::TIMED.contains(n))
                .collect();
            if !timed.is_empty() {
                match snapshot::restore(&*self.b, &timed) {
                    Ok(r) if r != snapshot::RestoreReport::default() => tracing::info!(
                        restored = r.restored,
                        skipped = r.skipped,
                        failed = r.failed,
                        clock_earlier = r.clock_earlier,
                        "snapshot restore"
                    ),
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error = %e, "snapshot restore failed"),
                }
            }
        }
        if let Err(e) = self.b.remove_file(SNAP_FILE) {
            tracing::warn!(error = %e, "cannot delete the snapshot");
        }
        self.pass(Mode::Startup)
    }

    fn load_rules(&mut self) {
        let bytes = match self.b.read_file(RULES_FILE, RULES_MAX) {
            Ok(Some(b)) => b,
            Ok(None) => return,
            Err(e) => {
                tracing::error!(error = %e, "cannot read rules.json; starting without rules");
                return;
            }
        };
        self.persisted = Some(bytes.clone());
        let file: RulesFile = match serde_json::from_slice(&bytes) {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(error = %e, "rules.json is malformed; starting without rules");
                return;
            }
        };
        self.disabled = file.disabled;
        if let Some(req) = file.apply {
            match Desired::from_request(&req) {
                Ok(d) => {
                    self.desired = d;
                    self.has_rules = true;
                }
                Err(e) => tracing::error!(error = %e, "rules.json holds an invalid apply; ignoring it"),
            }
        }
    }

    fn persist(&mut self) -> Result<(), String> {
        let f = RulesFile {
            version: RulesFile::VERSION,
            disabled: self.disabled,
            apply: self.has_rules.then(|| self.desired.to_request()),
        };
        let bytes = serde_json::to_vec(&f).map_err(|e| e.to_string())?;
        if self.persisted.as_ref() == Some(&bytes) {
            return Ok(());
        }
        self.b
            .write_file(RULES_FILE, &mut |w| w.write_all(&bytes))
            .map_err(|e| e.to_string())?;
        self.persisted = Some(bytes);
        Ok(())
    }

    /// `apply` (edge-firewall.md §4).
    pub fn apply(&mut self, req: &ApplyRequest) -> Result<ApplyResponse, HelperError> {
        let d = Desired::from_request(req).map_err(|message| HelperError {
            code: error_code::INVALID.into(),
            message,
        })?;
        self.desired = d;
        self.has_rules = true;
        self.persist_due = true;
        self.prune();
        let rep = self.pass(Mode::Apply);
        Ok(self.response(rep))
    }

    /// `disable`: save the flag, remove the jumps; sets and chains stay.
    pub fn disable(&mut self) -> ApplyResponse {
        self.disabled = true;
        self.persist_due = true;
        // Jumps removed on purpose are not "seen in place" any more: re-adding them at `enable`
        // is not a repair.
        self.last_ok
            .retain(|k, _| !(k.starts_with("jump") || k.starts_with("dns6")));
        self.last_emitted = None;
        let rep = self.pass(Mode::Apply);
        tracing::warn!("firewall disabled: Picket's jumps removed until enable");
        self.response(rep)
    }

    /// `enable`: clear the flag and re-add everything.
    pub fn enable(&mut self) -> ApplyResponse {
        self.disabled = false;
        self.persist_due = true;
        self.last_emitted = None;
        let rep = self.pass(Mode::Enable);
        tracing::info!("firewall enabled");
        self.response(rep)
    }

    fn response(&self, rep: PassReport) -> ApplyResponse {
        ApplyResponse {
            ok: true,
            rules_ok: rep.rules_ok,
            pending: rep.pending,
            conditions: rep.conditions,
        }
    }

    /// Writes `rules.json` if it lags the rules in force; logs a failure once.
    fn persist_if_due(&mut self) {
        if !self.persist_due {
            return;
        }
        match self.persist() {
            Ok(()) => {
                if self.persist_logged {
                    tracing::info!("rules.json written");
                }
                self.persist_due = false;
                self.persist_logged = false;
            }
            Err(e) => {
                if !self.persist_logged {
                    tracing::error!(error = %e, "cannot write rules.json; retrying at every re-assert");
                    self.persist_logged = true;
                }
            }
        }
    }

    /// At SIGTERM: write the snapshot (edge-firewall.md §4 "Persistence").
    pub fn shutdown(&mut self) {
        self.persist_if_due();
        match snapshot::write(&*self.b) {
            Ok(n) => tracing::info!(entries = n, "snapshot written"),
            Err(e) => tracing::error!(error = %e, "cannot write the snapshot"),
        }
    }

    /// Keys of every object the current rules want.
    fn desired_keys(&self) -> HashSet<String> {
        let mut k: HashSet<String> = SETS.iter().map(|d| format!("set:{}", d.name)).collect();
        let dns6 = self.desired.dns6_interfaces();
        for f in Family::BOTH {
            for c in [FWD, MON] {
                k.insert(internal_key(f, &Obj::Chain(c), None));
            }
            for (i, _) in &self.desired.interfaces {
                if let Some(t) = self.mode_target(i) {
                    k.insert(internal_key(f, &Obj::Jump(i.clone()), Some(t)));
                }
            }
        }
        if !dns6.is_empty() {
            k.insert(internal_key(Family::V6, &Obj::Chain(DNS6), None));
            for i in dns6 {
                k.insert(internal_key(Family::V6, &Obj::Dns6(i), None));
            }
        }
        k
    }

    fn prune(&mut self) {
        let keep = self.desired_keys();
        self.last_ok.retain(|k, _| keep.contains(k));
    }

    fn check_set(&mut self, d: &SetDef) -> SetCheck {
        match self.b.ipset_header(d.name) {
            Ok(Some(h)) if compatible(&h, d) => SetCheck::Ok(h),
            Ok(Some(h)) => {
                // Ours by name but created differently (an older helper, or by hand). It can be
                // replaced only while no rule references it.
                if h.references == Some(0) {
                    if let Err(e) = self.b.ipset_destroy(d.name) {
                        return SetCheck::Failed(format!("incompatible:{}", e.reason()));
                    }
                    match self.b.ipset_create(&d.spec()) {
                        Ok(()) => SetCheck::Created,
                        Err(e) => SetCheck::Failed(e.reason()),
                    }
                } else {
                    SetCheck::Failed("incompatible".into())
                }
            }
            Ok(None) => match self.b.ipset_create(&d.spec()) {
                Ok(()) => SetCheck::Created,
                Err(e) => SetCheck::Failed(e.reason()),
            },
            Err(e) => SetCheck::Failed(e.reason()),
        }
    }

    fn alarm(&mut self, name: &'static str, entries: u64, max: u64) {
        if max == 0 {
            return;
        }
        let was = self.set_alarm.get(name).copied().unwrap_or(false);
        if entries * 5 >= max * 4 && !was {
            // 80 % (edge-firewall.md §2): the edge reports fw_set_full.
            self.set_alarm.insert(name, true);
            tracing::warn!(set = name, entries, max, "set at 80 % of maxelem");
            self.shared.publish_set_full(name);
        } else if entries * 4 < max * 3 && was {
            self.set_alarm.insert(name, false);
        }
    }

    fn read(&self, f: Family, t: TableName) -> Result<Table, String> {
        let text = self.b.save(f, t).map_err(|e| e.code().to_string())?;
        Table::parse(&text).map_err(|e| e.to_string())
    }

    fn account_counters(&mut self, f: Family, t: &Table) {
        let mut add = [0u64; 2];
        for (i, chain) in [FWD, MON].into_iter().enumerate() {
            if let Some(p) = plan::final_return_packets(t, f, chain) {
                let growth = match self.counter_last.insert((f, chain), p) {
                    Some(last) if p >= last => p - last,
                    // The rule was re-added: it counts from zero.
                    Some(_) => p,
                    // First sight after the helper started: the baseline.
                    None => 0,
                };
                add[i] = growth;
            }
        }
        if add != [0, 0] {
            self.shared
                .counters
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .add(add[0], add[1]);
        }
    }

    fn sync_static(&mut self, fills: &HashMap<&'static str, u64>, force: bool, pending: &mut Vec<String>) {
        for set in [sets::STATIC4, sets::STATIC6, sets::EXEMPT4, sets::EXEMPT6] {
            let want: BTreeSet<(IpAddr, u8)> = self
                .desired
                .members(set)
                .iter()
                .map(|n| (n.addr(), n.prefix_len()))
                .collect();
            if !force && fills.get(set) == Some(&(want.len() as u64)) {
                continue;
            }
            let mut have = BTreeSet::new();
            let host = |ip: &IpAddr| if ip.is_ipv4() { 32 } else { 128 };
            let listed = self.b.ipset_list(set, &mut |m| {
                if have.len() <= 2 * STATIC_MAX as usize {
                    have.insert((m.elem.ip, m.elem.cidr.unwrap_or_else(|| host(&m.elem.ip))));
                }
            });
            if let Err(e) = listed {
                pending.push(format!("entries:{set}:{}", e.reason()));
                continue;
            }
            let adds: Vec<SetOp> = want
                .difference(&have)
                .map(|(ip, c)| SetOp {
                    set,
                    elem: Elem::net(*ip, *c),
                    timeout: None,
                })
                .collect();
            let dels: Vec<SetOp> = have
                .difference(&want)
                .map(|(ip, c)| SetOp {
                    set,
                    elem: Elem::net(*ip, *c),
                    timeout: None,
                })
                .collect();
            let mut failed = None;
            for r in self
                .b
                .ipset_add_ctl(&adds)
                .into_iter()
                .chain(self.b.ipset_del_ctl(&dels))
            {
                if let Err(e) = r {
                    failed = Some(e.reason());
                }
            }
            if let Some(r) = failed {
                pending.push(format!("entries:{set}:{r}"));
            }
        }
    }

    fn check_nat(&mut self, now: Duration, force: bool, pending: &mut Vec<String>) {
        let redirect = self.desired.redirect.clone();
        if !force
            && redirect.is_none()
            && self
                .last_nat_check
                .is_some_and(|t| now.saturating_sub(t) < NAT_CHECK)
        {
            return;
        }
        self.last_nat_check = Some(now);
        let mut tables = Vec::with_capacity(2);
        let mut dnsfilter = false;
        for f in Family::BOTH {
            match self.read(f, TableName::Nat) {
                Ok(t) => {
                    dnsfilter |= layout::dnsfilter_active(&t);
                    tables.push((f, t));
                }
                Err(code) => pending.push(format!("nat{}:{code}", f.digit())),
            }
        }
        self.dnsfilter_nat = dnsfilter;
        let Some(r) = redirect else {
            self.redirect_missing.clear();
            return;
        };
        let age = |a: &Option<(Duration, Vec<IfAddr>)>| a.as_ref().map(|(t, _)| now.saturating_sub(*t));
        let read_now =
            (force || age(&self.addrs).is_none_or(|a| a >= ADDR_TTL)) && self.read_addrs(now, pending);
        let mut missing = self.redirect_check(&tables, &r);
        if !read_now
            && missing.values().any(|m| *m)
            && age(&self.addrs).is_some_and(|a| a >= ADDR_RETRY)
            && self.read_addrs(now, pending)
        {
            missing = self.redirect_check(&tables, &r);
        }
        for f in Family::BOTH {
            if f == Family::V6 && !r.ipv6 {
                self.redirect_missing.remove(&f);
                continue;
            }
            match missing.get(&f) {
                Some(m) => {
                    self.redirect_missing.insert(f, *m);
                }
                // Never checked successfully: missing until proven present. A failed read keeps
                // the last result rather than flapping.
                None => {
                    self.redirect_missing.entry(f).or_insert(true);
                }
            }
        }
    }

    fn read_addrs(&mut self, now: Duration, pending: &mut Vec<String>) -> bool {
        match self.b.addresses() {
            Ok(a) => {
                self.addrs = Some((now, a));
                true
            }
            Err(e) => {
                pending.push(format!("addresses:{}", e.code()));
                false
            }
        }
    }

    /// Per family checked: whether the redirect is missing, by the cached addresses.
    fn redirect_check(&self, tables: &[(Family, Table)], r: &RedirectCheck) -> BTreeMap<Family, bool> {
        let Some((_, addrs)) = &self.addrs else {
            return BTreeMap::new();
        };
        tables
            .iter()
            .filter(|(f, _)| *f == Family::V4 || r.ipv6)
            .map(|(f, t)| (*f, !redirect_present(t, *f, &r.interfaces, r.port, addrs)))
            .collect()
    }

    fn conditions(&self, dnsfilter_filter: bool) -> Conditions {
        let mut c = Conditions {
            redirect_missing: self
                .redirect_missing
                .iter()
                .filter(|(_, m)| **m)
                .map(|(f, _)| f.label().to_string())
                .collect(),
            helper_disabled: self.disabled,
            ..Default::default()
        };
        if dnsfilter_filter || self.dnsfilter_nat {
            c.unifi_conflict.push("dnsfilter".into());
        }
        if self.shadowed.values().any(|s| *s) {
            c.unifi_conflict.push("shadowed_rules".into());
        }
        let mut unknown = BTreeSet::new();
        let mut found: BTreeMap<String, Found> = BTreeMap::new();
        for fs in self.findings.values() {
            for f in fs {
                if f.layout_unknown() {
                    unknown.insert(f.iface.clone());
                }
                if let Some(x) = f.found() {
                    let e = found.entry(f.iface.clone()).or_insert(x);
                    *e = (*e).min(x);
                }
            }
        }
        c.fw_layout_unknown = unknown.into_iter().collect();
        c.fw_catch_all = found
            .into_iter()
            .map(|(interface, f)| CatchAllFinding {
                interface,
                found: f.as_str().into(),
            })
            .collect();
        c.local_dst = self.local_dst.values().flatten().cloned().collect();
        c
    }

    /// The local destinations of each `enforce` interface of family `f` that has a place for its
    /// jump on UniFi ([`layout::unifi_local_set`]). Each set is read once per pass.
    fn local_dst(&self, f: Family, findings: &[IfFinding]) -> Vec<LocalDst> {
        let mut read: HashMap<&str, Result<Vec<String>, String>> = HashMap::new();
        let mut out = Vec::new();
        for x in findings {
            let Some(found) = &x.local_set else { continue };
            let (set, res) = match found {
                Err(e) => (String::new(), Err(format!("layout:{e}"))),
                Ok(name) => {
                    let r = read.entry(name).or_insert_with(|| self.read_local_set(f, name));
                    (name.clone(), r.clone())
                }
            };
            out.push(LocalDst {
                interface: x.iface.clone(),
                family: f.label().into(),
                set,
                nets: res.clone().unwrap_or_default(),
                unavailable: res.err(),
            });
        }
        within_budget(&mut out);
        out
    }

    /// Reads one of UniFi's `…local_zoned_subnets` sets as networks. Only what a plain lookup
    /// means can be used: a `hash:net` or `hash:ip` set of the table's family, every member
    /// decoded and none `nomatch` (an exception inside a wider member), at most
    /// [`MAX_LOCAL_DST_NETS`] of them. Anything else is reported, never partly used.
    fn read_local_set(&self, f: Family, name: &str) -> Result<Vec<String>, String> {
        let family = match f {
            Family::V4 => SetFamily::Inet,
            Family::V6 => SetFamily::Inet6,
        };
        let usable = |h: &SetHeader| -> Result<(), String> {
            if !matches!(h.type_name.as_str(), "hash:net" | "hash:ip") {
                return Err(format!("set_type:{}", h.type_name));
            }
            if h.family != Some(family) {
                return Err("family".into());
            }
            if h.elements.is_some_and(|n| n as usize > MAX_LOCAL_DST_NETS) {
                return Err("too_large".into());
            }
            Ok(())
        };
        // The header first, so an oversized or foreign set is never listed.
        match self.b.ipset_header(name) {
            Ok(Some(h)) => usable(&h)?,
            Ok(None) => return Err("read:no_set".into()),
            Err(e) => return Err(format!("read:{}", e.reason())),
        }
        let host = family.host_mask();
        let mut nets = BTreeSet::new();
        let (mut over, mut nomatch, mut foreign) = (false, false, false);
        let h = self
            .b
            .ipset_list(name, &mut |m| {
                nomatch |= m.nomatch;
                foreign |= SetFamily::of(&m.elem.ip) != family || m.elem.ip2.is_some();
                if nets.len() >= MAX_LOCAL_DST_NETS {
                    over = true;
                } else {
                    nets.insert((m.elem.ip, m.elem.cidr.unwrap_or(host)));
                }
            })
            .map_err(|e| format!("read:{}", e.reason()))?;
        // The set may have changed between the two reads.
        usable(&h)?;
        if h.undecoded > 0 {
            return Err("undecodable".into());
        }
        if foreign {
            return Err("family".into());
        }
        if nomatch {
            return Err("nomatch".into());
        }
        if over {
            return Err("too_large".into());
        }
        Ok(nets.into_iter().map(|(ip, c)| format!("{ip}/{c}")).collect())
    }

    /// One pass: sets, static contents, both families' chains and jumps (repaired and
    /// verified), the redirect and DNSFILTER checks, conditions and events.
    pub fn pass(&mut self, mode: Mode) -> PassReport {
        // The rules (and the `disable` flag) are saved before the kernel is changed.
        self.persist_if_due();
        let now = self.b.mono();
        let mut rep = PassReport::default();
        let mut all_ok = !self.disabled;
        let mut fills: HashMap<&'static str, u64> = HashMap::new();
        let mut timed_status = Vec::new();

        // Sets: created when missing unless disabled; their fill either way.
        for d in &SETS {
            let key = format!("set:{}", d.name);
            if self.disabled {
                if let Ok(Some(h)) = self.b.ipset_header(d.name) {
                    fills.insert(d.name, h.elements.unwrap_or(0) as u64);
                }
                continue;
            }
            match self.check_set(d) {
                SetCheck::Ok(h) => {
                    fills.insert(d.name, h.elements.unwrap_or(0) as u64);
                    self.last_ok.insert(key, now);
                }
                SetCheck::Created => {
                    fills.insert(d.name, 0);
                    let seen = self.last_ok.get(&key).copied();
                    if let Some(t) = seen {
                        rep.repaired.push(key.clone());
                        rep.gap = rep.gap.max(now.saturating_sub(t));
                    }
                    // A recreated set starts empty: the edge re-sends its entries for it
                    // (edge-firewall.md §4 "Re-assert"). That holds for a set never seen in
                    // place too (its creation failed at start-up, or `enable` after a disabled
                    // boot); only start-up step 1 needs no notice, as the edge connects after it
                    // and seeds itself from `dump`.
                    if d.timed() && mode != Mode::Startup {
                        rep.recreated.push(d.name.to_string());
                    }
                    self.last_ok.insert(key, now);
                }
                SetCheck::Failed(r) => {
                    all_ok = false;
                    rep.pending.push(format!("set:{}:{r}", d.name));
                }
            }
        }
        for d in SETS.iter().filter(|d| d.timed()) {
            if let Some(&n) = fills.get(d.name) {
                self.alarm(d.name, n, d.maxelem as u64);
                timed_status.push(SetStatus {
                    name: d.name.into(),
                    entries: n,
                    max: d.maxelem as u64,
                });
            }
        }
        if !self.disabled {
            let force = mode != Mode::Reassert
                || self
                    .last_static_check
                    .is_none_or(|t| now.saturating_sub(t) >= STATIC_FULL_CHECK);
            if force {
                self.last_static_check = Some(now);
            }
            self.sync_static(&fills, force, &mut rep.pending);
        }

        // Chains and jumps, per family.
        let dns6 = self.desired.dns6_interfaces();
        let mut dnsfilter_filter = false;
        let interfaces = self.desired.interfaces.clone();
        for f in Family::BOTH {
            let want = Want {
                family: f,
                platform: self.platform,
                interfaces: &interfaces,
                dns6: if f == Family::V6 { &dns6 } else { &[] },
                disabled: self.disabled,
            };
            let table = match self.read(f, TableName::Filter) {
                Ok(t) => t,
                Err(code) => {
                    all_ok = false;
                    rep.pending.push(format!("save{}:{code}", f.digit()));
                    self.local_dst.remove(&f);
                    continue;
                }
            };
            self.account_counters(f, &table);
            dnsfilter_filter |= layout::dnsfilter_active(&table);
            let first = plan::plan(&table, &want);
            let mut last = first.clone();
            // Whether `last` describes the table as it is: not after a write whose read-back failed.
            let mut verified = true;
            // Write, then read back to verify: UniFi may have changed the chain in between.
            for _ in 0..2 {
                let Some(text) = last.restore.clone() else { break };
                if let Err(e) = self.b.restore(f, &text) {
                    rep.pending.push(format!("restore{}:{}", f.digit(), e.code()));
                    // A failed restore (a timeout, say) may still have committed: the layout is
                    // unknown until the next pass reads it.
                    verified = false;
                    tracing::warn!(family = f.label(), error = %e, "iptables-restore failed; retrying at the next re-assert");
                    break;
                }
                for (o, st) in &last.states {
                    if let (Obj::Chain(c), true) = (o, *st != ObjState::Ok) {
                        // Our chain was (re)written: its counters restart from zero.
                        self.counter_last.insert((f, c), 0);
                    }
                }
                match self.read(f, TableName::Filter) {
                    Ok(t) => last = plan::plan(&t, &want),
                    Err(code) => {
                        rep.pending.push(format!("save{}:{code}", f.digit()));
                        verified = false;
                        break;
                    }
                }
            }
            if !last.all_ok() || last.restore.is_some() {
                all_ok = false;
            }
            rep.pending.extend(last.problems.iter().cloned());
            let final_state: HashMap<&Obj, ObjState> = last.states.iter().map(|(o, s)| (o, *s)).collect();
            for (o, st) in &first.states {
                if !matches!(st, ObjState::Missing | ObjState::Misplaced) {
                    continue;
                }
                if final_state.get(o) != Some(&ObjState::Ok) {
                    continue;
                }
                let target = match o {
                    Obj::Jump(i) => self.mode_target(i),
                    _ => None,
                };
                if let Some(t) = self.last_ok.get(&internal_key(f, o, target)) {
                    rep.repaired.push(label(f, o, *st));
                    rep.gap = rep.gap.max(now.saturating_sub(*t));
                }
            }
            for (o, st) in &last.states {
                if *st == ObjState::Ok {
                    let target = match o {
                        Obj::Jump(i) => self.mode_target(i),
                        _ => None,
                    };
                    self.last_ok.insert(internal_key(f, o, target), now);
                }
            }
            if verified {
                let local = self.local_dst(f, &last.findings);
                for l in &local {
                    let before = self
                        .local_dst
                        .get(&f)
                        .and_then(|v| v.iter().find(|p| p.interface == l.interface));
                    if l.unavailable.is_some() && before.is_none_or(|p| p.unavailable != l.unavailable) {
                        tracing::info!(interface = %l.interface, family = f.label(), reason = l.unavailable.as_deref(), "UniFi's local networks can't be read; every destination counts as blockable");
                    }
                }
                self.local_dst.insert(f, local);
            } else {
                // The layout the local networks rest on is unknown until a table read succeeds.
                self.local_dst.remove(&f);
            }
            self.findings.insert(f, last.findings.clone());
            self.shadowed.insert(f, last.shadowed);
        }

        // Picket's own objects decide rules_ok (rule presence, edge-firewall.md §4 `status`); a
        // pending `persist` and the redirect and DNSFILTER reads only add pending steps and
        // conditions (picket_api::helper::ApplyResponse::rules_ok).
        rep.rules_ok = all_ok && rep.pending.is_empty();
        if self.persist_due {
            rep.pending.push("persist".into());
        }
        self.check_nat(now, mode != Mode::Reassert, &mut rep.pending);
        let cond = self.conditions(dnsfilter_filter);
        rep.conditions = cond.clone();

        let repaired = mode != Mode::Startup && (!rep.repaired.is_empty() || !rep.recreated.is_empty());
        let last_repair =
            repaired.then(|| picket_api::time::format_secs(&picket_api::time::Timestamp::now()));
        let interfaces = self.desired.interface_modes();
        let pending = rep.pending.clone();
        let rules_ok = rep.rules_ok;
        self.shared.update(|s| {
            s.rules_ok = rules_ok;
            s.conditions = cond.clone();
            s.interfaces = interfaces;
            s.sets = timed_status;
            s.pending = pending;
            if last_repair.is_some() {
                s.last_repair = last_repair;
            }
        });
        if repaired {
            let ev = RulesRepaired {
                missing: rep.repaired.clone(),
                gap_ms: u64::try_from(rep.gap.as_millis()).unwrap_or(u64::MAX),
                recreated_sets: rep.recreated.clone(),
            };
            tracing::warn!(missing = ?ev.missing, recreated = ?ev.recreated_sets, gap_ms = ev.gap_ms, "rules repaired");
            self.shared.publish_repaired(&ev);
        }
        if self.last_emitted.as_ref() != Some(&cond) {
            self.shared.publish_conditions(&cond);
            self.last_emitted = Some(cond);
        }
        self.shared.beat(self.b.mono().as_secs());
        rep
    }
}

/// Requests to the engine thread.
pub enum Cmd {
    Apply(
        Box<ApplyRequest>,
        oneshot::Sender<Result<ApplyResponse, HelperError>>,
    ),
    Disable(oneshot::Sender<ApplyResponse>),
    Enable(oneshot::Sender<ApplyResponse>),
    /// Run a pass soon (inotify on UniFi's state file, or an `ensure` that found no set).
    Trigger,
    Shutdown(oneshot::Sender<()>),
}

/// The engine thread: commands, triggers and the 2 s re-assert. Runs until `Shutdown` or until
/// every sender is gone; writes the snapshot on the way out.
pub fn run<B: Backend>(mut engine: Engine<B>, rx: Receiver<Cmd>) {
    let mut next = Instant::now() + REASSERT;
    let mut follow_up: Option<Instant> = None;
    let mut last_end = Instant::now();
    loop {
        let deadline = follow_up.map_or(next, |f| f.min(next));
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(Cmd::Apply(req, tx)) => {
                let _ = tx.send(engine.apply(&req));
                last_end = Instant::now();
                next = last_end + REASSERT;
            }
            Ok(Cmd::Disable(tx)) => {
                let _ = tx.send(engine.disable());
                last_end = Instant::now();
                next = last_end + REASSERT;
            }
            Ok(Cmd::Enable(tx)) => {
                let _ = tx.send(engine.enable());
                last_end = Instant::now();
                next = last_end + REASSERT;
            }
            Ok(Cmd::Trigger) => {
                // UniFi may write its state file before or after it rewrites the chains: look
                // now and again a second later.
                let soon = (Instant::now() + Duration::from_millis(100)).max(last_end + MIN_GAP);
                next = next.min(soon);
                follow_up = Some(soon + Duration::from_secs(1));
            }
            Ok(Cmd::Shutdown(tx)) => {
                engine.shutdown();
                let _ = tx.send(());
                return;
            }
            Err(RecvTimeoutError::Timeout) => {
                let start = Instant::now();
                if follow_up.is_some_and(|f| f <= start) {
                    follow_up = None;
                }
                engine.pass(Mode::Reassert);
                last_end = Instant::now();
                next = (start + REASSERT).max(last_end + MIN_GAP);
            }
            Err(RecvTimeoutError::Disconnected) => {
                engine.shutdown();
                return;
            }
        }
    }
}

/// Keeps one family's entries within [`MAX_LOCAL_DST_TOTAL`] networks together, in order: an
/// entry that would pass it is reported `too_large` and carries none, so every message carrying
/// the conditions fits a frame.
fn within_budget(entries: &mut [LocalDst]) {
    let mut total = 0usize;
    for e in entries {
        if e.unavailable.is_some() {
            continue;
        }
        if total + e.nets.len() > MAX_LOCAL_DST_TOTAL {
            e.nets = Vec::new();
            e.unavailable = Some("too_large".into());
        } else {
            total += e.nets.len();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(iface: &str, n: usize) -> LocalDst {
        LocalDst {
            interface: iface.into(),
            family: "ipv4".into(),
            set: "UBIOS_local_zoned_subnets".into(),
            nets: (0..n)
                .map(|i| format!("10.{}.{}.0/24", i / 256, i % 256))
                .collect(),
            unavailable: None,
        }
    }

    /// Every interface's entry repeats its set, so a family's entries share one budget: past
    /// it, an entry is `too_large` rather than part of a frame too big to send.
    #[test]
    fn entries_past_the_family_budget_are_too_large() {
        let per = MAX_LOCAL_DST_TOTAL / MAX_LOCAL_DST_NETS;
        let mut v: Vec<LocalDst> = (0..=per)
            .map(|i| entry(&format!("br{i}"), MAX_LOCAL_DST_NETS))
            .collect();
        let mut gone = entry("br99", 0);
        gone.unavailable = Some("read:no_set".into());
        v.insert(1, gone);
        v.push(entry("small", 0));
        within_budget(&mut v);
        let usable = v.iter().filter(|e| e.unavailable.is_none()).count();
        assert_eq!(usable, per + 1, "the first {per} full ones and the empty one");
        let over = &v[per + 1];
        assert_eq!(
            (over.unavailable.as_deref(), over.nets.len()),
            (Some("too_large"), 0)
        );
        assert_eq!(v[1].unavailable.as_deref(), Some("read:no_set"), "left as it was");
        assert!(v.iter().map(|e| e.nets.len()).sum::<usize>() <= MAX_LOCAL_DST_TOTAL);
        // The whole conditions message fits a frame even with IPv6's longest networks.
        let long = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00/120".to_string();
        let mut c = Conditions::default();
        for fam in ["ipv4", "ipv6"] {
            for i in 0..=per {
                let mut e = entry(&format!("br{i}"), 0);
                e.family = fam.into();
                e.nets = vec![long.clone(); MAX_LOCAL_DST_NETS];
                c.local_dst.push(e);
            }
        }
        let (v4, v6): (Vec<_>, Vec<_>) = c.local_dst.into_iter().partition(|e| e.family == "ipv4");
        let (mut v4, mut v6) = (v4, v6);
        within_budget(&mut v4);
        within_budget(&mut v6);
        c.local_dst = v4.into_iter().chain(v6).collect();
        let bytes = serde_json::to_vec(&c).unwrap().len();
        assert!(bytes < picket_api::helper::MAX_FRAME / 2, "{bytes} bytes");
    }
}
