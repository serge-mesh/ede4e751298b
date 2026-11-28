//! An in-memory [`Backend`] for tests: ipsets with expiring members, iptables tables that
//! `iptables-restore --noflush` text is applied to (atomically, refusing what iptables would
//! refuse), a controllable clock and files, and fault injection (lock timeouts, a stalled
//! netlink probe, a restore held until released, sets destroyed or tables rewritten behind the
//! helper's back). Compiled for this crate's tests and with the `testkit` feature (the integration
//! tests, picket-edge's firewall tests, fuzz/helper); the shipped helper doesn't carry it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "a test double: a failure is the test's report, and it may cast freely"
)]

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::io::{self, Cursor, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

use crate::backend::{Backend, SetOp};
use crate::ipset::proto::{IPSET_ERR_HASH_FULL, IPSET_ERR_INVALID_FAMILY, IPSET_ERR_REFERENCED};
use crate::ipset::{CreateSpec, Elem, IpsetError, Member, SetFamily, SetHeader, SetType};
use crate::iptables::model::{Table, join_toks, norm_text, tokenize};
use crate::iptables::nat::IfAddr;
use crate::iptables::{ExecError, Family, TableName};

#[derive(Clone, Debug)]
pub struct FakeSet {
    pub set_type: SetType,
    pub family: SetFamily,
    pub timeout: Option<u32>,
    pub maxelem: u32,
    /// Member → expiry (monotonic); `None` = permanent.
    pub members: BTreeMap<Elem, Option<Duration>>,
    /// Members listed as `nomatch` (UniFi's own sets; Picket never adds such members).
    pub nomatch: BTreeSet<Elem>,
}

#[derive(Clone, Debug, Default)]
pub struct FakeChain {
    pub name: String,
    pub policy: Option<String>,
    /// Rule arguments (after `-A CHAIN`) and packet counter.
    pub rules: Vec<(String, u64)>,
}

#[derive(Clone, Debug, Default)]
pub struct FakeTable {
    pub chains: Vec<FakeChain>,
}

const BUILTIN_TARGETS: [&str; 14] = [
    "ACCEPT",
    "DROP",
    "REJECT",
    "RETURN",
    "NFLOG",
    "LOG",
    "DNAT",
    "SNAT",
    "MASQUERADE",
    "REDIRECT",
    "MARK",
    "CONNMARK",
    "TRACE",
    "NFQUEUE",
];

impl FakeTable {
    pub fn from_text(text: &str) -> FakeTable {
        let t = Table::parse(text).expect("fixture parses");
        FakeTable {
            chains: t
                .chains
                .iter()
                .map(|c| FakeChain {
                    name: c.name.clone(),
                    policy: c.policy.clone(),
                    rules: c
                        .rules
                        .iter()
                        .map(|r| {
                            (
                                r.args_text().unwrap_or_default(),
                                r.counters.map(|(p, _)| p).unwrap_or(0),
                            )
                        })
                        .collect(),
                })
                .collect(),
        }
    }

    pub fn render(&self, table: &str, counters: bool) -> String {
        let mut s = format!("*{table}\n");
        for c in &self.chains {
            s.push_str(&format!(
                ":{} {} [0:0]\n",
                c.name,
                c.policy.as_deref().unwrap_or("-")
            ));
        }
        for c in &self.chains {
            for (r, p) in &c.rules {
                if counters {
                    s.push_str(&format!("[{p}:{}] ", p * 60));
                }
                s.push_str(&format!("-A {} {r}\n", c.name));
            }
        }
        s.push_str("COMMIT\n");
        s
    }

    fn chain_mut(&mut self, name: &str) -> Option<&mut FakeChain> {
        self.chains.iter_mut().find(|c| c.name == name)
    }

    pub fn chain(&self, name: &str) -> Option<&FakeChain> {
        self.chains.iter().find(|c| c.name == name)
    }

    fn referenced(&self, name: &str) -> bool {
        self.chains.iter().flat_map(|c| &c.rules).any(|(r, _)| {
            let toks = tokenize(r);
            toks.windows(2)
                .any(|w| (w[0].text == "-j" || w[0].text == "-g") && w[1].text == name)
        })
    }

    /// Applies `iptables-restore --noflush` text; all or nothing, like the real command.
    fn apply(&mut self, text: &str, sets: &BTreeMap<String, FakeSet>) -> Result<(), String> {
        let mut t = self.clone();
        for (n, raw) in text.lines().enumerate() {
            let line = raw.trim();
            let fail = |m: &str| Err(format!("line {}: {m}: {line}", n + 1));
            if line.is_empty() || line.starts_with('#') || line.starts_with('*') || line == "COMMIT" {
                continue;
            }
            if let Some(rest) = line.strip_prefix(':') {
                let mut it = rest.split_whitespace();
                let name = it.next().unwrap_or_default().to_string();
                let policy = it.next().filter(|p| *p != "-").map(str::to_string);
                match t.chain_mut(&name) {
                    // --noflush: a declared user chain is flushed.
                    Some(c) if c.policy.is_none() => c.rules.clear(),
                    Some(c) => c.policy = policy.or(c.policy.take()),
                    None => t.chains.push(FakeChain {
                        name,
                        policy,
                        rules: Vec::new(),
                    }),
                }
                continue;
            }
            let toks = tokenize(line);
            if toks.len() < 2 {
                return fail("short line");
            }
            let op = toks[0].text.as_str();
            let chain = toks[1].text.clone();
            match op {
                "-F" => match t.chain_mut(&chain) {
                    Some(c) => c.rules.clear(),
                    None => return fail("no chain"),
                },
                "-X" => {
                    let Some(c) = t.chain(&chain) else {
                        return fail("no chain");
                    };
                    if !c.rules.is_empty() || c.policy.is_some() || t.referenced(&chain) {
                        return fail("chain in use");
                    }
                    t.chains.retain(|c| c.name != chain);
                }
                "-A" | "-I" | "-D" => {
                    let (pos, rest) = if op == "-I" {
                        match toks.get(2).and_then(|x| x.text.parse::<usize>().ok()) {
                            Some(p) => (Some(p), &toks[3..]),
                            None => (Some(1), &toks[2..]),
                        }
                    } else {
                        (None, &toks[2..])
                    };
                    let args = join_toks(rest);
                    if op != "-D" {
                        // Targets and sets must exist.
                        for w in rest.windows(2) {
                            if (w[0].text == "-j" || w[0].text == "-g")
                                && !BUILTIN_TARGETS.contains(&w[1].text.as_str())
                                && t.chain(&w[1].text).is_none()
                            {
                                return fail("no such target");
                            }
                            if w[0].text == "--match-set" && !sets.contains_key(&w[1].text) {
                                return fail("no such set");
                            }
                        }
                    }
                    let Some(c) = t.chain_mut(&chain) else {
                        return fail("no chain");
                    };
                    match op {
                        "-A" => c.rules.push((args, 0)),
                        "-I" => {
                            let p = pos.unwrap_or(1);
                            if p == 0 || p > c.rules.len() + 1 {
                                return fail("index of insertion too big");
                            }
                            c.rules.insert(p - 1, (args, 0));
                        }
                        _ => {
                            let want = norm_text(&args);
                            match c.rules.iter().position(|(r, _)| norm_text(r) == want) {
                                Some(i) => {
                                    c.rules.remove(i);
                                }
                                None => return fail("Bad rule (does a matching rule exist in that chain?)"),
                            }
                        }
                    }
                }
                _ => return fail("unknown command"),
            }
        }
        *self = t;
        Ok(())
    }
}

pub struct FakeState {
    pub sets: BTreeMap<String, FakeSet>,
    pub tables: HashMap<(Family, TableName), FakeTable>,
    pub addrs: Vec<IfAddr>,
    pub files: BTreeMap<String, Vec<u8>>,
    pub wall_ms: i64,
    pub mono: Duration,
    pub uptime: Option<Duration>,
    pub restore_errors: VecDeque<ExecError>,
    pub save_errors: VecDeque<ExecError>,
    /// Tables whose reads keep failing.
    pub save_fail: Vec<(Family, TableName)>,
    /// Families whose filter-table reads start failing after their next restore (a failed
    /// read-back).
    pub fail_reads_after_restore: Vec<Family>,
    pub restores: Vec<(Family, String)>,
    /// Every set created, in order.
    pub created: Vec<String>,
    /// While set, file writes fail (a full or read-only disk).
    pub write_fail: bool,
    /// How often the gateway's addresses were read.
    pub addr_reads: usize,
    /// Time each control-path add batch takes: the clocks move on by this after it is applied
    /// (a slow restore).
    pub add_ctl_delay: Duration,
    /// Sets whose creation fails with a netlink timeout.
    pub create_fail: Vec<String>,
}

pub struct FakeBackend {
    state: Mutex<FakeState>,
    /// While `Some(false)`, restores wait (an iptables-restore held on the xtables lock).
    gate: Arc<(Mutex<Option<bool>>, Condvar)>,
    /// While set, the fast-path probe stalls (a hung netlink call).
    pub probe_hang: AtomicBool,
}

impl Default for FakeBackend {
    fn default() -> Self {
        Self::new()
    }
}

const FILTER_BASE: &str = ":INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n";
const NAT_BASE: &str =
    ":PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\n";

impl FakeBackend {
    pub fn new() -> Self {
        let mut tables = HashMap::new();
        for f in Family::BOTH {
            tables.insert((f, TableName::Filter), FakeTable::from_text(FILTER_BASE));
            tables.insert((f, TableName::Nat), FakeTable::from_text(NAT_BASE));
        }
        Self {
            state: Mutex::new(FakeState {
                sets: BTreeMap::new(),
                tables,
                addrs: Vec::new(),
                files: BTreeMap::new(),
                wall_ms: 1_763_700_000_000,
                mono: Duration::from_secs(1000),
                uptime: Some(Duration::from_secs(60)),
                restore_errors: VecDeque::new(),
                save_errors: VecDeque::new(),
                save_fail: Vec::new(),
                fail_reads_after_restore: Vec::new(),
                restores: Vec::new(),
                created: Vec::new(),
                write_fail: false,
                addr_reads: 0,
                add_ctl_delay: Duration::ZERO,
                create_fail: Vec::new(),
            }),
            gate: Arc::new((Mutex::new(None), Condvar::new())),
            probe_hang: AtomicBool::new(false),
        }
    }

    pub fn st(&self) -> MutexGuard<'_, FakeState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Replaces a table with `iptables -S` / `iptables-save` text (UniFi rewriting it).
    pub fn set_table(&self, f: Family, t: TableName, text: &str) {
        self.st().tables.insert((f, t), FakeTable::from_text(text));
    }

    pub fn table(&self, f: Family, t: TableName) -> FakeTable {
        self.st().tables.get(&(f, t)).cloned().unwrap_or_default()
    }

    /// The rules of one chain, as text.
    pub fn rules(&self, f: Family, chain: &str) -> Vec<String> {
        self.table(f, TableName::Filter)
            .chain(chain)
            .map(|c| c.rules.iter().map(|r| r.0.clone()).collect())
            .unwrap_or_default()
    }

    pub fn set_counter(&self, f: Family, chain: &str, index: usize, packets: u64) {
        let mut st = self.st();
        let t = st.tables.get_mut(&(f, TableName::Filter)).expect("table");
        if let Some(c) = t.chain_mut(chain)
            && let Some(r) = c.rules.get_mut(index)
        {
            r.1 = packets;
        }
    }

    pub fn advance(&self, d: Duration) {
        let mut st = self.st();
        st.mono += d;
        st.wall_ms += d.as_millis() as i64;
        if let Some(u) = st.uptime.as_mut() {
            *u += d;
        }
    }

    pub fn push_restore_error(&self, e: ExecError) {
        self.st().restore_errors.push_back(e);
    }

    /// Creates or replaces a set the way UniFi does (one of its own, e.g.
    /// `UBIOS_local_zoned_subnets`): permanent members, `true` marking a `nomatch` one.
    pub fn put_set(&self, name: &str, set_type: SetType, family: SetFamily, members: &[(Elem, bool)]) {
        self.st().sets.insert(
            name.into(),
            FakeSet {
                set_type,
                family,
                timeout: None,
                maxelem: 65_536,
                members: members.iter().map(|(e, _)| (*e, None)).collect(),
                nomatch: members.iter().filter(|(_, n)| *n).map(|(e, _)| *e).collect(),
            },
        );
    }

    /// Destroys a set as a reboot or UniFi's clean-up would (ignoring references).
    pub fn destroy_behind_back(&self, name: &str) {
        self.st().sets.remove(name);
    }

    /// Live members with their remaining seconds (`None` = permanent).
    pub fn members(&self, set: &str) -> Vec<(Elem, Option<u32>)> {
        let st = self.st();
        let now = st.mono;
        st.sets
            .get(set)
            .map(|s| {
                s.members
                    .iter()
                    .filter(|(_, e)| e.is_none_or(|e| e > now))
                    .map(|(m, e)| (*m, e.map(|e| (e - now).as_secs() as u32)))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Holds every restore until [`FakeBackend::open_gate`].
    pub fn close_gate(&self) {
        *self.gate.0.lock().unwrap() = Some(false);
    }

    pub fn open_gate(&self) {
        *self.gate.0.lock().unwrap() = None;
        self.gate.1.notify_all();
    }

    fn purge(s: &mut FakeSet, now: Duration) {
        s.members.retain(|_, e| e.is_none_or(|e| e > now));
    }

    fn elem_family(e: &Elem) -> SetFamily {
        SetFamily::of(&e.ip)
    }

    fn do_add(&self, ops: &[SetOp]) -> Vec<Result<(), IpsetError>> {
        let mut st = self.st();
        let now = st.mono;
        // Expired members are collected once per call (as the kernel's gc would), not per add.
        let mut purged: Vec<&str> = Vec::new();
        ops.iter()
            .map(|op| {
                let Some(s) = st.sets.get_mut(op.set) else {
                    return Err(IpsetError::Kernel(2));
                };
                if Self::elem_family(&op.elem) != s.family {
                    return Err(IpsetError::Kernel(IPSET_ERR_INVALID_FAMILY));
                }
                if !purged.contains(&op.set) {
                    Self::purge(s, now);
                    purged.push(op.set);
                }
                let t = op.timeout.or(s.timeout);
                let exp = match t {
                    Some(0) | None => None,
                    Some(t) => Some(now + Duration::from_secs(t as u64)),
                };
                if let Some(e) = s.members.get_mut(&op.elem) {
                    *e = exp; // -exist: the timeout is overwritten
                    return Ok(());
                }
                if s.members.len() >= s.maxelem as usize {
                    return Err(IpsetError::Kernel(IPSET_ERR_HASH_FULL));
                }
                s.members.insert(op.elem, exp);
                Ok(())
            })
            .collect()
    }

    fn do_del(&self, ops: &[SetOp]) -> Vec<Result<(), IpsetError>> {
        let mut st = self.st();
        ops.iter()
            .map(|op| match st.sets.get_mut(op.set) {
                Some(s) => {
                    s.members.remove(&op.elem);
                    Ok(())
                }
                None => Err(IpsetError::Kernel(2)),
            })
            .collect()
    }

    fn references(st: &FakeState, name: &str) -> u32 {
        st.tables
            .values()
            .flat_map(|t| &t.chains)
            .flat_map(|c| &c.rules)
            .filter(|(r, _)| {
                let toks = tokenize(r);
                toks.windows(2)
                    .any(|w| w[0].text == "--match-set" && w[1].text == name)
            })
            .count() as u32
    }
}

impl Backend for FakeBackend {
    fn ipset_header(&self, name: &str) -> Result<Option<SetHeader>, IpsetError> {
        let mut st = self.st();
        let now = st.mono;
        let refs = Self::references(&st, name);
        let Some(s) = st.sets.get_mut(name) else {
            return Ok(None);
        };
        Self::purge(s, now);
        Ok(Some(SetHeader {
            name: name.into(),
            type_name: s.set_type.name().into(),
            family: Some(s.family),
            revision: 0,
            maxelem: Some(s.maxelem),
            elements: Some(s.members.len() as u32),
            references: Some(refs),
            timeout: s.timeout,
            undecoded: 0,
        }))
    }

    fn ipset_create(&self, spec: &CreateSpec) -> Result<(), IpsetError> {
        let mut st = self.st();
        if st.create_fail.contains(&spec.name) {
            return Err(IpsetError::Timeout);
        }
        if st.sets.contains_key(&spec.name) {
            return Err(IpsetError::Kernel(17));
        }
        st.sets.insert(
            spec.name.clone(),
            FakeSet {
                set_type: spec.set_type,
                family: spec.family,
                timeout: spec.timeout,
                maxelem: spec.maxelem,
                members: BTreeMap::new(),
                nomatch: BTreeSet::new(),
            },
        );
        st.created.push(spec.name.clone());
        Ok(())
    }

    fn ipset_destroy(&self, name: &str) -> Result<(), IpsetError> {
        let mut st = self.st();
        if !st.sets.contains_key(name) {
            return Err(IpsetError::Kernel(2));
        }
        if Self::references(&st, name) > 0 {
            return Err(IpsetError::Kernel(IPSET_ERR_REFERENCED));
        }
        st.sets.remove(name);
        Ok(())
    }

    fn ipset_list(&self, name: &str, sink: &mut dyn FnMut(Member)) -> Result<SetHeader, IpsetError> {
        let h = self.ipset_header(name)?.ok_or(IpsetError::Kernel(2))?;
        let now = self.st().mono;
        let members: Vec<(Elem, Option<Duration>, bool)> = {
            let st = self.st();
            st.sets
                .get(name)
                .map(|s| {
                    s.members
                        .iter()
                        .map(|(e, x)| (*e, *x, s.nomatch.contains(e)))
                        .collect()
                })
                .unwrap_or_default()
        };
        let timed = h.timeout.is_some();
        for (e, exp, nomatch) in members {
            let timeout = match (timed, exp) {
                (false, _) => None,
                (true, None) => Some(0),
                (true, Some(x)) => Some(((x - now).as_secs() as u32).max(1)),
            };
            sink(Member {
                elem: e,
                timeout,
                nomatch,
            });
        }
        Ok(h)
    }

    fn ipset_add_ctl(&self, ops: &[SetOp]) -> Vec<Result<(), IpsetError>> {
        let r = self.do_add(ops);
        let delay = self.st().add_ctl_delay;
        if !delay.is_zero() && !ops.is_empty() {
            self.advance(delay);
        }
        r
    }
    fn ipset_del_ctl(&self, ops: &[SetOp]) -> Vec<Result<(), IpsetError>> {
        self.do_del(ops)
    }
    fn ipset_add(&self, ops: &[SetOp]) -> Vec<Result<(), IpsetError>> {
        self.do_add(ops)
    }
    fn ipset_del(&self, ops: &[SetOp]) -> Vec<Result<(), IpsetError>> {
        self.do_del(ops)
    }
    fn ipset_probe(&self) -> Result<(), IpsetError> {
        let mut waited = 0;
        while self.probe_hang.load(Ordering::SeqCst) && waited < 600 {
            std::thread::sleep(Duration::from_millis(50));
            waited += 1;
        }
        Ok(())
    }

    fn save(&self, f: Family, t: TableName) -> Result<String, ExecError> {
        let mut st = self.st();
        if let Some(e) = st.save_errors.pop_front() {
            return Err(e);
        }
        if st.save_fail.contains(&(f, t)) {
            return Err(ExecError::Timeout);
        }
        Ok(st
            .tables
            .get(&(f, t))
            .map(|x| x.render(t.as_str(), t == TableName::Filter))
            .unwrap_or_default())
    }

    fn restore(&self, f: Family, text: &str) -> Result<(), ExecError> {
        {
            let (m, cv) = &*self.gate;
            let mut g = m.lock().unwrap();
            let mut waited = Duration::ZERO;
            while *g == Some(false) && waited < Duration::from_secs(20) {
                let (ng, _) = cv.wait_timeout(g, Duration::from_millis(50)).unwrap();
                g = ng;
                waited += Duration::from_millis(50);
            }
        }
        let mut st = self.st();
        if let Some(e) = st.restore_errors.pop_front() {
            return Err(e);
        }
        st.restores.push((f, text.to_string()));
        if let Some(i) = st.fail_reads_after_restore.iter().position(|x| *x == f) {
            st.fail_reads_after_restore.remove(i);
            st.save_fail.push((f, TableName::Filter));
        }
        let sets = st.sets.clone();
        let table = st.tables.entry((f, TableName::Filter)).or_default();
        table.apply(text, &sets).map_err(|stderr| ExecError::Failed {
            code: Some(1),
            stderr,
        })
    }

    fn addresses(&self) -> Result<Vec<IfAddr>, ExecError> {
        let mut st = self.st();
        st.addr_reads += 1;
        Ok(st.addrs.clone())
    }

    fn wall_ms(&self) -> i64 {
        self.st().wall_ms
    }
    fn mono(&self) -> Duration {
        self.st().mono
    }
    fn uptime(&self) -> Option<Duration> {
        self.st().uptime
    }

    fn read_file(&self, name: &str, max: u64) -> io::Result<Option<Vec<u8>>> {
        match self.st().files.get(name) {
            Some(b) if b.len() as u64 > max => Err(io::Error::new(io::ErrorKind::InvalidData, "too large")),
            Some(b) => Ok(Some(b.clone())),
            None => Ok(None),
        }
    }
    fn open_file(&self, name: &str) -> io::Result<Option<Box<dyn Read + Send>>> {
        Ok(self
            .st()
            .files
            .get(name)
            .map(|b| Box::new(Cursor::new(b.clone())) as Box<dyn Read + Send>))
    }
    fn write_file(
        &self,
        name: &str,
        write: &mut dyn FnMut(&mut dyn Write) -> io::Result<()>,
    ) -> io::Result<()> {
        if self.st().write_fail {
            return Err(io::Error::other("no space left on device"));
        }
        let mut buf = Vec::new();
        write(&mut buf)?;
        self.st().files.insert(name.to_string(), buf);
        Ok(())
    }
    fn remove_file(&self, name: &str) -> io::Result<()> {
        self.st().files.remove(name);
        Ok(())
    }
}
