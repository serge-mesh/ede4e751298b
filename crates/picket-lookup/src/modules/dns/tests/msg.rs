//! A small DNS response builder for the `dns` tests.

/// A response to one question, built record by record.
pub struct Msg {
    id: u16,
    flags: u16,
    question: Vec<u8>,
    sections: [Vec<Vec<u8>>; 2],
    opt: Option<Vec<u8>>,
}

/// A name in uncompressed wire form.
pub fn n(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for l in text.trim_end_matches('.').split('.').filter(|l| !l.is_empty()) {
        out.push(l.len() as u8);
        out.extend_from_slice(l.as_bytes());
    }
    out.push(0);
    out
}

/// A compression pointer.
pub fn ptr(offset: u16) -> Vec<u8> {
    (0xC000 | offset).to_be_bytes().to_vec()
}

pub fn a(ip: &str) -> Vec<u8> {
    ip.parse::<std::net::Ipv4Addr>().unwrap().octets().to_vec()
}

pub fn aaaa(ip: &str) -> Vec<u8> {
    ip.parse::<std::net::Ipv6Addr>().unwrap().octets().to_vec()
}

/// SOA data for a negative answer.
pub fn soa() -> Vec<u8> {
    let mut d = n("ns.example.org");
    d.extend(n("hostmaster.example.org"));
    for v in [1u32, 7200, 3600, 1_209_600, 300] {
        d.extend(v.to_be_bytes());
    }
    d
}

/// An EDE option (code 15): INFO-CODE and EXTRA-TEXT.
pub fn ede(code: u16, text: &[u8]) -> (u16, Vec<u8>) {
    let mut p = code.to_be_bytes().to_vec();
    p.extend_from_slice(text);
    (15, p)
}

impl Msg {
    /// A response (QR, RD, RA) to `qname`/`qtype` IN with this rcode.
    pub fn response(id: u16, qname: &str, qtype: u16, rcode: u16) -> Self {
        let mut question = n(qname);
        question.extend(qtype.to_be_bytes());
        question.extend(1u16.to_be_bytes());
        Self {
            id,
            flags: 0x8180 | (rcode & 0xF),
            question,
            sections: [vec![], vec![]],
            opt: None,
        }
    }

    /// Sets TC.
    pub fn tc(mut self) -> Self {
        self.flags |= 0x0200;
        self
    }

    /// Adds a record to the answer (1) or authority (2) section.
    pub fn rr(mut self, section: usize, owner: &[u8], rtype: u16, ttl: u32, rdata: &[u8]) -> Self {
        let mut r = owner.to_vec();
        r.extend(rtype.to_be_bytes());
        r.extend(1u16.to_be_bytes());
        r.extend(ttl.to_be_bytes());
        r.extend((rdata.len() as u16).to_be_bytes());
        r.extend_from_slice(rdata);
        self.sections[section - 1].push(r);
        self
    }

    /// Adds an OPT record with these options.
    pub fn opt(mut self, options: &[(u16, Vec<u8>)]) -> Self {
        let mut body = Vec::new();
        for (code, p) in options {
            body.extend(code.to_be_bytes());
            body.extend((p.len() as u16).to_be_bytes());
            body.extend_from_slice(p);
        }
        let mut r = vec![0u8];
        r.extend(41u16.to_be_bytes());
        r.extend(1232u16.to_be_bytes());
        r.extend(0u32.to_be_bytes());
        r.extend((body.len() as u16).to_be_bytes());
        r.extend(body);
        self.opt = Some(r);
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend(self.id.to_be_bytes());
        m.extend(self.flags.to_be_bytes());
        m.extend(1u16.to_be_bytes());
        m.extend((self.sections[0].len() as u16).to_be_bytes());
        m.extend((self.sections[1].len() as u16).to_be_bytes());
        m.extend(u16::from(self.opt.is_some()).to_be_bytes());
        m.extend(&self.question);
        for s in &self.sections {
            for r in s {
                m.extend(r);
            }
        }
        if let Some(o) = &self.opt {
            m.extend(o);
        }
        m
    }
}
