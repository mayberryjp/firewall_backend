//! Bounded mDNS wire codec and discovery policy. Names are decoded before any
//! filtering; encoding never copies compression pointers from a received packet.
use anyhow::{Result, bail, ensure};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(crate) use linux::prepare;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Name(Vec<Vec<u8>>);
impl Name {
    fn service(&self) -> bool {
        (self.0.len() >= 3
            && self.0[0].starts_with(b"_")
            && matches!(self.0[1].as_slice(), b"_tcp" | b"_udp"))
            || (self.0.len() >= 5
                && self.0[0].starts_with(b"_")
                && self.0[1] == b"_sub"
                && self.0[2].starts_with(b"_")
                && matches!(self.0[3].as_slice(), b"_tcp" | b"_udp"))
    }
    fn instance(&self) -> bool {
        self.0.len() >= 4
            && self.0[1].starts_with(b"_")
            && matches!(self.0[2].as_slice(), b"_tcp" | b"_udp")
    }
    fn host(&self) -> bool {
        self.0.iter().all(|label| !label.contains(&b'_'))
    }
    fn instance_of(&self, service: &Self) -> bool {
        self.instance()
            && &self.0[1..]
                == if service.0.get(1).is_some_and(|label| label == b"_sub") {
                    &service.0[2..]
                } else {
                    &service.0[..]
                }
    }
    fn text(value: &str) -> Self {
        Self(
            value
                .trim_end_matches('.')
                .split('.')
                .map(|s| s.as_bytes().to_ascii_lowercase())
                .collect(),
        )
    }
    fn encode(&self, out: &mut Vec<u8>) {
        for label in &self.0 {
            out.push(label.len() as u8);
            out.extend_from_slice(label);
        }
        out.push(0);
    }
    fn read(packet: &[u8], position: &mut usize) -> Result<Self> {
        let mut at = *position;
        let mut jumped = false;
        let mut labels = Vec::new();
        let mut length = 1;
        for _ in 0..128 {
            let b = *packet
                .get(at)
                .ok_or_else(|| anyhow::anyhow!("short DNS name"))?;
            if b & 0xc0 == 0xc0 {
                let tail = *packet
                    .get(at + 1)
                    .ok_or_else(|| anyhow::anyhow!("short DNS pointer"))?;
                let offset = ((b as usize & 63) << 8) | tail as usize;
                ensure!(
                    offset < at && offset >= 12,
                    "invalid DNS compression pointer"
                );
                if !jumped {
                    *position = at + 2;
                }
                at = offset;
                jumped = true;
                continue;
            }
            ensure!(b <= 63, "unsupported DNS label encoding");
            at += 1;
            if b == 0 {
                if !jumped {
                    *position = at;
                }
                return Ok(Self(labels));
            }
            let label = packet
                .get(at..at + b as usize)
                .ok_or_else(|| anyhow::anyhow!("short DNS label"))?;
            length += b as usize + 1;
            ensure!(length <= 255, "DNS name too long");
            labels.push(label.to_ascii_lowercase());
            at += b as usize;
            if !jumped {
                *position = at;
            }
        }
        bail!("DNS compression work limit exceeded")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Question {
    name: Name,
    kind: u16,
    class: u16,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Data {
    Bytes(Vec<u8>),
    Name(Name),
    Srv([u8; 6], Name),
    Nsec(Name, Vec<u8>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Record {
    name: Name,
    kind: u16,
    class: u16,
    ttl: u32,
    data: Data,
}
impl Record {
    fn encode(&self, out: &mut Vec<u8>) {
        self.name.encode(out);
        put16(out, self.kind);
        put16(out, self.class);
        out.extend_from_slice(&self.ttl.to_be_bytes());
        let data = self.rdata();
        put16(out, data.len() as u16);
        out.extend_from_slice(&data);
    }
    fn rdata(&self) -> Vec<u8> {
        let mut data = Vec::new();
        match &self.data {
            Data::Bytes(bytes) => data.extend_from_slice(bytes),
            Data::Name(name) => name.encode(&mut data),
            Data::Srv(prefix, name) => {
                data.extend_from_slice(prefix);
                name.encode(&mut data);
            }
            Data::Nsec(name, bitmap) => {
                name.encode(&mut data);
                data.extend_from_slice(bitmap);
            }
        }
        data
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Message {
    id: u16,
    flags: u16,
    questions: Vec<Question>,
    records: [Vec<Record>; 3],
}
fn put16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn get16(packet: &[u8], at: &mut usize) -> Result<u16> {
    let bytes = packet
        .get(*at..*at + 2)
        .ok_or_else(|| anyhow::anyhow!("short DNS integer"))?;
    *at += 2;
    Ok(u16::from_be_bytes(bytes.try_into()?))
}
impl Message {
    fn parse(packet: &[u8]) -> Result<Self> {
        ensure!(
            (12..=9000).contains(&packet.len()),
            "DNS payload outside 12..9000 bytes"
        );
        let mut at = 0;
        let id = get16(packet, &mut at)?;
        let flags = get16(packet, &mut at)?;
        ensure!(flags & 0x780f == 0, "unsupported DNS opcode/rcode");
        let counts = [
            get16(packet, &mut at)?,
            get16(packet, &mut at)?,
            get16(packet, &mut at)?,
            get16(packet, &mut at)?,
        ];
        ensure!(
            counts.iter().map(|n| *n as usize).sum::<usize>() <= 512,
            "DNS record count exceeds 512"
        );
        let mut result = Self {
            id,
            flags,
            ..Self::default()
        };
        for _ in 0..counts[0] {
            let question = Question {
                name: Name::read(packet, &mut at)?,
                kind: get16(packet, &mut at)?,
                class: get16(packet, &mut at)?,
            };
            ensure!(
                [1, 255].contains(&(question.class & 0x7fff)),
                "unsupported_record: non-IN question"
            );
            result.questions.push(question);
        }
        for (section, count) in counts[1..].iter().enumerate() {
            for _ in 0..*count {
                let name = Name::read(packet, &mut at)?;
                let kind = get16(packet, &mut at)?;
                let class = get16(packet, &mut at)?;
                ensure!(class & 0x7fff == 1, "unsupported_record: non-IN class");
                let high = get16(packet, &mut at)? as u32;
                let ttl = (high << 16) | get16(packet, &mut at)? as u32;
                let len = get16(packet, &mut at)? as usize;
                let end = at
                    .checked_add(len)
                    .filter(|end| *end <= packet.len())
                    .ok_or_else(|| anyhow::anyhow!("short DNS RDATA"))?;
                let data = match kind {
                    1 | 28 | 16 | 13 => {
                        ensure!(
                            (kind != 1 || len == 4) && (kind != 28 || len == 16),
                            "invalid address RDATA"
                        );
                        if kind == 16 || kind == 13 {
                            let mut cursor = at;
                            let mut strings = 0;
                            while cursor < end {
                                cursor += packet[cursor] as usize + 1;
                                strings += 1;
                            }
                            ensure!(
                                cursor == end && (kind != 13 || strings == 2),
                                "invalid text RDATA"
                            );
                        }
                        let bytes = packet[at..end].to_vec();
                        at = end;
                        Data::Bytes(bytes)
                    }
                    2 | 5 | 12 | 39 => Data::Name(Name::read(packet, &mut at)?),
                    33 => {
                        ensure!(len >= 7, "short SRV RDATA");
                        let prefix = packet[at..at + 6].try_into()?;
                        at += 6;
                        Data::Srv(prefix, Name::read(packet, &mut at)?)
                    }
                    47 => {
                        let next = Name::read(packet, &mut at)?;
                        ensure!(at <= end, "short NSEC RDATA");
                        let bitmap = packet[at..end].to_vec();
                        let mut cursor = 0;
                        let mut last = None;
                        while cursor < bitmap.len() {
                            ensure!(cursor + 2 <= bitmap.len(), "short NSEC bitmap");
                            let window = bitmap[cursor];
                            let n = bitmap[cursor + 1] as usize;
                            ensure!(
                                (1..=32).contains(&n)
                                    && last.is_none_or(|v| window > v)
                                    && cursor + 2 + n <= bitmap.len(),
                                "invalid NSEC bitmap"
                            );
                            last = Some(window);
                            cursor += n + 2;
                        }
                        at = end;
                        Data::Nsec(next, bitmap)
                    }
                    _ => bail!("unsupported_record: DNS RR type {kind}"),
                };
                ensure!(at == end, "invalid DNS RDATA length");
                result.records[section].push(Record {
                    name,
                    kind,
                    class,
                    ttl,
                    data,
                });
            }
        }
        ensure!(at == packet.len(), "trailing DNS bytes");
        Ok(result)
    }
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put16(&mut out, self.id);
        put16(&mut out, self.flags);
        put16(&mut out, self.questions.len() as u16);
        for records in &self.records {
            put16(&mut out, records.len() as u16);
        }
        for question in &self.questions {
            question.name.encode(&mut out);
            put16(&mut out, question.kind);
            put16(&mut out, question.class);
        }
        for record in self.records.iter().flatten() {
            record.encode(&mut out);
        }
        out
    }
    fn reflected(&mut self) {
        self.id = 0;
        for question in &mut self.questions {
            question.class &= 0x7fff;
        }
    }
    fn empty(&self) -> bool {
        self.questions.is_empty() && self.records.iter().all(Vec::is_empty)
    }
    fn legacy(&mut self, request: &Self) {
        self.id = request.id;
        self.questions = request.questions.clone();
        for question in &mut self.questions {
            question.class &= 0x7fff;
        }
        for record in self.records.iter_mut().flatten() {
            record.class &= 0x7fff;
            record.ttl = record.ttl.min(10);
        }
    }
    // Responses are independent RR datagrams. Query known-answer continuations
    // repeat their question section and use TC except on the final datagram.
    fn split(&self, budget: usize) -> Result<Vec<Vec<u8>>> {
        ensure!(budget >= 512, "mDNS egress MTU too small");
        if self.encode().len() <= budget {
            return Ok(vec![self.encode()]);
        }
        let query = self.flags & 0x8000 == 0;
        let mut current = Self {
            id: self.id,
            flags: self.flags,
            questions: self.questions.clone(),
            ..Self::default()
        };
        ensure!(
            current.encode().len() <= budget,
            "mDNS question section exceeds egress budget"
        );
        let mut result = Vec::new();
        for (section, records) in self.records.iter().enumerate() {
            for record in records {
                current.records[section].push(record.clone());
                if current.encode().len() > budget {
                    current.records[section].pop();
                    ensure!(
                        current.records.iter().any(|r| !r.is_empty()),
                        "mDNS RR exceeds egress budget"
                    );
                    if query {
                        current.flags |= 0x0200;
                    }
                    ensure!(
                        result.len() < 256,
                        "mDNS datagram batch exceeds queue bound"
                    );
                    result.push(current.encode());
                    current = Self {
                        id: self.id,
                        flags: self.flags,
                        questions: self.questions.clone(),
                        ..Self::default()
                    };
                    current.records[section].push(record.clone());
                    ensure!(
                        current.encode().len() <= budget,
                        "mDNS RR exceeds egress budget"
                    );
                }
            }
        }
        if !current.empty() {
            ensure!(
                result.len() < 256,
                "mDNS datagram batch exceeds queue bound"
            );
            result.push(current.encode());
        }
        ensure!(
            result.len() <= 256,
            "mDNS datagram batch exceeds queue bound"
        );
        Ok(result)
    }
}

struct Policy {
    filters: Vec<Name>,
    associations: BTreeMap<Name, Instant>,
    parents: BTreeMap<Name, Name>,
    limit: usize,
}
impl Policy {
    fn new(filters: &[String]) -> Self {
        Self {
            filters: filters.iter().map(|f| Name::text(f)).collect(),
            associations: BTreeMap::new(),
            parents: BTreeMap::new(),
            limit: 8192,
        }
    }
    fn allowed(&self, name: &Name) -> bool {
        self.filters.contains(name) || self.associations.contains_key(name)
    }
    fn enumerated(&self, name: &Name) -> bool {
        self.filters.iter().any(|filter| {
            filter == name
                || (filter.0.len() > 4 && filter.0[1] == b"_sub" && filter.0[2..] == name.0)
        }) || self
            .associations
            .keys()
            .any(|instance| instance.instance_of(name))
    }
    fn question_allowed(&self, question: &Question, query: bool) -> bool {
        if self.allowed(&question.name)
            || question.name == Name::text("_services._dns-sd._udp.local.")
        {
            return true;
        }
        if !query || question.name.0.last().is_none_or(|label| label != b"local") {
            return false;
        }
        let provider = self.filters.iter().any(Name::host);
        // Browsing must reach a provider before its SRV target is known.
        // Questions never authorize records; every section is still filtered.
        (provider && question.name.service() && matches!(question.kind, 12 | 255))
            || (question.name.instance()
                && matches!(question.kind, 16 | 33 | 255)
                && (provider
                    || self
                        .filters
                        .iter()
                        .any(|filter| question.name.instance_of(filter))))
    }
    fn associate(&mut self, name: &Name, ttl: u32, now: Instant, parent: &Name) {
        if name == parent || self.filters.contains(name) {
            return;
        }
        if self.associations.contains_key(name) || self.associations.len() < self.limit {
            let mut expires = now + Duration::from_secs(ttl.min(120) as u64);
            if !self.filters.contains(parent) {
                if let Some(parent_expires) = self.associations.get(parent) {
                    expires = expires.min(*parent_expires);
                }
            }
            if self
                .associations
                .get(name)
                .is_none_or(|old| *old <= expires)
            {
                self.associations.insert(name.clone(), expires);
                self.parents.insert(name.clone(), parent.clone());
            }
        }
    }
    fn prune(&mut self, now: Instant) {
        self.associations.retain(|_, expires| *expires > now);
        // Valid DNS-SD dependencies have at most two edges: type -> instance
        // -> host, or provider -> instance. Invalid/cyclic names never seed one.
        for _ in 0..3 {
            let orphaned = self
                .parents
                .iter()
                .filter(|(_, parent)| !self.allowed(parent))
                .map(|(name, _)| name.clone())
                .collect::<Vec<_>>();
            for name in orphaned {
                self.associations.remove(&name);
            }
            self.parents
                .retain(|name, _| self.associations.contains_key(name));
        }
    }
    fn filter(&mut self, message: &Message, now: Instant) -> Message {
        if self.filters.is_empty() {
            return message.clone();
        }
        self.prune(now);
        // Fixed-point traversal admits only PTR instances and SRV providers
        // rooted in a configured service/provider, never a whole mixed packet.
        for _ in 0..4 {
            for record in message.records.iter().flatten() {
                match &record.data {
                    Data::Name(target)
                        if record.kind == 12
                            && record.name.service()
                            && target.instance_of(&record.name)
                            && self.filters.contains(&record.name) =>
                    {
                        self.associate(target, record.ttl.max(1), now, &record.name);
                    }
                    Data::Srv(_, target)
                        if record.name.instance()
                            && target.host()
                            && self.allowed(&record.name) =>
                    {
                        self.associate(target, record.ttl.max(1), now, &record.name);
                    }
                    Data::Srv(_, target)
                        if record.name.instance()
                            && target.host()
                            && self.filters.contains(target) =>
                    {
                        self.associate(&record.name, record.ttl.max(1), now, target);
                    }
                    _ => {}
                }
            }
        }
        let mut output = message.clone();
        output
            .questions
            .retain(|q| self.question_allowed(q, message.flags & 0x8000 == 0));
        for records in &mut output.records {
            records.retain(|r| match &r.data {
                Data::Name(target) if r.kind == 12 => {
                    if r.name == Name::text("_services._dns-sd._udp.local.") {
                        self.enumerated(target)
                    } else {
                        self.allowed(target)
                            && (self.filters.contains(&r.name)
                                || self.associations.contains_key(target))
                    }
                }
                Data::Srv(_, target) => self.allowed(&r.name) && self.allowed(target),
                Data::Name(target) | Data::Nsec(target, _) => {
                    self.allowed(&r.name) && self.allowed(target)
                }
                Data::Bytes(_) => self.allowed(&r.name),
            });
        }
        for record in output.records.iter().flatten().filter(|r| r.ttl == 0) {
            self.associations.remove(&record.name);
            if let Data::Name(name) = &record.data {
                self.associations.remove(name);
            }
        }
        self.prune(now);
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(name: &str, kind: u16, data: Data) -> Record {
        Record {
            name: Name::text(name),
            kind,
            class: 0x8001,
            ttl: 120,
            data,
        }
    }
    fn discovery() -> Message {
        Message {
            flags: 0x8400,
            records: [
                vec![
                    record(
                        "_ipp._tcp.local.",
                        12,
                        Data::Name(Name::text("printer._ipp._tcp.local.")),
                    ),
                    record(
                        "printer._ipp._tcp.local.",
                        33,
                        Data::Srv([0, 0, 0, 0, 2, 119], Name::text("printer.local.")),
                    ),
                    record(
                        "printer._ipp._tcp.local.",
                        16,
                        Data::Bytes(vec![3, b'a', b'=', b'b']),
                    ),
                    record("printer.local.", 1, Data::Bytes(vec![192, 0, 2, 1])),
                    record(
                        "_ssh._tcp.local.",
                        12,
                        Data::Name(Name::text("private._ssh._tcp.local.")),
                    ),
                    record(
                        "private._ssh._tcp.local.",
                        33,
                        Data::Srv([0, 0, 0, 0, 0, 22], Name::text("private.local.")),
                    ),
                    record("private.local.", 1, Data::Bytes(vec![192, 0, 2, 2])),
                ],
                Vec::new(),
                Vec::new(),
            ],
            ..Message::default()
        }
    }
    #[test]
    fn codec_roundtrip_class_bits_compression_and_bad_packets() {
        let mut m = discovery();
        m.questions.push(Question {
            name: Name::text("_ipp._tcp.local."),
            kind: 12,
            class: 0x8001,
        });
        assert_eq!(Message::parse(&m.encode()).unwrap(), m);
        let mut compressed = vec![
            0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 1, b'a', 5, b'l', b'o', b'c', b'a', b'l', 0, 0, 1,
            128, 1,
        ];
        compressed.extend_from_slice(&[0xc0, 12, 0, 28, 0, 1]);
        assert_eq!(Message::parse(&compressed).unwrap().questions.len(), 2);
        compressed[12] = 0xc0;
        compressed[13] = 12;
        assert!(Message::parse(&compressed).is_err());
        for len in 0..12 {
            assert!(Message::parse(&m.encode()[..len]).is_err());
        }
        m.reflected();
        assert_eq!(m.questions[0].class, 1);
        let nsec = record(
            "printer.local.",
            47,
            Data::Nsec(Name::text("printer.local."), vec![0, 1, 64]),
        );
        m.records[2].push(nsec);
        assert_eq!(Message::parse(&m.encode()).unwrap(), m);
        m.records[2][0].kind = 65280;
        assert!(
            Message::parse(&m.encode())
                .unwrap_err()
                .to_string()
                .contains("unsupported_record")
        );
    }
    #[test]
    fn service_and_provider_filter_mixed_sections_no_leakage() {
        for filter in ["_ipp._tcp.local.", "printer.local."] {
            let mut policy = Policy::new(&[filter.into()]);
            let m = discovery();
            let output = policy.filter(&m, Instant::now());
            assert_eq!(output.records[0].len(), 4);
            assert!(!output.encode().windows(7).any(|w| w == b"private"));
            assert_eq!(Message::parse(&output.encode()).unwrap(), output);
        }
        let mut policy = Policy::new(&["_ipp._tcp.local.".into()]);
        let mut orphan = discovery();
        orphan.records[0].drain(..3);
        assert!(policy.filter(&orphan, Instant::now()).empty());
        policy.filter(&discovery(), Instant::now());
        assert_eq!(policy.filter(&orphan, Instant::now()).records[0].len(), 1);
        assert!(
            policy
                .filter(&orphan, Instant::now() + Duration::from_secs(121))
                .empty()
        );
    }
    #[test]
    fn provider_only_browsing_solicits_services_without_authorizing_peer_records() {
        let now = Instant::now();
        let mut client = Policy::new(&["printer.local.".into()]);
        let mut query = Message {
            questions: vec![
                Question {
                    name: Name::text("_ipp._tcp.local."),
                    kind: 12,
                    class: 1,
                },
                Question {
                    name: Name::text("_print._sub._ipp._tcp.local."),
                    kind: 12,
                    class: 1,
                },
                Question {
                    name: Name::text("printer._ipp._tcp.local."),
                    kind: 33,
                    class: 1,
                },
                Question {
                    name: Name::text("printer._ipp._tcp.local."),
                    kind: 16,
                    class: 1,
                },
                Question {
                    name: Name::text("_ipp._tcp.local."),
                    kind: 255,
                    class: 1,
                },
                Question {
                    name: Name::text("private.local."),
                    kind: 1,
                    class: 1,
                },
                Question {
                    name: Name::text("_ipp._tcp.example."),
                    kind: 12,
                    class: 1,
                },
            ],
            ..Message::default()
        };
        let private = discovery().records[0][4..].to_vec();
        for (section, rr) in private.into_iter().enumerate() {
            query.records[section].push(rr);
        }
        let outgoing = client.filter(&query, now);
        assert_eq!(outgoing.questions.len(), 5);
        assert!(outgoing.records.iter().all(Vec::is_empty));
        assert!(
            client.associations.is_empty(),
            "questions must not authorize dependencies"
        );
        let mut publisher = Policy::new(&["printer.local.".into()]);
        let mut mixed = discovery();
        mixed.records[2] = mixed.records[0].drain(2..).collect();
        let incoming = publisher.filter(&mixed, now);
        assert_eq!(incoming.records.iter().map(Vec::len).sum::<usize>(), 4);
        assert!(!incoming.encode().windows(7).any(|w| w == b"private"));
        let enumeration = Message {
            flags: 0x8400,
            records: [
                vec![
                    record(
                        "_services._dns-sd._udp.local.",
                        12,
                        Data::Name(Name::text("_ipp._tcp.local.")),
                    ),
                    record(
                        "_services._dns-sd._udp.local.",
                        12,
                        Data::Name(Name::text("_ssh._tcp.local.")),
                    ),
                ],
                Vec::new(),
                Vec::new(),
            ],
            ..Message::default()
        };
        assert_eq!(publisher.filter(&enumeration, now).records[0].len(), 1);
        assert!(
            publisher
                .filter(&enumeration, now + Duration::from_secs(121))
                .empty()
        );
        query.flags = 0x8400;
        assert!(
            client.filter(&query, now).empty(),
            "query permission must not admit response records/questions"
        );
        let mut service = Policy::new(&["_ipp._tcp.local.".into()]);
        let followup = Message {
            questions: vec![Question {
                name: Name::text("printer._ipp._tcp.local."),
                kind: 33,
                class: 1,
            }],
            ..Message::default()
        };
        assert_eq!(service.filter(&followup, now).questions, followup.questions);
    }
    #[test]
    fn legacy_replies_and_bounded_splitting() {
        let mut m = discovery();
        m.records[0] = vec![m.records[0][0].clone(); 64];
        let parts = m.split(512).unwrap();
        assert!(parts.len() > 1);
        let mut count = 0;
        for part in parts {
            assert!(part.len() <= 512);
            count += Message::parse(&part).unwrap().records[0].len();
        }
        assert_eq!(count, 64);
        let request = Message {
            id: 42,
            questions: vec![Question {
                name: Name::text("_ipp._tcp.local."),
                kind: 12,
                class: 1,
            }],
            ..Message::default()
        };
        m.legacy(&request);
        assert_eq!(m.id, 42);
        assert_eq!(m.questions, request.questions);
        assert!(
            m.records
                .iter()
                .flatten()
                .all(|r| r.ttl <= 10 && r.class == 1)
        );
        m.flags = 0;
        let parts = m.split(512).unwrap();
        for (index, part) in parts.iter().enumerate() {
            let fragment = Message::parse(part).unwrap();
            assert_eq!(fragment.questions, m.questions);
            assert_eq!(fragment.flags & 0x0200 != 0, index + 1 < parts.len());
        }
    }
    #[test]
    fn subtypes_all_sections_goodbyes_and_association_exhaustion() {
        let mut message = discovery();
        message.records[0][0].name = Name::text("_print._sub._ipp._tcp.local.");
        message.records[2] = message.records[0].drain(1..).collect();
        message.records[1].push(record(
            "_services._dns-sd._udp.local.",
            12,
            Data::Name(Name::text("_ipp._tcp.local.")),
        ));
        let mut policy = Policy::new(&["_print._sub._ipp._tcp.local.".into()]);
        let output = policy.filter(&message, Instant::now());
        assert_eq!(output.records[0].len(), 1);
        assert_eq!(output.records[1].len(), 1);
        assert_eq!(output.records[2].len(), 3);
        let mut goodbye = message.clone();
        for rr in goodbye.records.iter_mut().flatten() {
            rr.ttl = 0;
        }
        let output = policy.filter(&goodbye, Instant::now());
        assert!(output.records.iter().flatten().any(|rr| rr.ttl == 0));
        let orphan = Message {
            records: [
                vec![record("printer.local.", 1, Data::Bytes(vec![192, 0, 2, 1]))],
                Vec::new(),
                Vec::new(),
            ],
            ..Message::default()
        };
        assert!(policy.filter(&orphan, Instant::now()).empty());
        let mut full = Policy::new(&["_ipp._tcp.local.".into()]);
        let now = Instant::now();
        for index in 0..8192 {
            full.associate(
                &Name::text(&format!("host{index}.local.")),
                120,
                now,
                &Name::text("_ipp._tcp.local."),
            );
        }
        assert_eq!(full.associations.len(), 8192);
        assert!(full.filter(&discovery(), now).empty());
        assert_eq!(full.associations.len(), 8192);
        let mut short = discovery();
        short.records[0][0].ttl = 1;
        let mut policy = Policy::new(&["_ipp._tcp.local.".into()]);
        policy.filter(&short, now);
        assert!(policy.filter(&orphan, now + Duration::from_secs(2)).empty());
    }
    #[test]
    fn codec_resource_limits_fail_without_partial_success() {
        let mut header = vec![0u8; 12];
        header[4..6].copy_from_slice(&513u16.to_be_bytes());
        assert!(
            Message::parse(&header)
                .unwrap_err()
                .to_string()
                .contains("512")
        );
        assert!(Message::parse(&vec![0; 9001]).is_err());
        let mut message = Message::default();
        message.records[0].push(record("x.local.", 16, Data::Bytes(vec![0; 3000])));
        assert!(message.split(1232).is_err());
        let mut wrong = discovery().encode();
        wrong[2] = 0x08;
        assert!(Message::parse(&wrong).is_err());
        let name = Name::text(&format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        ));
        let rr = Record {
            name: name.clone(),
            kind: 12,
            class: 1,
            ttl: 120,
            data: Data::Name(name),
        };
        let huge = Message {
            records: [vec![rr; 512], Vec::new(), Vec::new()],
            ..Message::default()
        };
        assert!(
            huge.split(576)
                .unwrap_err()
                .to_string()
                .contains("queue bound")
        );
    }
}
