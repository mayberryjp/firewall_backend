use anyhow::{Result, bail, ensure};
use std::net::Ipv4Addr;

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct Prefix {
    pub address: Ipv4Addr,
    pub length: u8,
}
impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.address, self.length)
    }
}
impl Prefix {
    pub fn new(address: Ipv4Addr, length: u8) -> Result<Self> {
        ensure!(length <= 32, "invalid IPv4 prefix length");
        let mask = u32::MAX.checked_shl(u32::from(32 - length)).unwrap_or(0);
        Ok(Self {
            address: Ipv4Addr::from(u32::from(address) & mask),
            length,
        })
    }
    pub fn overlaps(self, other: Self) -> bool {
        Self::new(self.address, self.length.min(other.length)).ok()
            == Self::new(other.address, self.length.min(other.length)).ok()
    }
}
#[derive(Clone, Debug)]
pub struct Path {
    pub next_hop: Ipv4Addr,
    pub as_path: Vec<u32>,
    pub origin: u8,
    pub local_pref: u32,
    pub med: u32,
}
pub struct Update {
    pub withdrawn: Vec<Prefix>,
    pub announced: Vec<Prefix>,
    pub path: Option<Path>,
}
pub struct Open {
    pub asn: u32,
    pub router_id: Ipv4Addr,
    pub hold: u16,
    pub four_byte: bool,
}
fn take<'a>(bytes: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    ensure!(bytes.len() >= n, "truncated BGP message");
    let (a, b) = bytes.split_at(n);
    *bytes = b;
    Ok(a)
}
fn word(bytes: &mut &[u8]) -> Result<u16> {
    let b = take(bytes, 2)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}
fn prefixes(mut bytes: &[u8]) -> Result<Vec<Prefix>> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        let length = take(&mut bytes, 1)?[0];
        ensure!(length <= 32, "IPv4 NLRI length exceeds 32");
        let mut octets = [0; 4];
        let n = usize::from(length).div_ceil(8);
        octets[..n].copy_from_slice(take(&mut bytes, n)?);
        let p = Prefix::new(octets.into(), length)?;
        ensure!(p.address.octets() == octets, "noncanonical BGP NLRI");
        result.push(p);
    }
    Ok(result)
}
fn nlri(prefix: Prefix) -> Vec<u8> {
    let mut bytes = vec![prefix.length];
    bytes.extend(&prefix.address.octets()[..usize::from(prefix.length).div_ceil(8)]);
    bytes
}
pub fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![255; 16];
    bytes.extend(((body.len() + 19) as u16).to_be_bytes());
    bytes.push(kind);
    bytes.extend(body);
    bytes
}
pub fn extract(buffer: &mut Vec<u8>) -> Result<Option<(u8, Vec<u8>)>> {
    if buffer.len() < 19 {
        return Ok(None);
    }
    ensure!(buffer[..16] == [255; 16], "invalid BGP marker");
    let length = usize::from(u16::from_be_bytes([buffer[16], buffer[17]]));
    ensure!(
        (19..=4096).contains(&length),
        "BGP message length outside 19..4096"
    );
    ensure!(
        (1..=4).contains(&buffer[18]),
        "unsupported BGP message type"
    );
    if buffer.len() < length {
        return Ok(None);
    }
    let kind = buffer[18];
    let body = buffer[19..length].to_vec();
    buffer.drain(..length);
    Ok(Some((kind, body)))
}
pub fn open(asn: u32, id: Ipv4Addr, hold: u16) -> Vec<u8> {
    let mut body = vec![4];
    body.extend((if asn > 65535 { 23456 } else { asn as u16 }).to_be_bytes());
    body.extend(hold.to_be_bytes());
    body.extend(id.octets());
    body.extend([8, 2, 6, 65, 4]);
    body.extend(asn.to_be_bytes());
    frame(1, &body)
}
pub fn parse_open(mut bytes: &[u8]) -> Result<Open> {
    ensure!(take(&mut bytes, 1)?[0] == 4, "BGP version must be 4");
    let short = word(&mut bytes)?;
    let hold = word(&mut bytes)?;
    ensure!(hold == 0 || hold >= 3, "unacceptable BGP hold time");
    let id = take(&mut bytes, 4)?;
    let router_id = Ipv4Addr::new(id[0], id[1], id[2], id[3]);
    ensure!(
        !router_id.is_unspecified() && !router_id.is_multicast() && !router_id.is_broadcast(),
        "invalid BGP router ID"
    );
    let len = usize::from(take(&mut bytes, 1)?[0]);
    ensure!(
        bytes.len() == len,
        "BGP OPEN optional parameter length mismatch"
    );
    let mut as4 = None;
    while !bytes.is_empty() {
        let kind = take(&mut bytes, 1)?[0];
        let n = usize::from(take(&mut bytes, 1)?[0]);
        let mut param = take(&mut bytes, n)?;
        ensure!(kind == 2, "unsupported BGP OPEN parameter");
        while !param.is_empty() {
            let code = take(&mut param, 1)?[0];
            let n = usize::from(take(&mut param, 1)?[0]);
            let value = take(&mut param, n)?;
            if code == 65 {
                ensure!(n == 4 && as4.is_none(), "invalid four-octet ASN capability");
                as4 = Some(u32::from_be_bytes(value.try_into()?));
            }
        }
    }
    let asn = as4.unwrap_or(u32::from(short));
    ensure!(
        short == 23456 || asn == u32::from(short),
        "inconsistent BGP ASN"
    );
    Ok(Open {
        asn,
        router_id,
        hold,
        four_byte: as4.is_some(),
    })
}
pub fn update(mut bytes: &[u8], four_byte: bool, ibgp: bool) -> Result<Update> {
    let n = usize::from(word(&mut bytes)?);
    let withdrawn = prefixes(take(&mut bytes, n)?)?;
    let n = usize::from(word(&mut bytes)?);
    let mut attrs = take(&mut bytes, n)?;
    let announced = prefixes(bytes)?;
    let mut seen = std::collections::BTreeSet::new();
    let (mut origin, mut path, mut next_hop, mut local_pref, mut med) = (None, None, None, None, 0);
    while !attrs.is_empty() {
        let flags = take(&mut attrs, 1)?[0];
        let code = take(&mut attrs, 1)?[0];
        ensure!(
            flags & 15 == 0 && seen.insert(code),
            "invalid or duplicate BGP path attribute"
        );
        let n = if flags & 16 != 0 {
            usize::from(word(&mut attrs)?)
        } else {
            usize::from(take(&mut attrs, 1)?[0])
        };
        let mut value = take(&mut attrs, n)?;
        match code {
            1 => {
                ensure!(
                    flags & 0xe0 == 0x40 && n == 1 && value[0] <= 2,
                    "invalid ORIGIN"
                );
                origin = Some(value[0]);
            }
            2 => {
                ensure!(flags & 0xe0 == 0x40, "invalid AS_PATH flags");
                let mut sequence = Vec::new();
                while !value.is_empty() {
                    let kind = take(&mut value, 1)?[0];
                    let count = usize::from(take(&mut value, 1)?[0]);
                    ensure!(
                        kind == 2 && count > 0,
                        "basic BGP supports nonempty AS_SEQUENCE segments only"
                    );
                    for _ in 0..count {
                        let asn = if four_byte {
                            u32::from_be_bytes(take(&mut value, 4)?.try_into()?)
                        } else {
                            u32::from(word(&mut value)?)
                        };
                        ensure!(asn > 0 && asn < u32::MAX, "invalid AS_PATH ASN");
                        sequence.push(asn);
                    }
                    ensure!(
                        sequence.len() <= 255,
                        "AS_PATH exceeds supported 255-AS limit"
                    );
                }
                path = Some(sequence);
            }
            3 => {
                ensure!(flags & 0xe0 == 0x40 && n == 4, "invalid NEXT_HOP");
                next_hop = Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]));
            }
            4 => {
                ensure!(flags & 0xe0 == 0x80 && n == 4, "invalid MED");
                med = u32::from_be_bytes(value.try_into()?);
            }
            5 => {
                ensure!(flags & 0xe0 == 0x40 && n == 4, "invalid LOCAL_PREF");
                local_pref = Some(u32::from_be_bytes(value.try_into()?));
            }
            6 => ensure!(flags & 0xe0 == 0x40 && n == 0, "invalid ATOMIC_AGGREGATE"),
            7 => ensure!(
                flags & 0xe0 == 0xc0 && n == if four_byte { 8 } else { 6 },
                "invalid AGGREGATOR"
            ),
            _ => ensure!(flags & 0x80 != 0, "unrecognized well-known BGP attribute"),
        }
    }
    if announced.is_empty() {
        return Ok(Update {
            withdrawn,
            announced,
            path: None,
        });
    }
    ensure!(
        origin.is_some() && path.is_some() && next_hop.is_some() && (!ibgp || local_pref.is_some()),
        "missing mandatory BGP path attribute"
    );
    let next_hop = next_hop.unwrap();
    ensure!(
        !next_hop.is_unspecified() && !next_hop.is_multicast() && !next_hop.is_broadcast(),
        "invalid NEXT_HOP"
    );
    Ok(Update {
        withdrawn,
        announced,
        path: Some(Path {
            next_hop,
            as_path: path.unwrap(),
            origin: origin.unwrap(),
            local_pref: local_pref.unwrap_or(100),
            med,
        }),
    })
}
pub fn announce(prefix: Prefix, asn: u32, local: Ipv4Addr, four_byte: bool, ibgp: bool) -> Vec<u8> {
    let mut attrs = vec![0x40, 1, 1, 0, 0x40, 2];
    if ibgp {
        attrs.push(0)
    } else if four_byte {
        attrs.extend([6, 2, 1]);
        attrs.extend(asn.to_be_bytes());
    } else {
        attrs.extend([4, 2, 1]);
        attrs.extend((asn as u16).to_be_bytes());
    }
    attrs.extend([0x40, 3, 4]);
    attrs.extend(local.octets());
    if ibgp {
        attrs.extend([0x40, 5, 4]);
        attrs.extend(100u32.to_be_bytes());
    }
    let mut body = vec![0, 0];
    body.extend((attrs.len() as u16).to_be_bytes());
    body.extend(attrs);
    body.extend(nlri(prefix));
    frame(2, &body)
}
pub fn withdraw(prefix: Prefix) -> Vec<u8> {
    let n = nlri(prefix);
    let mut body = (n.len() as u16).to_be_bytes().to_vec();
    body.extend(n);
    body.extend([0, 0]);
    frame(2, &body)
}
pub fn message(kind: u8, body: &[u8]) -> Result<()> {
    match kind {
        4 => ensure!(body.is_empty(), "KEEPALIVE must be empty"),
        3 => {
            ensure!(body.len() >= 2, "short NOTIFICATION");
            bail!("peer NOTIFICATION code {} subcode {}", body[0], body[1]);
        }
        _ => bail!("unexpected BGP message"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn framing_open_as4_and_update_round_trip() -> Result<()> {
        let mut packet = open(4200000001, "192.0.2.1".parse()?, 90);
        let (kind, body) = extract(&mut packet)?.unwrap();
        assert_eq!(kind, 1);
        let parsed = parse_open(&body)?;
        assert_eq!(parsed.asn, 4200000001);
        assert!(parsed.four_byte);
        let p = Prefix::new("198.51.100.7".parse()?, 24)?;
        for ibgp in [false, true] {
            let mut packet = announce(p, 4200000001, "192.0.2.1".parse()?, true, ibgp);
            let (_, body) = extract(&mut packet)?.unwrap();
            let u = update(&body, true, ibgp)?;
            assert_eq!(u.announced, vec![p]);
            assert_eq!(
                u.path.unwrap().as_path,
                if ibgp { vec![] } else { vec![4200000001] }
            );
        }
        let mut packet = withdraw(p);
        let (_, body) = extract(&mut packet)?.unwrap();
        assert_eq!(update(&body, true, false)?.withdrawn, vec![p]);
        Ok(())
    }
    #[test]
    fn malformed_and_oversized_inputs_are_rejected() {
        for n in 0..10 {
            assert!(parse_open(&vec![0; n]).is_err());
        }
        assert!(update(&[0, 0, 0, 0, 33], true, false).is_err());
        let mut packet = frame(4, &[]);
        packet[16..18].copy_from_slice(&4097u16.to_be_bytes());
        assert!(extract(&mut packet).is_err());
        let mut packet = frame(4, &[]);
        packet[0] = 0;
        assert!(extract(&mut packet).is_err());
        assert!(message(4, &[1]).is_err());
    }
}
