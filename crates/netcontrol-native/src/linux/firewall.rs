use anyhow::Result;
use rustables::{
    Batch, Chain, ChainPolicy, ChainType, Hook, HookClass, MsgType, Protocol, ProtocolFamily, Rule,
    Table,
    expr::{
        Bitwise, Cmp, CmpOp, ConnTrackState, Conntrack, ConntrackKey, Masquerade, Meta, MetaType,
    },
};
use serde_json::Value;

const TABLE: &str = "netcontrol";
pub fn validate(value: &Value) -> Result<()> {
    crate::firewall_plan::compile(value)?;
    Ok(())
}

pub fn verify(value: &Value, recorded: &Option<Value>, fingerprint: Option<&str>) -> Result<()> {
    let observed = super::netfilter::fingerprint()?;
    match (recorded, fingerprint) {
        (Some(recorded), Some(expected)) => {
            crate::ensure_unchanged(
                recorded == value,
                "owned firewall configuration differs from committed state",
            )?;
            crate::ensure_unchanged(observed == expected, "owned nftables table drift")?;
        }
        (None, None) => {
            crate::ensure_unchanged(
                observed == super::netfilter::empty_fingerprint(),
                "refusing to adopt preexisting nftables table without durable ownership",
            )?;
            crate::ensure_unchanged(
                value["policy"] == "accept"
                    && value["rules"].as_array().is_some_and(Vec::is_empty)
                    && value["nat"]["masquerade"]
                        .as_array()
                        .is_some_and(Vec::is_empty)
                    && value.get("policies").is_none_or(Value::is_null),
                "nonempty firewall has no durable owned state",
            )?;
        }
        _ => anyhow::bail!("incomplete native firewall ownership journal"),
    }
    Ok(())
}

fn matching(chain: &Chain, plan: &crate::firewall_plan::Match) -> Result<Rule> {
    let mut rule = Rule::new(chain)?;
    if plan.established_related {
        rule = rule
            .with_expr(Conntrack::new(ConntrackKey::State))
            .with_expr(Bitwise::new(
                (ConnTrackState::ESTABLISHED | ConnTrackState::RELATED)
                    .bits()
                    .to_ne_bytes(),
                0u32.to_ne_bytes(),
            )?)
            .with_expr(Cmp::new(CmpOp::Neq, 0u32.to_ne_bytes()));
    }
    if !plan.source.is_empty() {
        rule = rule.snetwork(plan.source.parse()?)?;
    }
    if !plan.destination.is_empty() {
        rule = rule.dnetwork(plan.destination.parse()?)?;
    }
    if !plan.ingress.is_empty() {
        rule = rule.iiface(&plan.ingress)?;
    }
    if !plan.protocol.is_empty() {
        let protocol = if plan.protocol == "tcp" {
            Protocol::TCP
        } else {
            Protocol::UDP
        };
        rule = if plan.port != 0 {
            rule.dport(plan.port, protocol)
        } else {
            rule.protocol(protocol)
        };
    }
    Ok(if plan.action == "drop" {
        rule.drop()
    } else {
        rule.accept()
    })
}
fn icmp(chain: &Chain) -> Result<Rule> {
    Ok(Rule::new(chain)?
        .with_expr(Meta::new(MetaType::NfProto))
        .with_expr(Cmp::new(CmpOp::Eq, [libc::NFPROTO_IPV4 as u8]))
        .icmp()
        .accept())
}

pub fn remove_owned(expected: &str) -> Result<()> {
    crate::ensure_unchanged(
        super::netfilter::fingerprint()? == expected,
        "firewall changed before bootstrap rollback",
    )?;
    let table = Table::new(ProtocolFamily::Inet).with_name(TABLE);
    let mut batch = Batch::new();
    batch.add(&table, MsgType::Del);
    batch.send()?;
    crate::ensure_unchanged(
        super::netfilter::fingerprint()? == super::netfilter::empty_fingerprint(),
        "firewall bootstrap rollback did not remove owned table",
    )
}

pub fn apply(value: &Value) -> Result<()> {
    let plans = crate::firewall_plan::compile(value)?;
    let table = Table::new(ProtocolFamily::Inet)
        .with_name(TABLE)
        .with_userdata(b"netcontrol-native-v1".to_vec());
    let mut batch = Batch::new();
    // CREATE is nonexclusive, so add+delete also handles the initially absent table.
    // All deletion, chains and ordered rules form one kernel transaction.
    batch.add(&table, MsgType::Add);
    batch.add(&table, MsgType::Del);
    batch.add(&table, MsgType::Add);
    let forward = Chain::new(&table)
        .with_name("forward")
        .with_type(ChainType::Filter)
        .with_hook(Hook::new(HookClass::Forward, 0))
        .with_policy(if value["policy"] == "drop" {
            ChainPolicy::Drop
        } else {
            ChainPolicy::Accept
        })
        .add_to_batch(&mut batch);
    if value["allow_all_icmp"] == true {
        icmp(&forward)?.add_to_batch(&mut batch);
        for (name, hook) in [("input", HookClass::In), ("output", HookClass::Out)] {
            let chain = Chain::new(&table)
                .with_name(name)
                .with_type(ChainType::Filter)
                .with_hook(Hook::new(hook, 0))
                .with_policy(ChainPolicy::Accept)
                .add_to_batch(&mut batch);
            icmp(&chain)?.add_to_batch(&mut batch);
        }
    }
    for plan in &plans {
        matching(&forward, plan)?.add_to_batch(&mut batch);
    }
    if let Some(nat) = value["nat"]["masquerade"]
        .as_array()
        .filter(|v| !v.is_empty())
    {
        let post = Chain::new(&table)
            .with_name("postrouting")
            .with_type(ChainType::Nat)
            .with_hook(Hook::new(HookClass::PostRouting, 100))
            .with_policy(ChainPolicy::Accept)
            .add_to_batch(&mut batch);
        for item in nat {
            let family = if item["family"] == "ipv4" {
                libc::NFPROTO_IPV4
            } else {
                libc::NFPROTO_IPV6
            };
            let mut rule = Rule::new(&post)?
                .with_expr(Meta::new(MetaType::NfProto))
                .with_expr(Cmp::new(CmpOp::Eq, [family as u8]));
            if let Some(source) = item["source"].as_str().filter(|v| !v.is_empty()) {
                rule = rule.snetwork(source.parse()?)?;
            }
            rule.oiface(item["out_interface"].as_str().unwrap_or(""))?
                .with_expr(Masquerade {})
                .add_to_batch(&mut batch);
        }
    }
    batch.send()?;
    Ok(())
}
