use anyhow::Result;
use rustables::{
    Batch, Chain, ChainPolicy, ChainType, Hook, HookClass, MsgType, Protocol, ProtocolFamily, Rule,
    Table,
    expr::{
        Bitwise, Cmp, CmpOp, ConnTrackState, Conntrack, ConntrackKey, Counter, Log, Masquerade,
        Meta, MetaType,
    },
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const TABLE: &str = "netcontrol";
pub fn validate(value: &Value) -> Result<()> {
    crate::firewall_plan::compile(value)?;
    crate::firewall_plan::compile_input(value)?;
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
                    && crate::firewall_plan::destination_rewrites(value)?.is_empty()
                    && value.get("policies").is_none_or(Value::is_null)
                    && value.get("input").is_none_or(Value::is_null),
                "nonempty firewall has no durable owned state",
            )?;
        }
        _ => anyhow::bail!("incomplete native firewall ownership journal"),
    }
    Ok(())
}

fn matching(
    chain: &Chain,
    plan: &crate::firewall_plan::Match,
    prefix: &str,
    generation: &str,
) -> Result<Rule> {
    let mut rule = Rule::new(chain)?.with_userdata(crate::firewall_counters::userdata(
        generation,
        &plan.counter_key,
    )?);
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
    if !plan.egress.is_empty() {
        rule = rule.oiface(&plan.egress)?;
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
    rule = rule.with_expr(Counter::default());
    Ok(if plan.action == "drop" {
        rule.with_expr(Log::new(Some(super::deny_log::GROUP), Some(prefix))?)
            .drop()
    } else {
        rule.accept()
    })
}
fn icmp(chain: &Chain, generation: &str) -> Result<Rule> {
    Ok(Rule::new(chain)?
        .with_userdata(crate::firewall_counters::userdata(
            generation,
            "/firewall/allow_all_icmp",
        )?)
        .with_expr(Meta::new(MetaType::NfProto))
        .with_expr(Cmp::new(CmpOp::Eq, [libc::NFPROTO_IPV4 as u8]))
        .icmp()
        .with_expr(Counter::default())
        .accept())
}

fn default_rule(
    chain: &Chain,
    key: &str,
    action: &str,
    prefix: &str,
    generation: &str,
) -> Result<Rule> {
    matching(
        chain,
        &crate::firewall_plan::Match {
            counter_key: key.into(),
            action: action.into(),
            ..Default::default()
        },
        prefix,
        generation,
    )
}

pub fn counters(value: &Value, recorded: &Option<Value>, fingerprint: &str) -> Result<Value> {
    verify(value, recorded, Some(fingerprint))?;
    let mut snapshot = crate::firewall_counters::snapshot(
        &super::netfilter::rules()?,
        &crate::firewall_plan::counter_layout(value)?,
    )?;
    crate::ensure_unchanged(
        super::netfilter::fingerprint()? == fingerprint,
        "firewall changed while reading rule counters",
    )?;
    snapshot["ruleset_id"] =
        serde_json::json!(hex::encode(Sha256::digest(serde_json::to_vec(value)?)));
    Ok(snapshot)
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
    let input_plans = crate::firewall_plan::compile_input(value)?;
    let ruleset = hex::encode(Sha256::digest(serde_json::to_vec(value)?));
    let generation = std::fs::read_to_string("/proc/sys/kernel/random/uuid")?;
    let generation = generation.trim();
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
        icmp(&forward, generation)?.add_to_batch(&mut batch);
        let output = Chain::new(&table)
            .with_name("output")
            .with_type(ChainType::Filter)
            .with_hook(Hook::new(HookClass::Out, 0))
            .with_policy(ChainPolicy::Accept)
            .add_to_batch(&mut batch);
        icmp(&output, generation)?.add_to_batch(&mut batch);
        default_rule(&output, "generated/output/policy", "accept", "", generation)?
            .add_to_batch(&mut batch);
    }
    if !input_plans.is_empty() || value["allow_all_icmp"] == true {
        let input = Chain::new(&table)
            .with_name("input")
            .with_type(ChainType::Filter)
            .with_hook(Hook::new(HookClass::In, 0))
            .with_policy(if value["input"]["policy"] == "drop" {
                ChainPolicy::Drop
            } else {
                ChainPolicy::Accept
            })
            .add_to_batch(&mut batch);
        if value["allow_all_icmp"] == true {
            icmp(&input, generation)?.add_to_batch(&mut batch);
        }
        for (index, plan) in input_plans.iter().enumerate() {
            matching(
                &input,
                plan,
                &format!("nc:input:rule:{index}:{ruleset}"),
                generation,
            )?
            .add_to_batch(&mut batch);
        }
        let configured = value.get("input").is_some_and(|input| !input.is_null());
        default_rule(
            &input,
            if configured {
                "/firewall/input/policy"
            } else {
                "generated/input/policy"
            },
            if value["input"]["policy"] == "drop" {
                "drop"
            } else {
                "accept"
            },
            &format!("nc:input:policy:0:{ruleset}"),
            generation,
        )?
        .add_to_batch(&mut batch);
    }
    for (index, plan) in plans.iter().enumerate() {
        matching(
            &forward,
            plan,
            &format!("nc:forward:rule:{index}:{ruleset}"),
            generation,
        )?
        .add_to_batch(&mut batch);
    }
    default_rule(
        &forward,
        "/firewall/policy",
        value["policy"].as_str().unwrap_or(""),
        &format!("nc:forward:policy:0:{ruleset}"),
        generation,
    )?
    .add_to_batch(&mut batch);
    let rewrites = crate::firewall_plan::destination_rewrites(value)?;
    if !rewrites.is_empty() {
        Chain::new(&table)
            .with_name("destination_rewrite")
            .with_type(ChainType::Nat)
            .with_hook(Hook::new(HookClass::PreRouting, -100))
            .with_policy(ChainPolicy::Accept)
            .add_to_batch(&mut batch);
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
        for (index, item) in nat.iter().enumerate() {
            let family = if item["family"] == "ipv4" {
                libc::NFPROTO_IPV4
            } else {
                libc::NFPROTO_IPV6
            };
            let mut rule = Rule::new(&post)?
                .with_userdata(crate::firewall_counters::userdata(
                    generation,
                    &format!("/firewall/nat/masquerade/{index}"),
                )?)
                .with_expr(Meta::new(MetaType::NfProto))
                .with_expr(Cmp::new(CmpOp::Eq, [family as u8]));
            if let Some(source) = item["source"].as_str().filter(|v| !v.is_empty()) {
                rule = rule.snetwork(source.parse()?)?;
            }
            rule.oiface(item["out_interface"].as_str().unwrap_or(""))?
                .with_expr(Counter::default())
                .with_expr(Masquerade {})
                .add_to_batch(&mut batch);
        }
    }
    if rewrites.is_empty() {
        batch.send()?;
    } else {
        super::destination_rewrite::send(batch, &rewrites, generation)?;
    }
    Ok(())
}
