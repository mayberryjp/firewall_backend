use anyhow::{Result, ensure};
use netcontrol_core::DestinationRewriteRule;
use rustables::{Batch, sys::*};
use std::net::IpAddr;

fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
    let length = 4 + value.len();
    let mut output = Vec::with_capacity((length + 3) & !3);
    output.extend((length as u16).to_ne_bytes());
    output.extend(kind.to_ne_bytes());
    output.extend(value);
    output.resize((length + 3) & !3, 0);
    output
}

fn number(kind: u16, value: u32) -> Vec<u8> {
    attribute(kind, &value.to_be_bytes())
}

fn expression(name: &str, data: Vec<u8>) -> Vec<u8> {
    let mut value = attribute(NFTA_EXPR_NAME, format!("{name}\0").as_bytes());
    value.extend(attribute(NFTA_EXPR_DATA | 0x8000, &data));
    attribute(NFTA_LIST_ELEM | 0x8000, &value)
}

fn compare(value: &[u8]) -> Vec<u8> {
    expression(
        "cmp",
        [
            number(NFTA_CMP_SREG, NFT_REG_1),
            number(NFTA_CMP_OP, NFT_CMP_EQ),
            attribute(NFTA_CMP_DATA | 0x8000, &attribute(NFTA_DATA_VALUE, value)),
        ]
        .concat(),
    )
}

fn rule(
    item: &DestinationRewriteRule,
    sequence: u32,
    generation: &str,
    index: usize,
) -> Result<Vec<u8>> {
    let target: IpAddr = item.target_address.parse()?;
    let (family, address) = match target {
        IpAddr::V4(ip) => (libc::NFPROTO_IPV4 as u32, ip.octets().to_vec()),
        IpAddr::V6(ip) => (libc::NFPROTO_IPV6 as u32, ip.octets().to_vec()),
    };
    let mut interface = [0; libc::IFNAMSIZ];
    ensure!(
        item.out_interface.len() < interface.len(),
        "invalid rewrite WAN name"
    );
    interface[..item.out_interface.len()].copy_from_slice(item.out_interface.as_bytes());
    let meta = |key| {
        expression(
            "meta",
            [
                number(NFTA_META_DREG, NFT_REG_1),
                number(NFTA_META_KEY, key),
            ]
            .concat(),
        )
    };
    // rustables 0.9 has no FIB expression. Encode this rule using the Linux UAPI
    // and append it inside the same atomic batch as the typed chains/filter rules.
    let expressions = [
        meta(NFT_META_NFPROTO),
        compare(&[family as u8]),
        meta(NFT_META_L4PROTO),
        compare(&[if item.protocol == "tcp" {
            libc::IPPROTO_TCP as u8
        } else {
            libc::IPPROTO_UDP as u8
        }]),
        expression(
            "payload",
            [
                number(NFTA_PAYLOAD_DREG, NFT_REG_1),
                number(NFTA_PAYLOAD_BASE, NFT_PAYLOAD_TRANSPORT_HEADER),
                number(NFTA_PAYLOAD_OFFSET, 2),
                number(NFTA_PAYLOAD_LEN, 2),
            ]
            .concat(),
        ),
        compare(&item.destination_port.to_be_bytes()),
        expression(
            "fib",
            [
                number(NFTA_FIB_DREG, NFT_REG_1),
                number(NFTA_FIB_RESULT, NFT_FIB_RESULT_OIFNAME),
                number(NFTA_FIB_FLAGS, NFTA_FIB_F_DADDR | NFTA_FIB_F_MARK),
            ]
            .concat(),
        ),
        compare(&interface),
        expression(
            "counter",
            [
                attribute(NFTA_COUNTER_BYTES, &0u64.to_be_bytes()),
                attribute(NFTA_COUNTER_PACKETS, &0u64.to_be_bytes()),
            ]
            .concat(),
        ),
        expression(
            "immediate",
            [
                number(NFTA_IMMEDIATE_DREG, NFT_REG_1),
                attribute(
                    NFTA_IMMEDIATE_DATA | 0x8000,
                    &attribute(NFTA_DATA_VALUE, &address),
                ),
            ]
            .concat(),
        ),
        expression(
            "nat",
            [
                number(NFTA_NAT_TYPE, NFT_NAT_DNAT),
                number(NFTA_NAT_FAMILY, family),
                number(NFTA_NAT_REG_ADDR_MIN, NFT_REG_1),
            ]
            .concat(),
        ),
    ]
    .concat();
    let attrs = [
        attribute(NFTA_RULE_TABLE, b"netcontrol\0"),
        attribute(NFTA_RULE_CHAIN, b"destination_rewrite\0"),
        attribute(NFTA_RULE_EXPRESSIONS | 0x8000, &expressions),
        attribute(
            NFTA_RULE_USERDATA,
            &crate::firewall_counters::userdata(
                generation,
                &format!("/firewall/nat/destination_rewrite/{index}"),
            )?,
        ),
    ]
    .concat();
    let mut message = Vec::new();
    message.extend((20u32 + attrs.len() as u32).to_ne_bytes());
    message.extend((((NFNL_SUBSYS_NFTABLES as u16) << 8) | NFT_MSG_NEWRULE as u16).to_ne_bytes());
    message
        .extend(((NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND) as u16).to_ne_bytes());
    message.extend(sequence.to_ne_bytes());
    message.extend(0u32.to_ne_bytes());
    message.extend([libc::NFPROTO_INET as u8, 0, 0, 0]);
    message.extend(attrs);
    Ok(message)
}

pub fn send(batch: Batch, rules: &[DestinationRewriteRule], generation: &str) -> Result<()> {
    let mut bytes = batch.finalize();
    ensure!(bytes.len() >= 40, "short nftables batch");
    let mut end = bytes.split_off(bytes.len() - 20);
    let mut sequence = u32::from_ne_bytes(end[8..12].try_into()?);
    for (index, item) in rules.iter().enumerate() {
        bytes.extend(rule(item, sequence, generation, index)?);
        sequence += 1;
    }
    end[8..12].copy_from_slice(&sequence.to_ne_bytes());
    bytes.extend(end);
    super::netfilter::send_batch(&bytes, sequence - 1)
}
