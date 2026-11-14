use anyhow::{Result, ensure};

pub(super) fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
    let length = 4 + value.len();
    let mut bytes = Vec::with_capacity((length + 3) & !3);
    bytes.extend((length as u16).to_ne_bytes());
    bytes.extend(kind.to_ne_bytes());
    bytes.extend(value);
    bytes.resize((length + 3) & !3, 0);
    bytes
}

pub(super) fn number(kind: u16, value: u32) -> Vec<u8> {
    attribute(kind, &value.to_be_bytes())
}

pub(super) fn expression(name: &str, data: Vec<u8>) -> Vec<u8> {
    attribute(
        0x8001,
        &[
            attribute(1, format!("{name}\0").as_bytes()),
            attribute(0x8002, &data),
        ]
        .concat(),
    )
}

pub(super) fn payload(attrs: Vec<u8>) -> Vec<u8> {
    [[libc::NFPROTO_INET as u8, 0, 0, 0].to_vec(), attrs].concat()
}

pub(super) fn message(kind: u16, flags: u16, sequence: u32, attrs: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend((20 + attrs.len() as u32).to_ne_bytes());
    bytes.extend(((10u16 << 8) | kind).to_ne_bytes());
    bytes.extend(flags.to_ne_bytes());
    bytes.extend(sequence.to_ne_bytes());
    bytes.extend(0u32.to_ne_bytes());
    bytes.extend(payload(attrs.to_vec()));
    bytes
}

pub(super) fn send(items: &[(u16, u16, Vec<u8>)]) -> Result<()> {
    ensure!(
        !items.is_empty() && items.len() <= 4096,
        "invalid bounded nftables batch"
    );
    let frame = |kind: u16, sequence: u32| {
        [
            20u32.to_ne_bytes().to_vec(),
            kind.to_ne_bytes().to_vec(),
            1u16.to_ne_bytes().to_vec(),
            sequence.to_ne_bytes().to_vec(),
            0u32.to_ne_bytes().to_vec(),
            vec![libc::AF_UNSPEC as u8, 0, 0, 10],
        ]
        .concat()
    };
    let mut bytes = frame(0x10, 0);
    for (index, (kind, flags, attrs)) in items.iter().enumerate() {
        bytes.extend(message(*kind, *flags, index as u32 + 1, attrs));
    }
    bytes.extend(frame(0x11, items.len() as u32 + 1));
    ensure!(
        bytes.len() <= 1024 * 1024,
        "experience nftables batch exceeds 1 MiB"
    );
    super::netfilter::send_batch(&bytes, items.len() as u32)
}

pub(super) fn resequence(bytes: &mut [u8]) -> Result<u32> {
    let mut frames = bytes;
    let mut sequence = 0u32;
    while !frames.is_empty() {
        ensure!(frames.len() >= 20, "short combined nftables frame");
        let length = u32::from_ne_bytes(frames[..4].try_into()?) as usize;
        let aligned = (length + 3) & !3;
        ensure!(
            length >= 20 && aligned <= frames.len(),
            "invalid combined nftables frame length"
        );
        frames[8..12].copy_from_slice(&sequence.to_ne_bytes());
        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("nftables sequence exhausted"))?;
        frames = &mut frames[aligned..];
    }
    sequence
        .checked_sub(2)
        .ok_or_else(|| anyhow::anyhow!("incomplete combined nftables batch"))
}
