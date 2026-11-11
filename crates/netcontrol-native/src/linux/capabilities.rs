use super::networking;
use anyhow::{Context, Result, anyhow, ensure};
use netcontrol_core::{
    CapabilitySupport, InterfaceCapabilities, InterfaceChannels, InterfaceDriver,
    InterfaceHardware, InterfaceInterrupt, InterfaceInterruptCount, InterfaceInventory,
    InterfaceLink, InterfaceLinkMode, InterfaceQueue, InterfaceRss, InventorySource,
    InventoryStatus, PERFORMANCE_CAPABILITIES, PerformanceCapability,
};
use netlink_packet_route::link::{LinkAttribute, LinkMessage};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::Path,
    time::{Duration, Instant},
};

pub(super) async fn discover(
    handle: &rtnetlink::Handle,
    host_mode: bool,
) -> Result<InterfaceInventory> {
    let started = Instant::now();
    let socket = socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;
    let mut errors = vec![];
    let kernel_release = observed(
        read_text(Path::new("/proc/sys/kernel/osrelease")),
        &mut errors,
    );
    let boot_id = observed(
        read_text(Path::new("/proc/sys/kernel/random/boot_id")),
        &mut errors,
    );
    let xdp_family = netdev_family().map_err(|error| format!("{error:#}"));
    let interrupts = if host_mode {
        Some(
            crate::performance::read_hardware_interrupts(Path::new("/proc/interrupts"))
                .map_err(|error| format!("{error:#}")),
        )
    } else {
        None
    };
    let mut interfaces = vec![];
    let links = networking::links(handle).await?;
    for link in &links {
        ensure!(
            interfaces.len() < 8192 && started.elapsed() < Duration::from_secs(30),
            "interface capability scan exceeded interface/time limit"
        );
        let parent = networking::parent(link);
        let mut row = InterfaceCapabilities {
            name: parent.name.clone(),
            kind: parent.kind.clone(),
            index: Some(parent.index),
            mac: (!parent.mac.is_empty()).then_some(parent.mac),
            capabilities: PERFORMANCE_CAPABILITIES
                .iter()
                .map(|name| {
                    PerformanceCapability::unknown(
                        name,
                        "not inspected by this read-only discovery",
                    )
                })
                .collect(),
            ..Default::default()
        };
        row.driver = observed(driver(&socket, &row.name), &mut row.errors);
        row.link = observed(link_settings(&socket, &row.name), &mut row.errors);
        row.channels = observed(channels(&socket, &row.name), &mut row.errors);
        discover_rss(&mut row, |bytes| ethtool(&socket, &parent.name, bytes));
        match offloads(&socket, &row.name) {
            Ok(features) => row.capabilities.extend(features),
            Err(e) => row.errors.push(format!("ethtool offloads: {e:#}")),
        }
        match xdp_family
            .as_ref()
            .map_err(|reason| anyhow!("{reason}"))
            .and_then(|family| xdp_features(*family, parent.index))
        {
            Ok(flags) => {
                for (name, bit) in [
                    ("xdp_native", 1),
                    ("xdp_redirect", 2),
                    ("af_xdp_zero_copy", 8),
                    ("xdp_hardware", 16),
                    ("xdp_rx_scatter_gather", 32),
                ] {
                    set_capability(
                        &mut row,
                        name,
                        flags & bit != 0,
                        None,
                        format!("netdev XDP feature flags: 0x{flags:x}"),
                    );
                }
            }
            Err(e) => {
                let reason = format!("netdev XDP features: {e:#}");
                row.errors.push(reason.clone());
                for name in [
                    "xdp_native",
                    "xdp_redirect",
                    "af_xdp_zero_copy",
                    "xdp_hardware",
                    "xdp_rx_scatter_gather",
                ] {
                    capability(&mut row, name).reason = Some(reason.clone());
                }
            }
        }
        capability(&mut row, "dpdk").reason = Some(
            "requires installed DPDK PMD/device matching and driver-specific prerequisites; no device rebinding performed".into(),
        );
        capability(&mut row, "accelerated_rfs").reason = Some(
            "requires driver-specific accelerated flow-steering evidence; ntuple/RSS alone is insufficient".into(),
        );
        if host_mode {
            match sysfs(&mut row, Path::new("/sys/class/net")) {
                Ok(()) => {
                    if row.hardware.is_some() {
                        if let Err(error) = discover_interrupts(
                            &mut row,
                            Path::new("/sys/class/net"),
                            Path::new("/proc"),
                            interrupts
                                .as_ref()
                                .context("missing host interrupt observation")?,
                        ) {
                            row.errors.push(format!("interrupt discovery: {error:#}"));
                            for queue in &mut row.queues {
                                queue.irq_mapping_reason =
                                    Some(format!("interrupt discovery: {error:#}"));
                            }
                        }
                    } else {
                        for queue in &mut row.queues {
                            queue.irq_mapping_reason =
                                Some("no observed hardware device IRQs; software queue".into());
                        }
                    }
                }
                Err(e) => row.errors.push(format!("sysfs: {e:#}")),
            }
        } else {
            row.errors.push(
                "sysfs identity/queue evidence omitted: mounted sysfs is not guaranteed to match the lab network namespace".into(),
            );
        }
        interfaces.push(row);
    }
    inherit_vlan_rps(&mut interfaces, &links);
    let current: BTreeMap<_, _> = networking::links(handle)
        .await?
        .into_iter()
        .map(|link| (link.header.index, link))
        .collect();
    for link in &links {
        let before = networking::parent(link);
        let after_link = current
            .get(&before.index)
            .with_context(|| format!("interface {} disappeared during discovery", before.name))?;
        let after = networking::parent(after_link);
        ensure!(
            before.name == after.name
                && before.mac == after.mac
                && before.kind == after.kind
                && (before.kind != "vlan" || vlan_lower_link(link) == vlan_lower_link(after_link)),
            "interface {} changed identity or VLAN parent during discovery; retry refresh",
            before.name
        );
    }
    ensure!(
        started.elapsed() < Duration::from_secs(30),
        "interface capability scan exceeded time limit"
    );
    Ok(InterfaceInventory {
        source: InventorySource::Native,
        status: if errors.is_empty() && interfaces.iter().all(|row| row.errors.is_empty()) {
            InventoryStatus::Observed
        } else {
            InventoryStatus::Partial
        },
        kernel_release,
        boot_id,
        errors,
        interfaces,
    })
}

fn vlan_lower_link(link: &LinkMessage) -> (Option<u32>, bool) {
    let lower = link
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            LinkAttribute::Link(index) => Some(*index),
            _ => None,
        });
    let foreign = link
        .attributes
        .iter()
        .any(|attribute| matches!(attribute, LinkAttribute::LinkNetNsId(_)));
    (lower, foreign)
}

fn inherit_vlan_rps(rows: &mut [InterfaceCapabilities], links: &[LinkMessage]) {
    let by_index: BTreeMap<_, _> = rows
        .iter()
        .filter_map(|row| row.index.map(|index| (index, row)))
        .collect();
    let ancestry: BTreeMap<_, _> = links
        .iter()
        .map(|link| (link.header.index, vlan_lower_link(link)))
        .collect();
    let updates: Vec<_> = rows
        .iter()
        .enumerate()
        .filter(|(_, row)| row.kind == "vlan")
        .map(|(position, row)| {
            let inherited = (|| -> Result<PerformanceCapability> {
                let mut index = row.index.context("VLAN kernel index unavailable")?;
                let mut visited = BTreeSet::new();
                loop {
                    ensure!(visited.insert(index), "cyclic VLAN ancestry");
                    ensure!(visited.len() <= 32, "VLAN ancestry exceeds 32 links");
                    let parent = by_index.get(&index).context("VLAN parent is missing")?;
                    if parent.kind != "vlan" {
                        ensure!(
                            parent.hardware.is_some(),
                            "VLAN parent {} is not an observed physical device; receive path is ambiguous",
                            parent.name
                        );
                        let mut rps = parent
                            .capabilities
                            .iter()
                            .find(|cap| cap.name == "rps")
                            .context("VLAN parent RPS evidence unavailable")?
                            .clone();
                        let rx: Vec<_> = parent
                            .queues
                            .iter()
                            .filter(|queue| queue.name.starts_with("rx-"))
                            .collect();
                        if rps.enabled == Some(false)
                            && (rx.is_empty() || rx.iter().any(|queue| queue.rps_cpus.is_none()))
                        {
                            rps.enabled = None;
                            rps.reason = Some(
                                "parent RX queue masks are incomplete; disabled RPS cannot be established".into(),
                            );
                        }
                        rps.inherited_from = Some(parent.name.clone());
                        rps.evidence.insert(0, format!(
                            "normal VLAN receive path uses physical parent {} RPS; VLAN queue masks are diagnostic only",
                            parent.name
                        ));
                        return Ok(rps);
                    }
                    let (lower, foreign) = ancestry
                        .get(&index)
                        .context("VLAN parent topology unavailable")?;
                    ensure!(
                        !*foreign,
                        "VLAN parent is outside the observed network namespace"
                    );
                    index = (*lower).context("VLAN lower-link index unavailable")?;
                }
            })();
            (position, inherited)
        })
        .collect();
    for (position, inherited) in updates {
        let row = &mut rows[position];
        match inherited {
            Ok(rps) => *capability(row, "rps") = rps,
            Err(error) => {
                let reason = format!("VLAN RPS inheritance: {error:#}");
                *capability(row, "rps") = PerformanceCapability::unknown("rps", &reason);
                row.errors.push(reason);
            }
        }
    }
}

fn observed<T>(value: Result<T>, errors: &mut Vec<String>) -> Option<T> {
    match value {
        Ok(value) => Some(value),
        Err(e) => {
            errors.push(format!("{e:#}"));
            None
        }
    }
}

fn capability<'a>(row: &'a mut InterfaceCapabilities, name: &str) -> &'a mut PerformanceCapability {
    row.capabilities
        .iter_mut()
        .find(|c| c.name == name)
        .expect("built-in capability must exist")
}

fn set_capability(
    row: &mut InterfaceCapabilities,
    name: &str,
    supported: bool,
    enabled: Option<bool>,
    evidence: String,
) {
    let cap = capability(row, name);
    cap.support = if supported {
        CapabilitySupport::Supported
    } else {
        CapabilitySupport::Unsupported
    };
    cap.enabled = enabled;
    cap.evidence = vec![evidence];
    cap.reason = None;
}

fn source_error(row: &mut InterfaceCapabilities, name: &str, error: anyhow::Error) {
    let reason = format!("{name}: {error:#}");
    capability(row, name).reason = Some(reason.clone());
    row.errors.push(reason);
}

fn socket(domain: i32, kind: i32, protocol: i32) -> Result<OwnedFd> {
    let fd = unsafe { libc::socket(domain, kind | libc::SOCK_CLOEXEC, protocol) };
    ensure!(
        fd >= 0,
        "open discovery socket: {}",
        std::io::Error::last_os_error()
    );
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn ethtool(socket: &OwnedFd, name: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        !name.is_empty() && name.len() < libc::IFNAMSIZ && !name.contains('\0'),
        "invalid kernel interface name"
    );
    ensure!(
        bytes.len() >= 4 && bytes.len() <= 256 * 1024,
        "invalid ethtool buffer size"
    );
    // u64 storage satisfies alignment for all ethtool UAPI structures.
    let mut aligned = vec![0u64; bytes.len().div_ceil(8)];
    let data = unsafe {
        std::slice::from_raw_parts_mut(aligned.as_mut_ptr().cast::<u8>(), aligned.len() * 8)
    };
    data[..bytes.len()].copy_from_slice(bytes);
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (target, byte) in request.ifr_name.iter_mut().zip(name.bytes()) {
        *target = byte as libc::c_char;
    }
    request.ifr_ifru.ifru_data = data.as_mut_ptr().cast();
    if unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCETHTOOL as _, &mut request) } < 0 {
        return Err(std::io::Error::last_os_error())
            .context(format!("ethtool command 0x{:x} on {name}", word(bytes, 0)?));
    }
    Ok(data[..bytes.len()].to_vec())
}

fn word(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_ne_bytes(
        bytes
            .get(offset..offset + 4)
            .context("short kernel u32")?
            .try_into()?,
    ))
}

fn text(bytes: &[u8]) -> Result<Option<String>> {
    let end = bytes
        .iter()
        .position(|b| *b == 0)
        .context("unterminated kernel string")?;
    let text = std::str::from_utf8(&bytes[..end])?;
    ensure!(
        !text.chars().any(char::is_control),
        "control character in kernel string"
    );
    Ok((!text.is_empty()).then(|| text.into()))
}

fn request(command: u32, size: usize) -> Vec<u8> {
    let mut bytes = vec![0; size];
    bytes[..4].copy_from_slice(&command.to_ne_bytes());
    bytes
}

fn driver(fd: &OwnedFd, name: &str) -> Result<InterfaceDriver> {
    let bytes = ethtool(fd, name, &request(0x3, 196))?;
    Ok(InterfaceDriver {
        name: text(&bytes[4..36])?.context("driver name is empty")?,
        version: text(&bytes[36..68])?,
        firmware_version: text(&bytes[68..100])?,
        bus_address: text(&bytes[100..132])?,
        expansion_rom_version: text(&bytes[132..164])?,
    })
}

fn link_settings(fd: &OwnedFd, name: &str) -> Result<InterfaceLink> {
    let mut bytes = ethtool(fd, name, &request(0x4c, 48))?;
    let words = -(bytes[15] as i8 as i16);
    ensure!(
        words > 0 && words <= 127,
        "invalid ethtool link-mode handshake"
    );
    let words = words as usize;
    bytes = request(0x4c, 48 + 12 * words);
    bytes[15] = words as u8;
    let bytes = ethtool(fd, name, &bytes)?;
    ensure!(bytes[15] as usize == words, "link-mode bitmap size changed");
    let carrier = ethtool(fd, name, &request(0xa, 8))?;
    decode_link(&bytes, word(&carrier, 4)? != 0)
}

fn decode_link(bytes: &[u8], carrier: bool) -> Result<InterfaceLink> {
    ensure!(bytes.len() >= 48, "short link settings");
    let words = bytes[15] as usize;
    ensure!(
        words > 0 && words <= 127 && bytes.len() == 48 + 12 * words,
        "invalid link-mode bitmap size"
    );
    let speed = word(bytes, 4)?;
    Ok(InterfaceLink {
        carrier: Some(carrier),
        speed_mbps: (carrier && speed != 0 && speed != u32::MAX).then_some(speed),
        duplex: if carrier { duplex(bytes[8]) } else { None },
        autonegotiation: match bytes[11] {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        },
        supported_modes: modes(&bytes[48..48 + 4 * words])?,
        advertised_modes: modes(&bytes[48 + 4 * words..48 + 8 * words])?,
        partner_advertised_modes: modes(&bytes[48 + 8 * words..])?,
    })
}

fn duplex(value: u8) -> Option<String> {
    match value {
        0 => Some("half".into()),
        1 => Some("full".into()),
        _ => None,
    }
}

const LINK_MODES: &[&str] = &[
    "10baseT_Half",
    "10baseT_Full",
    "100baseT_Half",
    "100baseT_Full",
    "1000baseT_Half",
    "1000baseT_Full",
    "Autoneg",
    "TP",
    "AUI",
    "MII",
    "FIBRE",
    "BNC",
    "10000baseT_Full",
    "Pause",
    "Asym_Pause",
    "2500baseX_Full",
    "Backplane",
    "1000baseKX_Full",
    "10000baseKX4_Full",
    "10000baseKR_Full",
    "10000baseR_FEC",
    "20000baseMLD2_Full",
    "20000baseKR2_Full",
    "40000baseKR4_Full",
    "40000baseCR4_Full",
    "40000baseSR4_Full",
    "40000baseLR4_Full",
    "56000baseKR4_Full",
    "56000baseCR4_Full",
    "56000baseSR4_Full",
    "56000baseLR4_Full",
    "25000baseCR_Full",
    "25000baseKR_Full",
    "25000baseSR_Full",
    "50000baseCR2_Full",
    "50000baseKR2_Full",
    "100000baseKR4_Full",
    "100000baseSR4_Full",
    "100000baseCR4_Full",
    "100000baseLR4_ER4_Full",
    "50000baseSR2_Full",
    "1000baseX_Full",
    "10000baseCR_Full",
    "10000baseSR_Full",
    "10000baseLR_Full",
    "10000baseLRM_Full",
    "10000baseER_Full",
    "2500baseT_Full",
    "5000baseT_Full",
    "FEC_NONE",
    "FEC_RS",
    "FEC_BASER",
    "50000baseKR_Full",
    "50000baseSR_Full",
    "50000baseCR_Full",
    "50000baseLR_ER_FR_Full",
    "50000baseDR_Full",
    "100000baseKR2_Full",
    "100000baseSR2_Full",
    "100000baseCR2_Full",
    "100000baseLR2_ER2_FR2_Full",
    "100000baseDR2_Full",
    "200000baseKR4_Full",
    "200000baseSR4_Full",
    "200000baseLR4_ER4_FR4_Full",
    "200000baseDR4_Full",
    "200000baseCR4_Full",
    "100baseT1_Full",
    "1000baseT1_Full",
    "400000baseKR8_Full",
    "400000baseSR8_Full",
    "400000baseLR8_ER8_FR8_Full",
    "400000baseDR8_Full",
    "400000baseCR8_Full",
    "FEC_LLRS",
    "100000baseKR_Full",
    "100000baseSR_Full",
    "100000baseLR_ER_FR_Full",
    "100000baseCR_Full",
    "100000baseDR_Full",
    "200000baseKR2_Full",
    "200000baseSR2_Full",
    "200000baseLR2_ER2_FR2_Full",
    "200000baseDR2_Full",
    "200000baseCR2_Full",
    "400000baseKR4_Full",
    "400000baseSR4_Full",
    "400000baseLR4_ER4_FR4_Full",
    "400000baseDR4_Full",
    "400000baseCR4_Full",
    "100baseFX_Half",
    "100baseFX_Full",
    "10baseT1L_Full",
    "800000baseCR8_Full",
    "800000baseKR8_Full",
    "800000baseDR8_Full",
    "800000baseDR8_2_Full",
    "800000baseSR8_Full",
    "800000baseVR8_Full",
    "10baseT1S_Full",
    "10baseT1S_Half",
    "10baseT1S_P2MP_Half",
    "10baseT1BRR_Full",
];

fn modes(bytes: &[u8]) -> Result<Vec<InterfaceLinkMode>> {
    ensure!(bytes.len() % 4 == 0, "unaligned link-mode bitmap");
    let mut modes = vec![];
    for bit in 0..bytes.len() * 8 {
        if word(bytes, bit / 32 * 4)? & (1 << (bit % 32)) == 0 {
            continue;
        }
        let name = LINK_MODES.get(bit).copied();
        let duplex = name.and_then(|n| {
            if n.ends_with("_Full") {
                Some("full".into())
            } else if n.ends_with("_Half") {
                Some("half".into())
            } else {
                None
            }
        });
        let speed_mbps = name
            .filter(|_| duplex.is_some())
            .and_then(|n| n.split("base").next())
            .and_then(|speed| speed.parse().ok());
        modes.push(InterfaceLinkMode {
            bit: bit as u32,
            name: name.map(String::from),
            speed_mbps,
            duplex,
        });
    }
    Ok(modes)
}

fn channels(fd: &OwnedFd, name: &str) -> Result<InterfaceChannels> {
    let bytes = ethtool(fd, name, &request(0x3c, 36))?;
    Ok(InterfaceChannels {
        max_rx: word(&bytes, 4)?,
        max_tx: word(&bytes, 8)?,
        max_other: word(&bytes, 12)?,
        max_combined: word(&bytes, 16)?,
        rx: word(&bytes, 20)?,
        tx: word(&bytes, 24)?,
        other: word(&bytes, 28)?,
        combined: word(&bytes, 32)?,
    })
}

fn discover_rss(row: &mut InterfaceCapabilities, mut query: impl FnMut(&[u8]) -> Result<Vec<u8>>) {
    // The size-only query establishes support even if detailed driver reads fail.
    let size = match query(&request(0x38, 8)).and_then(|bytes| word(&bytes, 4)) {
        Ok(size) => size,
        Err(error) => {
            source_error(row, "rss", error);
            return;
        }
    };
    set_capability(
        row,
        "rss",
        size > 0,
        None,
        format!("ethtool RSS indirection table size: {size}"),
    );
    if size == 0 {
        return;
    }
    row.rss = Some(InterfaceRss {
        context: 0,
        indirection_table: None,
        hash_function: None,
        input_transformation: None,
    });
    let details = (|| -> Result<InterfaceRss> {
        let sizes = query(&request(0x46, 24))?; // ETHTOOL_GRSSH, default RSS context.
        let (entries, key_size) = rss_sizes(&sizes)?;
        let mut bytes = request(0x46, 24 + entries * 4 + key_size);
        bytes[8..12].copy_from_slice(&(entries as u32).to_ne_bytes());
        bytes[12..16].copy_from_slice(&(key_size as u32).to_ne_bytes());
        let response = query(&bytes)?;
        ensure!(
            rss_sizes(&response)? == (entries, key_size),
            "RSS sizes changed during discovery; retry refresh"
        );
        decode_rss(&response)
    })();
    match details {
        Ok(rss) => {
            let targets: BTreeSet<_> = rss
                .indirection_table
                .as_ref()
                .unwrap()
                .iter()
                .copied()
                .collect();
            let enabled = if targets.len() <= 1 {
                Some(false)
            } else if rss.hash_function.is_some_and(|function| function & 7 != 0) {
                Some(true)
            } else {
                None
            };
            let cap = capability(row, "rss");
            cap.enabled = enabled;
            cap.evidence.push(format!(
                "default RSS context targets RX queues {targets:?}; hash function bits: {}",
                rss.hash_function.unwrap()
            ));
            if enabled.is_none() {
                let reason =
                    "RSS table targets multiple queues but active hashing is not identified"
                        .to_string();
                cap.reason = Some(reason.clone());
                row.errors.push(reason);
            }
            row.rss = Some(rss);
        }
        Err(error) => source_error(row, "rss", error),
    }
}

fn rss_sizes(bytes: &[u8]) -> Result<(usize, usize)> {
    ensure!(
        bytes.len() >= 24 && word(bytes, 4)? == 0,
        "invalid default RSS context header"
    );
    let entries = word(bytes, 8)? as usize;
    let key_size = word(bytes, 12)? as usize;
    ensure!(
        entries > 0
            && entries <= 65536
            && key_size <= 4096
            && 24 + entries * 4 + key_size <= 256 * 1024,
        "RSS table/key exceeds discovery bounds"
    );
    Ok((entries, key_size))
}

fn decode_rss(bytes: &[u8]) -> Result<InterfaceRss> {
    let (entries, key_size) = rss_sizes(bytes)?;
    ensure!(
        bytes.len() == 24 + 4 * entries + key_size,
        "short or oversized RSS response"
    );
    let table: Vec<_> = (0..entries)
        .map(|index| word(bytes, 24 + 4 * index))
        .collect::<Result<_>>()?;
    ensure!(
        table.iter().all(|queue| *queue <= 4095),
        "RSS target exceeds RX queue index limit"
    );
    Ok(InterfaceRss {
        context: 0,
        indirection_table: Some(table),
        hash_function: Some(bytes[16]),
        input_transformation: Some(bytes[17]),
    })
}

fn offloads(fd: &OwnedFd, name: &str) -> Result<Vec<PerformanceCapability>> {
    let mut info = request(0x37, 24);
    info[8..16].copy_from_slice(&(1u64 << 4).to_ne_bytes()); // ETH_SS_FEATURES.
    let info = ethtool(fd, name, &info)?;
    ensure!(
        u64::from_ne_bytes(info[8..16].try_into()?) & (1 << 4) != 0,
        "driver did not expose feature names"
    );
    let count = word(&info, 16)? as usize;
    ensure!(count <= 4096, "too many ethtool features");
    let mut strings = request(0x1b, 12 + count * 32);
    strings[4..8].copy_from_slice(&4u32.to_ne_bytes());
    strings[8..12].copy_from_slice(&(count as u32).to_ne_bytes());
    let strings = ethtool(fd, name, &strings)?;
    ensure!(
        word(&strings, 8)? as usize == count,
        "feature-name count changed"
    );
    let blocks = count.div_ceil(32);
    let mut features = request(0x3a, 8 + blocks * 16);
    features[4..8].copy_from_slice(&(blocks as u32).to_ne_bytes());
    let features = ethtool(fd, name, &features)?;
    ensure!(
        word(&features, 4)? as usize == blocks,
        "feature count changed"
    );
    decode_offloads(count, &strings, &features)
}

fn decode_offloads(
    count: usize,
    strings: &[u8],
    features: &[u8],
) -> Result<Vec<PerformanceCapability>> {
    ensure!(
        count <= 4096
            && strings.len() == 12 + count * 32
            && features.len() == 8 + count.div_ceil(32) * 16,
        "invalid ethtool feature buffers"
    );
    let mut result = vec![];
    for bit in 0..count {
        let Some(name) = text(&strings[12 + bit * 32..12 + (bit + 1) * 32])? else {
            continue;
        };
        let offset = 8 + bit / 32 * 16;
        let mask = 1u32 << (bit % 32);
        let available = word(features, offset)? & mask != 0;
        let active = word(features, offset + 8)? & mask != 0;
        result.push(PerformanceCapability {
            name: format!("ethtool:{name}"),
            support: if available || active {
                CapabilitySupport::Supported
            } else {
                CapabilitySupport::Unknown
            },
            enabled: Some(active),
            inherited_from: None,
            evidence: vec![format!(
                "ethtool feature bit {bit}; changeable={available}; active={active}"
            )],
            reason: (!(available || active)).then(|| {
                "disabled nonchangeable feature; kernel flags do not prove hardware support".into()
            }),
        });
    }
    Ok(result)
}

fn read_text(path: &Path) -> Result<String> {
    let mut bytes = vec![];
    File::open(path)
        .with_context(|| format!("read {}", path.display()))?
        .take(4097)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 4096,
        "oversized sysfs/procfs value: {}",
        path.display()
    );
    let value = std::str::from_utf8(&bytes)?.trim();
    ensure!(
        !value.chars().any(char::is_control),
        "invalid sysfs/procfs text: {}",
        path.display()
    );
    Ok(value.into())
}

fn optional_text(path: &Path) -> Result<Option<String>> {
    match read_text(path) {
        Ok(value) => Ok(Some(value)),
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

fn cpu_mask(value: &str) -> Result<bool> {
    ensure!(
        !value.is_empty()
            && value.split(',').all(|part| !part.is_empty()
                && part.len() <= 8
                && part.bytes().all(|b| b.is_ascii_hexdigit())),
        "invalid CPU/queue mask"
    );
    Ok(value.bytes().any(|b| b != b'0' && b != b','))
}

fn sysfs(row: &mut InterfaceCapabilities, root: &Path) -> Result<()> {
    ensure!(
        row.name != "." && row.name != ".." && !row.name.contains('/'),
        "invalid sysfs interface name"
    );
    let base = root.join(&row.name);
    let index: u32 = read_text(&base.join("ifindex"))?.parse()?;
    ensure!(
        Some(index) == row.index,
        "sysfs interface index does not match namespace"
    );
    match fs::read_link(base.join("device")) {
        Ok(device) => {
            let bus = fs::read_link(base.join("device/subsystem"))?;
            let mut hardware = InterfaceHardware {
                bus: bus.file_name().and_then(|v| v.to_str()).map(String::from),
                address: device
                    .file_name()
                    .and_then(|v| v.to_str())
                    .map(String::from),
                ..Default::default()
            };
            if hardware.bus.as_deref() == Some("pci") {
                for (field, target) in [
                    ("vendor", &mut hardware.vendor_id),
                    ("device", &mut hardware.device_id),
                    ("subsystem_vendor", &mut hardware.subsystem_vendor_id),
                    ("subsystem_device", &mut hardware.subsystem_device_id),
                    ("revision", &mut hardware.revision),
                ] {
                    let value = observed(
                        read_text(&base.join("device").join(field)).and_then(|v| {
                            ensure!(
                                v.starts_with("0x") && u32::from_str_radix(&v[2..], 16).is_ok(),
                                "invalid PCI {field}"
                            );
                            Ok(v)
                        }),
                        &mut row.errors,
                    );
                    *target = value;
                }
            }
            hardware.numa_node = observed(
                optional_text(&base.join("device/numa_node")).and_then(|v| {
                    v.map(|v| v.parse::<i32>().map_err(anyhow::Error::from))
                        .transpose()
                }),
                &mut row.errors,
            )
            .flatten()
            .filter(|v| *v >= 0);
            row.hardware = Some(hardware);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let mut queues = vec![];
    for entry in fs::read_dir(base.join("queues"))? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow!("non-UTF8 queue name"))?;
        if !(name.starts_with("rx-") || name.starts_with("tx-")) {
            continue;
        }
        ensure!(queues.len() < 8192, "too many interface queues");
        let path = entry.path();
        let mask = |key: &str| -> Result<Option<String>> {
            let value = optional_text(&path.join(key))?;
            if let Some(value) = &value {
                cpu_mask(value)?;
            }
            Ok(value)
        };
        queues.push(InterfaceQueue {
            name,
            rps_cpus: mask("rps_cpus")?,
            xps_cpus: mask("xps_cpus")?,
            xps_rxqs: mask("xps_rxqs")?,
            rps_flow_count: optional_text(&path.join("rps_flow_cnt"))?
                .map(|v| v.parse::<u32>())
                .transpose()?,
            ..Default::default()
        });
    }

    finish_queue_observation(row, queues)?;
    ensure!(
        read_text(&base.join("ifindex"))?.parse::<u32>()? == index,
        "sysfs interface changed during discovery"
    );
    Ok(())
}

fn discover_interrupts(
    row: &mut InterfaceCapabilities,
    sys: &Path,
    proc: &Path,
    observation: &std::result::Result<Vec<crate::performance::HardwareInterrupt>, String>,
) -> Result<()> {
    let device = sys.join(&row.name).join("device");
    let mut irqs = BTreeSet::new();
    match fs::read_dir(device.join("msi_irqs")) {
        Ok(entries) => {
            for entry in entries {
                ensure!(irqs.len() < 4096, "too many device IRQs");
                let entry = entry?;
                let irq = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| anyhow!("non-UTF8 IRQ name"))?
                    .parse::<u32>()?;
                ensure!(irqs.insert(irq), "duplicate device IRQ");
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(irq) = optional_text(&device.join("irq"))? {
                let irq: u32 = irq.parse()?;
                if irq > 0 {
                    irqs.insert(irq);
                }
            }
        }
        Err(error) => return Err(error.into()),
    }
    ensure!(!irqs.is_empty(), "device IRQ inventory unavailable");
    let mut observations = vec![];
    for irq in irqs {
        let mut errors = vec![];
        let interrupt = match observation {
            Ok(rows) => {
                let found = rows.iter().find(|row| row.irq == irq);
                if found.is_none() {
                    errors.push(format!("IRQ {irq} absent from interrupt snapshot"));
                }
                found
            }
            Err(error) => {
                errors.push(format!("interrupt counters unavailable: {error}"));
                None
            }
        };
        let effective_cpus = observed(
            read_text(
                &proc
                    .join("irq")
                    .join(irq.to_string())
                    .join("effective_affinity_list"),
            )
            .and_then(|value| netcontrol_core::parse_cpu_list(&value))
            .map(|cpus| cpus.into_iter().collect()),
            &mut errors,
        );
        row.errors
            .extend(errors.iter().map(|error| format!("IRQ {irq}: {error}")));
        observations.push(InterfaceInterrupt {
            irq,
            description: interrupt.map(|row| row.description.clone()),
            effective_cpus,
            counts: interrupt.map(|row| {
                row.counts
                    .iter()
                    .map(|(cpu_id, count)| InterfaceInterruptCount {
                        cpu_id: *cpu_id,
                        interrupts: count.to_string(),
                    })
                    .collect()
            }),
            errors,
        });
    }
    row.interrupts = Some(observations);
    map_queue_irqs(row);
    Ok(())
}

fn map_queue_irqs(row: &mut InterfaceCapabilities) {
    for queue in &mut row.queues {
        let Some((direction, index)) = queue.name.split_once('-') else {
            continue;
        };
        let names = [
            format!("{}-{direction}-{index}", row.name),
            format!(
                "{}-{}-{index}",
                row.name,
                if direction == "rx" { "Rx" } else { "Tx" }
            ),
            format!("{}-TxRx-{index}", row.name),
        ];
        let matches: Vec<_> = row
            .interrupts
            .iter()
            .flatten()
            .filter(|interrupt| {
                interrupt.description.as_ref().is_some_and(|description| {
                    // Only exact, unshared driver action names establish queue identity.
                    !description.contains(',')
                        && description
                            .split_whitespace()
                            .last()
                            .is_some_and(|action| names.iter().any(|name| name == action))
                })
            })
            .map(|interrupt| interrupt.irq)
            .collect();
        if matches.len() == 1 {
            queue.irqs = Some(matches);
            queue.irq_mapping_reason = None;
        } else {
            let reason = format!(
                "queue {} IRQ mapping unavailable or ambiguous; driver action must uniquely identify the queue",
                queue.name
            );
            queue.irqs = None;
            queue.irq_mapping_reason = Some(reason.clone());
            row.errors.push(reason);
        }
    }
}
fn finish_queue_observation(
    row: &mut InterfaceCapabilities,
    mut queues: Vec<InterfaceQueue>,
) -> Result<()> {
    queues.sort_by(|a, b| a.name.cmp(&b.name));
    for (name, field, rx) in [
        ("rps", "rps_cpus", true),
        ("xps", "xps_cpus", false),
        ("xps_rxqs", "xps_rxqs", false),
    ] {
        let selected: Vec<_> = queues
            .iter()
            .filter(|q| q.name.starts_with(if rx { "rx-" } else { "tx-" }))
            .collect();
        if selected.is_empty() {
            let cap = capability(row, name);
            cap.support = CapabilitySupport::NotApplicable;
            cap.reason = Some("interface has no corresponding queues".into());
            continue;
        }
        let values: Vec<_> = selected
            .iter()
            .filter_map(|q| match field {
                "rps_cpus" => q.rps_cpus.as_deref(),
                "xps_cpus" => q.xps_cpus.as_deref(),
                _ => q.xps_rxqs.as_deref(),
            })
            .collect();
        let enabled = values
            .iter()
            .try_fold(false, |enabled, v| cpu_mask(v).map(|set| enabled || set))?;
        set_capability(
            row,
            name,
            !values.is_empty(),
            Some(enabled),
            format!(
                "sysfs {field}: {} of {} queues expose masks",
                values.len(),
                selected.len()
            ),
        );
    }
    let flow_sizes: Vec<_> = queues.iter().filter_map(|q| q.rps_flow_count).collect();
    if !flow_sizes.is_empty() {
        match read_text(Path::new("/proc/sys/net/core/rps_sock_flow_entries"))
            .and_then(|v| v.parse::<u32>().map_err(anyhow::Error::from))
        {
            Ok(global) => set_capability(
                row,
                "rfs",
                true,
                Some(global > 0 && flow_sizes.iter().any(|size| *size > 0)),
                format!("rps_sock_flow_entries={global}; per-queue rps_flow_cnt={flow_sizes:?}"),
            ),
            Err(e) => source_error(row, "rfs", e),
        }
    } else {
        set_capability(
            row,
            "rfs",
            false,
            Some(false),
            "no queue exposes rps_flow_cnt".into(),
        );
    }
    row.queues = queues;
    Ok(())
}

fn attribute(kind: u16, payload: &[u8]) -> Vec<u8> {
    let length = 4 + payload.len();
    let mut bytes = Vec::with_capacity((length + 3) & !3);
    bytes.extend((length as u16).to_ne_bytes());
    bytes.extend(kind.to_ne_bytes());
    bytes.extend(payload);
    bytes.resize((length + 3) & !3, 0);
    bytes
}

fn generic(family: u16, command: u8, attrs: &[u8]) -> Result<Vec<(u16, Vec<u8>)>> {
    let fd = socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_GENERIC)?;
    let timeout = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    ensure!(
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&timeout as *const libc::timeval).cast(),
                std::mem::size_of_val(&timeout) as libc::socklen_t,
            )
        } == 0,
        "set discovery timeout: {}",
        std::io::Error::last_os_error()
    );
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as u16;
    let mut bytes = vec![];
    bytes.extend((20u32 + attrs.len() as u32).to_ne_bytes());
    bytes.extend(family.to_ne_bytes());
    bytes.extend(1u16.to_ne_bytes());
    bytes.extend(1u32.to_ne_bytes());
    bytes.extend(0u32.to_ne_bytes());
    bytes.extend([command, 1, 0, 0]);
    bytes.extend(attrs);
    let sent = unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            bytes.as_ptr().cast(),
            bytes.len(),
            0,
            (&address as *const libc::sockaddr_nl).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    ensure!(
        sent == bytes.len() as isize,
        "send netdev query: {}",
        std::io::Error::last_os_error()
    );
    let mut reply = vec![0u8; 65536];
    let received = unsafe {
        libc::recv(
            fd.as_raw_fd(),
            reply.as_mut_ptr().cast(),
            reply.len(),
            libc::MSG_TRUNC,
        )
    };
    if received < 0 {
        return Err(std::io::Error::last_os_error()).context("receive netdev query");
    }
    ensure!(received as usize <= reply.len(), "oversized netdev reply");
    reply.truncate(received as usize);
    decode_generic(&reply, family)
}

fn decode_generic(bytes: &[u8], family: u16) -> Result<Vec<(u16, Vec<u8>)>> {
    ensure!(bytes.len() >= 16, "short netdev message");
    let length = word(bytes, 0)? as usize;
    ensure!(
        length >= 16 && length <= bytes.len() && word(bytes, 8)? == 1,
        "invalid netdev message"
    );
    let kind = u16::from_ne_bytes(bytes[4..6].try_into()?);
    if kind == libc::NLMSG_ERROR as u16 {
        let error = word(&bytes[..length], 16)? as i32;
        ensure!(error < 0 && error != i32::MIN, "invalid netdev error");
        return Err(std::io::Error::from_raw_os_error(-error)).context("netdev query");
    }
    ensure!(kind == family && length >= 20, "unexpected netdev response");
    crate::netlink_decode::attributes(&bytes[20..length])
}

fn netdev_family() -> Result<u16> {
    let control = generic(0x10, 3, &attribute(2, b"netdev\0"))?;
    let family = control
        .iter()
        .find(|(kind, _)| *kind == 1)
        .context("missing netdev family ID")?;
    ensure!(family.1.len() == 2, "invalid netdev family ID");
    Ok(u16::from_ne_bytes(family.1.as_slice().try_into()?))
}

fn xdp_features(family: u16, index: u32) -> Result<u64> {
    let attrs = generic(family, 1, &attribute(1, &index.to_ne_bytes()))?;
    let returned_index = attrs
        .iter()
        .find(|(kind, _)| *kind == 1)
        .context("missing netdev interface index")?;
    ensure!(
        word(&returned_index.1, 0)? == index,
        "netdev interface index mismatch"
    );
    let flags = attrs
        .iter()
        .find(|(kind, _)| *kind == 3)
        .context("driver/kernel did not advertise XDP features")?;
    ensure!(flags.1.len() == 8, "invalid XDP feature flags");
    Ok(u64::from_ne_bytes(flags.1.as_slice().try_into()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rss_reply(table: &[u32], function: u8) -> Vec<u8> {
        let mut bytes = request(0x46, 24 + table.len() * 4);
        bytes[8..12].copy_from_slice(&(table.len() as u32).to_ne_bytes());
        bytes[16] = function;
        bytes[17] = 2;
        for (index, queue) in table.iter().enumerate() {
            bytes[24 + index * 4..28 + index * 4].copy_from_slice(&queue.to_ne_bytes());
        }
        bytes
    }

    #[test]
    fn capabilities_rss_observes_table_hashing_and_unknown_without_queue_count_inference() {
        for (table, function, enabled) in [
            (vec![0, 1, 2, 3], 1, Some(true)),
            (vec![0, 0, 0, 0], 1, Some(false)),
            (vec![0, 1], 0, None),
            (vec![0, 1], 8, None),
            (vec![0, 1], 2, Some(true)),
            (vec![0, 1], 4, Some(true)),
        ] {
            let reply = rss_reply(&table, function);
            let mut row = InterfaceCapabilities {
                capabilities: vec![PerformanceCapability::unknown("rss", "not inspected")],
                ..Default::default()
            };
            let mut calls = 0;
            discover_rss(&mut row, |bytes| {
                calls += 1;
                match word(bytes, 0)? {
                    0x38 => {
                        let mut bytes = request(0x38, 8);
                        bytes[4..8].copy_from_slice(&(table.len() as u32).to_ne_bytes());
                        Ok(bytes)
                    }
                    0x46 if bytes.len() == 24 => Ok(reply[..24].to_vec()),
                    0x46 => {
                        assert_eq!(word(bytes, 8)?, table.len() as u32);
                        Ok(reply.clone())
                    }
                    _ => anyhow::bail!("unexpected query"),
                }
            });
            assert_eq!(calls, 3);
            assert_eq!(
                capability(&mut row, "rss").support,
                CapabilitySupport::Supported
            );
            assert_eq!(capability(&mut row, "rss").enabled, enabled);
            let rss = row.rss.unwrap();
            assert_eq!(rss.input_transformation, Some(2));
            assert_eq!(rss.indirection_table.unwrap(), table);
            assert_eq!(row.errors.is_empty(), enabled.is_some());
        }
    }

    #[test]
    fn capabilities_rss_detail_failures_preserve_support_and_explicit_unknown() {
        let mut row = InterfaceCapabilities {
            capabilities: vec![PerformanceCapability::unknown("rss", "not inspected")],
            ..Default::default()
        };
        discover_rss(&mut row, |bytes| {
            if word(bytes, 0)? == 0x38 {
                Ok(vec![0x38, 0, 0, 0, 128, 0, 0, 0])
            } else {
                anyhow::bail!("driver cannot read RSS hash settings")
            }
        });
        let cap = capability(&mut row, "rss");
        assert_eq!(cap.support, CapabilitySupport::Supported);
        assert_eq!(cap.enabled, None);
        assert!(cap.reason.as_ref().unwrap().contains("cannot read"));
        assert!(row.rss.unwrap().indirection_table.is_none());
        assert_eq!(row.errors.len(), 1);
        let mut row = InterfaceCapabilities {
            capabilities: vec![PerformanceCapability::unknown("rss", "not inspected")],
            ..Default::default()
        };
        discover_rss(&mut row, |_| anyhow::bail!("permission denied"));
        assert_eq!(
            capability(&mut row, "rss").support,
            CapabilitySupport::Unknown
        );
        assert!(row.rss.is_none());
        let mut row = InterfaceCapabilities {
            capabilities: vec![PerformanceCapability::unknown("rss", "not inspected")],
            ..Default::default()
        };
        discover_rss(&mut row, |_| Ok(request(0x38, 8)));
        assert_eq!(
            capability(&mut row, "rss").support,
            CapabilitySupport::Unsupported
        );
        assert!(row.rss.is_none());
    }

    #[test]
    fn capabilities_rss_bounds_truncation_and_size_races() {
        let valid = rss_reply(&[0, 1], 1);
        assert!(decode_rss(&valid[..valid.len() - 1]).is_err());
        assert!(decode_rss(&rss_reply(&[4096], 1)).is_err());
        for (offset, value) in [(8, 0u32), (8, 65537), (12, 4097), (4, 1)] {
            let mut invalid = valid.clone();
            invalid[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
            assert!(rss_sizes(&invalid).is_err());
        }
        let mut row = InterfaceCapabilities {
            capabilities: vec![PerformanceCapability::unknown("rss", "not inspected")],
            ..Default::default()
        };
        let mut calls = 0;
        discover_rss(&mut row, |_| {
            calls += 1;
            Ok(match calls {
                1 => vec![0x38, 0, 0, 0, 2, 0, 0, 0],
                2 => valid[..24].to_vec(),
                _ => rss_reply(&[0, 1, 2], 1),
            })
        });
        assert_eq!(capability(&mut row, "rss").enabled, None);
        assert!(row.errors[0].contains("sizes changed"));
    }

    #[test]
    fn capabilities_irq_mapping_requires_exact_unambiguous_driver_actions() {
        let mut row = InterfaceCapabilities {
            name: "enp1s0".into(),
            queues: (0..4)
                .map(|index| InterfaceQueue {
                    name: format!("rx-{index}"),
                    ..Default::default()
                })
                .collect(),
            interrupts: Some(
                (0..4)
                    .map(|index| InterfaceInterrupt {
                        irq: 135 + index,
                        description: Some(format!("PCI-MSIX enp1s0-TxRx-{index}")),
                        effective_cpus: Some(vec![(index + 1) % 4]),
                        counts: None,
                        errors: vec![],
                    })
                    .collect(),
            ),
            ..Default::default()
        };
        map_queue_irqs(&mut row);
        for (index, queue) in row.queues.iter().enumerate() {
            assert_eq!(queue.irqs, Some(vec![135 + index as u32]));
        }
        let interrupts = row.interrupts.as_mut().unwrap();
        interrupts[0].description = Some("PCI-MSI other-enp1s0-TxRx-0".into());
        interrupts[1].description = Some("PCI-MSI enp1s0-TxRx-1, shared".into());
        interrupts[2].description = None;
        let mut duplicate = interrupts[3].clone();
        duplicate.irq = 140;
        interrupts.push(duplicate);
        map_queue_irqs(&mut row);
        assert!(
            row.queues
                .iter()
                .all(|queue| queue.irqs.is_none() && queue.irq_mapping_reason.is_some())
        );
    }

    fn rps_row(name: &str, index: u32, kind: &str, enabled: Option<bool>) -> InterfaceCapabilities {
        let mut rps = PerformanceCapability::unknown("rps", "queue observation unavailable");
        if enabled.is_some() {
            rps.support = CapabilitySupport::Supported;
            rps.reason = None;
        }
        rps.enabled = enabled;
        InterfaceCapabilities {
            name: name.into(),
            index: Some(index),
            kind: kind.into(),
            hardware: (kind == "device").then(InterfaceHardware::default),
            queues: vec![InterfaceQueue {
                name: "rx-0".into(),
                rps_cpus: Some(if enabled == Some(true) { "2" } else { "0" }.into()),
                rps_flow_count: None,
                xps_cpus: None,
                xps_rxqs: None,
                ..Default::default()
            }],
            capabilities: vec![rps, PerformanceCapability::unknown("rss", "not inspected")],
            ..Default::default()
        }
    }

    fn vlan_link(index: u32, lower: u32) -> LinkMessage {
        let mut link = LinkMessage::default();
        link.header.index = index;
        link.attributes.push(LinkAttribute::Link(lower));
        link
    }

    #[test]
    fn capabilities_vlan_rps_inherits_parent_state_not_own_masks() {
        for enabled in [Some(true), Some(false), None] {
            let mut rows = vec![
                rps_row("vlan20", 4, "vlan", Some(true)),
                rps_row("vlan10", 3, "vlan", Some(false)),
                rps_row("eno1", 2, "device", enabled),
                rps_row("wg0", 5, "wireguard", Some(true)),
                rps_row("lo", 1, "loopback", Some(false)),
            ];
            inherit_vlan_rps(&mut rows, &[vlan_link(4, 3), vlan_link(3, 2)]);
            for row in &mut rows[..2] {
                let rps = capability(row, "rps");
                assert_eq!(rps.enabled, enabled);
                assert_eq!(rps.inherited_from.as_deref(), Some("eno1"));
                assert_eq!(rps.reason.is_some(), enabled.is_none());
                assert!(rps.evidence[0].contains("diagnostic only"));
                assert!(capability(row, "rss").inherited_from.is_none());
            }
            assert_eq!(rows[0].queues[0].rps_cpus.as_deref(), Some("2"));
            assert_eq!(rows[1].queues[0].rps_cpus.as_deref(), Some("0"));
            for row in &mut rows[2..] {
                assert!(capability(row, "rps").inherited_from.is_none());
            }
            assert_eq!(capability(&mut rows[3], "rps").enabled, Some(true));
        }
    }

    #[test]
    fn capabilities_vlan_rps_unresolved_ancestry_is_unknown_with_errors() {
        let mut foreign = vlan_link(3, 2);
        foreign.attributes.push(LinkAttribute::LinkNetNsId(0));
        for links in [
            vec![],
            vec![vlan_link(3, 99)],
            vec![vlan_link(3, 3)],
            vec![foreign],
        ] {
            let mut rows = vec![
                rps_row("vlan10", 3, "vlan", Some(true)),
                rps_row("eno1", 2, "device", Some(true)),
            ];
            inherit_vlan_rps(&mut rows, &links);
            let rps = capability(&mut rows[0], "rps");
            assert_eq!(rps.support, CapabilitySupport::Unknown);
            assert_eq!(rps.enabled, None);
            assert_eq!(rps.inherited_from, None);
            assert!(
                rps.reason
                    .as_deref()
                    .unwrap()
                    .contains("VLAN RPS inheritance")
            );
            assert_eq!(rows[0].errors.len(), 1);
        }
        for kind in ["bridge", "bond", "veth", "wireguard"] {
            let mut rows = vec![
                rps_row("vlan10", 3, "vlan", Some(true)),
                rps_row("lower0", 2, kind, Some(true)),
            ];
            inherit_vlan_rps(&mut rows, &[vlan_link(3, 2)]);
            assert_eq!(capability(&mut rows[0], "rps").enabled, None);
            assert!(rows[0].errors[0].contains("receive path is ambiguous"));
        }
    }

    #[test]
    fn capabilities_vlan_rps_missing_parent_masks_are_not_disabled() {
        for enabled in [Some(false), Some(true)] {
            let mut parent = rps_row("eno1", 2, "device", enabled);
            parent.queues.push(InterfaceQueue {
                name: "rx-1".into(),
                rps_cpus: None,
                rps_flow_count: None,
                xps_cpus: None,
                xps_rxqs: None,
                ..Default::default()
            });
            let mut rows = vec![rps_row("vlan10", 3, "vlan", Some(false)), parent];
            inherit_vlan_rps(&mut rows, &[vlan_link(3, 2)]);
            let rps = capability(&mut rows[0], "rps");
            assert_eq!(rps.enabled, enabled.filter(|enabled| *enabled));
            assert_eq!(rps.inherited_from.as_deref(), Some("eno1"));
            assert_eq!(rps.reason.is_some(), enabled == Some(false));
        }
    }

    #[test]
    fn capabilities_vlan_rps_ancestry_is_bounded_and_parent_changes_are_detectable() {
        let mut rows: Vec<_> = (1..=33)
            .map(|index| rps_row(&format!("vlan{index}"), index, "vlan", Some(false)))
            .collect();
        rows.push(rps_row("eno1", 34, "device", Some(true)));
        let links: Vec<_> = (1..=33).map(|index| vlan_link(index, index + 1)).collect();
        inherit_vlan_rps(&mut rows, &links);
        assert_eq!(capability(&mut rows[0], "rps").enabled, None);
        assert!(rows[0].errors[0].contains("exceeds 32 links"));
        assert_eq!(capability(&mut rows[2], "rps").enabled, Some(true));
        assert_ne!(
            vlan_lower_link(&vlan_link(3, 2)),
            vlan_lower_link(&vlan_link(3, 4))
        );
        let mut foreign = vlan_link(3, 2);
        foreign.attributes.push(LinkAttribute::LinkNetNsId(0));
        assert_ne!(vlan_lower_link(&vlan_link(3, 2)), vlan_lower_link(&foreign));
    }

    #[test]
    fn capabilities_link_modes_preserve_unknown_bits_and_down_state() {
        let mut bytes = request(0x4c, 48 + 48);
        bytes[15] = 4;
        bytes[4..8].copy_from_slice(&1000u32.to_ne_bytes());
        bytes[8] = 1;
        bytes[11] = 1;
        bytes[48..52].copy_from_slice(&((1u32 << 4) | (1 << 5) | (1 << 6)).to_ne_bytes());
        bytes[60..64].copy_from_slice(&(1u32 << 31).to_ne_bytes());
        let link = decode_link(&bytes, true).unwrap();
        assert_eq!(link.speed_mbps, Some(1000));
        assert_eq!(link.supported_modes[0].duplex.as_deref(), Some("half"));
        assert_eq!(link.supported_modes[1].duplex.as_deref(), Some("full"));
        assert_eq!(link.supported_modes[2].speed_mbps, None);
        assert_eq!(link.supported_modes[3].bit, 127);
        assert_eq!(link.supported_modes[3].name, None);
        assert!(decode_link(&bytes, false).unwrap().speed_mbps.is_none());
        bytes[4..8].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert!(decode_link(&bytes, true).unwrap().speed_mbps.is_none());
        assert!(decode_link(&bytes[..bytes.len() - 1], true).is_err());
    }

    #[test]
    fn capabilities_masks_and_netlink_reject_malformed_evidence() {
        assert!(!cpu_mask("00000000,00000000").unwrap());
        assert!(cpu_mask("00000001,00000000").unwrap());
        for value in ["", ",", "garbage", "123456789", "0,"] {
            assert!(cpu_mask(value).is_err());
        }
        assert!(decode_generic(&[0; 16], 42).is_err());
        assert!(text(b"no terminator").is_err());
        assert!(text(b"bad\n\0").is_err());
        assert_eq!(text(b"driver\0unused").unwrap().as_deref(), Some("driver"));
    }

    #[test]
    fn capabilities_offloads_distinguish_fixed_active_and_changeable() {
        let mut strings = request(0x1b, 12 + 3 * 32);
        for (bit, name) in ["fixed-active", "changeable-disabled", "unknown-disabled"]
            .iter()
            .enumerate()
        {
            let start = 12 + bit * 32;
            strings[start..start + name.len()].copy_from_slice(name.as_bytes());
        }
        let mut flags = request(0x3a, 24);
        flags[8..12].copy_from_slice(&2u32.to_ne_bytes());
        flags[16..20].copy_from_slice(&1u32.to_ne_bytes());
        let caps = decode_offloads(3, &strings, &flags).unwrap();
        assert_eq!(caps[0].support, CapabilitySupport::Supported);
        assert_eq!(caps[0].enabled, Some(true));
        assert_eq!(caps[1].support, CapabilitySupport::Supported);
        assert_eq!(caps[1].enabled, Some(false));
        assert_eq!(caps[2].support, CapabilitySupport::Unknown);
        assert!(caps[2].reason.is_some());
        assert!(decode_offloads(3, &strings[..strings.len() - 1], &flags).is_err());
    }

    #[test]
    fn capabilities_sysfs_identity_queues_and_masks() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "netcontrol-capabilities-{}-{stamp}",
            std::process::id()
        ));
        let base = root.join("net/test0");
        let device = root.join("devices/0000:01:00.0");
        fs::create_dir_all(base.join("queues/rx-0")).unwrap();
        fs::create_dir_all(base.join("queues/tx-0")).unwrap();
        fs::create_dir_all(&device).unwrap();
        std::os::unix::fs::symlink(&device, base.join("device")).unwrap();
        std::os::unix::fs::symlink(root.join("bus/pci"), device.join("subsystem")).unwrap();
        for (path, value) in [
            (base.join("ifindex"), "2"),
            (base.join("queues/rx-0/rps_cpus"), "00000002"),
            (base.join("queues/tx-0/xps_cpus"), "00000000"),
            (base.join("queues/tx-0/xps_rxqs"), "00000001"),
            (device.join("vendor"), "0x8086"),
            (device.join("device"), "0x1234"),
            (device.join("subsystem_vendor"), "0x8086"),
            (device.join("subsystem_device"), "0x0001"),
            (device.join("revision"), "0x01"),
            (device.join("numa_node"), "-1"),
        ] {
            fs::write(path, value).unwrap();
        }
        let mut row = InterfaceCapabilities {
            name: "test0".into(),
            index: Some(2),
            capabilities: PERFORMANCE_CAPABILITIES
                .iter()
                .map(|name| PerformanceCapability::unknown(name, "not inspected"))
                .collect(),
            ..Default::default()
        };
        sysfs(&mut row, &root.join("net")).unwrap();
        assert_eq!(
            row.hardware.as_ref().unwrap().vendor_id.as_deref(),
            Some("0x8086")
        );
        assert_eq!(row.hardware.as_ref().unwrap().numa_node, None);
        assert_eq!(row.queues.len(), 2);
        assert_eq!(
            capability(&mut row, "rps").support,
            CapabilitySupport::Supported
        );
        assert_eq!(capability(&mut row, "rps").enabled, Some(true));
        assert_eq!(capability(&mut row, "xps").enabled, Some(false));
        assert_eq!(capability(&mut row, "xps_rxqs").enabled, Some(true));
        fs::create_dir_all(device.join("msi_irqs")).unwrap();
        fs::write(device.join("msi_irqs/135"), "msix").unwrap();
        fs::write(device.join("msi_irqs/134"), "msix").unwrap();
        fs::create_dir_all(root.join("proc/irq/135")).unwrap();
        fs::write(root.join("proc/irq/135/effective_affinity_list"), "1,3").unwrap();
        let interrupts = crate::performance::hardware_interrupts(
            "CPU1 CPU3\n134: 1 0 PCI-MSI test0\n135: 18446744073709551615 7 PCI-MSI test0-TxRx-0\n",
        )
        .unwrap();
        discover_interrupts(
            &mut row,
            &root.join("net"),
            &root.join("proc"),
            &Ok(interrupts),
        )
        .unwrap();
        assert_eq!(row.queues[0].irqs, Some(vec![135]));
        assert_eq!(row.queues[1].irqs, Some(vec![135]));
        let irqs = row.interrupts.as_ref().unwrap();
        assert_eq!(irqs[1].effective_cpus, Some(vec![1, 3]));
        assert_eq!(
            irqs[1].counts.as_ref().unwrap()[0].interrupts,
            u64::MAX.to_string()
        );
        assert!(irqs[0].effective_cpus.is_none());
        assert!(!irqs[0].errors.is_empty());
        row.interrupts = None;
        discover_interrupts(
            &mut row,
            &root.join("net"),
            &root.join("proc"),
            &Err("unreadable procfs".into()),
        )
        .unwrap();
        assert!(
            row.interrupts
                .as_ref()
                .unwrap()
                .iter()
                .all(|irq| irq.counts.is_none())
        );
        assert!(row.queues.iter().all(|queue| queue.irqs.is_none()));
        assert_eq!(
            row.interrupts.as_ref().unwrap()[1].effective_cpus,
            Some(vec![1, 3])
        );
        fs::remove_file(device.join("msi_irqs/134")).unwrap();
        fs::remove_file(device.join("msi_irqs/135")).unwrap();
        fs::remove_dir(device.join("msi_irqs")).unwrap();
        fs::write(device.join("irq"), "135").unwrap();
        fs::write(root.join("proc/irq/135/effective_affinity_list"), "3-1").unwrap();
        let interrupts =
            crate::performance::hardware_interrupts("CPU1 CPU3\n135: 9 7 PCI-MSI test0-TxRx-0\n")
                .unwrap();
        discover_interrupts(
            &mut row,
            &root.join("net"),
            &root.join("proc"),
            &Ok(interrupts),
        )
        .unwrap();
        let irqs = row.interrupts.as_ref().unwrap();
        assert_eq!(irqs.len(), 1);
        assert!(irqs[0].effective_cpus.is_none());
        assert!(!irqs[0].errors.is_empty());
        assert!(irqs[0].counts.is_some());
        row.index = Some(3);
        assert!(sysfs(&mut row, &root.join("net")).is_err());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn capabilities_readonly_linux_inventory() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (connection, handle, _) = rtnetlink::new_connection().unwrap();
            let task = tokio::spawn(connection);
            let inventory = discover(&handle, true).await.unwrap();
            assert_eq!(inventory.source, InventorySource::Native);
            assert!(inventory.kernel_release.is_some());
            let loopback = inventory
                .interfaces
                .iter()
                .find(|row| row.kind == "loopback")
                .unwrap();
            assert!(loopback.index.is_some());
            assert!(loopback.driver.is_none());
            assert!(
                loopback
                    .capabilities
                    .iter()
                    .any(|c| c.name == "dpdk" && c.support == CapabilitySupport::Unknown)
            );
            task.abort();
        });
    }
}
