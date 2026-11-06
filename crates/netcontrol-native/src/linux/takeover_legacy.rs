use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Table {
    pub family: u8,
    pub name: String,
    info: Vec<u8>,
    entries: Vec<u8>,
}

fn socket(family: u8) -> Result<(OwnedFd, i32)> {
    ensure!(
        std::mem::size_of::<usize>() == 8,
        "legacy firewall takeover requires a 64-bit Linux ABI"
    );
    let (domain, level) = if family == 4 {
        (libc::AF_INET, libc::IPPROTO_IP)
    } else {
        (libc::AF_INET6, libc::IPPROTO_IPV6)
    };
    let fd = unsafe {
        libc::socket(
            domain,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::IPPROTO_RAW,
        )
    };
    ensure!(
        fd >= 0,
        "open legacy firewall control socket: {}",
        std::io::Error::last_os_error()
    );
    Ok((unsafe { OwnedFd::from_raw_fd(fd) }, level))
}

fn get(fd: &OwnedFd, level: i32, option: i32, buffer: &mut [u8]) -> Result<()> {
    let mut length = libc::socklen_t::try_from(buffer.len())?;
    ensure!(
        unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                level,
                option,
                buffer.as_mut_ptr().cast(),
                &mut length,
            )
        } == 0,
        "read legacy firewall: {}",
        std::io::Error::last_os_error()
    );
    ensure!(
        length as usize == buffer.len(),
        "legacy firewall response length changed"
    );
    Ok(())
}
fn integer(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_ne_bytes(
        bytes
            .get(offset..offset + 4)
            .context("truncated legacy table")?
            .try_into()?,
    ))
}

fn read(family: u8, name: &str) -> Result<Table> {
    ensure!(
        !name.is_empty() && name.len() < 32 && !name.contains('\0'),
        "invalid legacy table name"
    );
    let (fd, level) = socket(family)?;
    let mut info = vec![0; 84];
    info[..name.len()].copy_from_slice(name.as_bytes());
    get(&fd, level, 64, &mut info)?;
    let size = usize::try_from(integer(&info, 80)?)?;
    ensure!(
        size <= 128 * 1024 * 1024,
        "legacy firewall capture exceeds 128 MiB"
    );
    let mut entries = vec![0; 40 + size];
    entries[..name.len()].copy_from_slice(name.as_bytes());
    entries[32..36].copy_from_slice(&(size as u32).to_ne_bytes());
    get(&fd, level, 65, &mut entries)?;
    Ok(Table {
        family,
        name: name.into(),
        info,
        entries,
    })
}

pub(super) fn capture() -> Result<Vec<Table>> {
    let mut tables = Vec::new();
    for (family, path) in [
        (4, "/proc/thread-self/net/ip_tables_names"),
        (6, "/proc/thread-self/net/ip6_tables_names"),
    ] {
        let names = match fs::read_to_string(path) {
            Ok(names) => names,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).with_context(|| format!("inventory {path}")),
        };
        for name in names.lines().filter(|name| !name.is_empty()) {
            tables.push(read(family, name)?);
        }
    }
    Ok(tables)
}

fn replacement(table: &Table, counters: *mut [u64; 2]) -> Result<Vec<u8>> {
    let hooks = integer(&table.info, 32)?;
    ensure!(hooks & !31 == 0, "unsupported legacy firewall hook");
    let (entry_size, target_offset, next_offset) = if table.family == 4 {
        (112usize, 88usize, 90usize)
    } else {
        (168, 140, 142)
    };
    let standard_size = entry_size + 40;
    let error_size = entry_size + 64;
    let size = hooks.count_ones() as usize * standard_size + error_size;
    let mut buffer = vec![0; 96 + size];
    buffer[..table.name.len()].copy_from_slice(table.name.as_bytes());
    buffer[32..36].copy_from_slice(&hooks.to_ne_bytes());
    buffer[36..40].copy_from_slice(&(hooks.count_ones() + 1).to_ne_bytes());
    buffer[40..44].copy_from_slice(&(size as u32).to_ne_bytes());
    buffer[84..88].copy_from_slice(&integer(&table.info, 76)?.to_ne_bytes());
    buffer[88..96].copy_from_slice(&(counters as usize as u64).to_ne_bytes());
    let mut offset = 0;
    for hook in 0..5 {
        if hooks & (1 << hook) == 0 {
            continue;
        }
        buffer[44 + hook * 4..48 + hook * 4].copy_from_slice(&(offset as u32).to_ne_bytes());
        buffer[64 + hook * 4..68 + hook * 4].copy_from_slice(&(offset as u32).to_ne_bytes());
        let entry = &mut buffer[96 + offset..96 + offset + standard_size];
        entry[target_offset..target_offset + 2].copy_from_slice(&(entry_size as u16).to_ne_bytes());
        entry[next_offset..next_offset + 2].copy_from_slice(&(standard_size as u16).to_ne_bytes());
        entry[entry_size..entry_size + 2].copy_from_slice(&40u16.to_ne_bytes());
        entry[entry_size + 32..entry_size + 36].copy_from_slice(&(-2i32).to_ne_bytes());
        offset += standard_size;
    }
    let entry = &mut buffer[96 + offset..];
    entry[target_offset..target_offset + 2].copy_from_slice(&(entry_size as u16).to_ne_bytes());
    entry[next_offset..next_offset + 2].copy_from_slice(&(error_size as u16).to_ne_bytes());
    entry[entry_size..entry_size + 2].copy_from_slice(&64u16.to_ne_bytes());
    entry[entry_size + 2..entry_size + 8].copy_from_slice(b"ERROR\0");
    entry[entry_size + 32..entry_size + 38].copy_from_slice(b"ERROR\0");
    Ok(buffer)
}

pub(super) fn clear() -> Result<()> {
    for table in capture()? {
        let count = integer(&table.info, 76)? as usize;
        ensure!(
            count <= 8 * 1024 * 1024,
            "legacy firewall counter count exceeds capture bound"
        );
        let mut counters = vec![[0u64; 2]; count];
        let buffer = replacement(&table, counters.as_mut_ptr())?;
        let (fd, level) = socket(table.family)?;
        ensure!(
            unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    level,
                    64,
                    buffer.as_ptr().cast(),
                    libc::socklen_t::try_from(buffer.len())?,
                )
            } == 0,
            "disable legacy firewall {}: {}",
            table.name,
            std::io::Error::last_os_error()
        );
        let observed = read(table.family, &table.name)?;
        let hooks = integer(&observed.info, 32)?;
        ensure!(
            integer(&observed.info, 76)? == hooks.count_ones() + 1,
            "legacy rules remain after takeover"
        );
        let entry_size = if table.family == 4 { 112 } else { 168 };
        for hook in 0..5 {
            if hooks & (1 << hook) == 0 {
                continue;
            }
            let offset = integer(&observed.info, 36 + hook * 4)? as usize;
            ensure!(
                integer(&observed.info, 56 + hook * 4)? as usize == offset,
                "legacy chain contains non-policy rules"
            );
            let verdict = observed
                .entries
                .get(40 + offset + entry_size + 32..40 + offset + entry_size + 36)
                .context("legacy policy target missing")?;
            ensure!(
                i32::from_ne_bytes(verdict.try_into()?) == -2,
                "legacy policy did not become ACCEPT"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires NETCONTROL_INTEGRATION=1, isolated namespaces and legacy ip_tables filter support"]
    fn legacy_takeover_clears_drop_policies() -> Result<()> {
        if !crate::linux::host_integration::isolate_host_fixture(
            "linux::takeover_legacy::tests::legacy_takeover_clears_drop_policies",
        )? {
            return Ok(());
        }
        let table = read(4, "filter")?;
        let mut counters = vec![[0u64; 2]; integer(&table.info, 76)? as usize];
        let mut buffer = replacement(&table, counters.as_mut_ptr())?;
        for hook in 0..5 {
            if integer(&table.info, 32)? & (1 << hook) == 0 {
                continue;
            }
            let offset = integer(&buffer, 44 + hook * 4)? as usize;
            buffer[96 + offset + 112 + 32..96 + offset + 112 + 36]
                .copy_from_slice(&(-1i32).to_ne_bytes());
        }
        let (fd, level) = socket(4)?;
        ensure!(
            unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    level,
                    64,
                    buffer.as_ptr().cast(),
                    buffer.len().try_into()?,
                )
            } == 0,
            "install legacy fixture: {}",
            std::io::Error::last_os_error()
        );
        assert!(capture()?.iter().any(|table| table.name == "filter"));
        clear()?;
        clear()?;
        let table = read(4, "filter")?;
        let offset = integer(&table.info, 36 + 4)? as usize;
        assert_eq!(
            i32::from_ne_bytes(
                table.entries[40 + offset + 112 + 32..40 + offset + 112 + 36].try_into()?
            ),
            -2
        );
        Ok(())
    }

    #[test]
    fn legacy_replacement_has_only_accept_policies_and_an_error_sentinel() {
        for family in [4, 6] {
            let mut table = Table {
                family,
                name: "filter".into(),
                info: vec![0; 84],
                entries: vec![],
            };
            table.info[32..36].copy_from_slice(&14u32.to_ne_bytes());
            table.info[76..80].copy_from_slice(&99u32.to_ne_bytes());
            let data = replacement(&table, std::ptr::null_mut()).unwrap();
            let entry_size = if family == 4 { 112 } else { 168 };
            assert_eq!(integer(&data, 36).unwrap(), 4);
            assert_eq!(integer(&data, 84).unwrap(), 99);
            for hook in 1..=3 {
                let offset = integer(&data, 44 + hook * 4).unwrap() as usize;
                assert_eq!(integer(&data, 64 + hook * 4).unwrap() as usize, offset);
                assert_eq!(
                    i32::from_ne_bytes(
                        data[96 + offset + entry_size + 32..96 + offset + entry_size + 36]
                            .try_into()
                            .unwrap()
                    ),
                    -2
                );
            }
            assert_eq!(data.len(), 96 + 3 * (entry_size + 40) + entry_size + 64);
        }
    }
}
