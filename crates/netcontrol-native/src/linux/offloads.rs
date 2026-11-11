use crate::model::RpsIdentity;
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::OpenOptionsExt,
    },
};

const GSSET_INFO: u32 = 0x37;
const GSTRINGS: u32 = 0x1b;
const GFEATURES: u32 = 0x3a;
const SFEATURES: u32 = 0x3b;
const FEATURE_SET: u32 = 4;
const FEATURE_WISH: u32 = 2;
const MAX_FEATURES: usize = 4096;
type Values = BTreeMap<String, BTreeMap<String, bool>>;
type Identities = BTreeMap<String, RpsIdentity>;
type State = (Values, Values, Identities);

pub(super) struct Io;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Feature {
    bit: usize,
    available: bool,
    requested: bool,
    active: bool,
    never_changed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Snapshot {
    count: usize,
    features: BTreeMap<String, Feature>,
}

impl Snapshot {
    fn active(&self) -> BTreeMap<String, bool> {
        self.features
            .iter()
            .map(|(name, feature)| (name.clone(), feature.active))
            .collect()
    }

    fn requested(&self) -> BTreeMap<String, bool> {
        self.features
            .iter()
            .map(|(name, feature)| (name.clone(), feature.requested))
            .collect()
    }

    fn validate(&self, values: &BTreeMap<String, bool>, strict: bool) -> Result<()> {
        self.validate_field(values, strict, false)
    }

    fn validate_field(
        &self,
        values: &BTreeMap<String, bool>,
        strict: bool,
        requested: bool,
    ) -> Result<()> {
        for (name, value) in values {
            let feature = self.features.get(name).with_context(|| {
                format!("ethtool feature {name:?} does not exist on this interface")
            })?;
            ensure!(
                (!strict
                    && (if requested {
                        feature.requested
                    } else {
                        feature.active
                    }) == *value)
                    || (feature.available && !feature.never_changed),
                "ethtool feature {name:?} is immutable (available={}, never_changed={}, active={}, requested={})",
                feature.available,
                feature.never_changed,
                feature.active,
                feature.requested
            );
        }
        Ok(())
    }
}

// Keep policy and exact-state verification testable without simulating successful ioctls.
trait Driver {
    fn identity(&mut self, name: &str) -> Result<RpsIdentity>;
    fn snapshot(&mut self, name: &str) -> Result<Snapshot>;
    fn writable(&mut self) -> Result<()>;
    fn set(&mut self, name: &str, bytes: &[u8]) -> Result<u32>;
}

fn interface_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() < libc::IFNAMSIZ
            && name != "."
            && name != ".."
            && !name
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || b"/:\0".contains(&b)),
        "invalid offload interface name"
    );
    Ok(())
}

fn validate(values: &Values, expected: &Identities) -> Result<()> {
    ensure!(values.len() <= 128, "offload interface limit exceeded");
    for (name, features) in values {
        interface_name(name)?;
        ensure!(
            features.len() <= MAX_FEATURES,
            "too many requested features"
        );
        for feature in features.keys() {
            ensure!(
                !feature.is_empty()
                    && feature.len() < 32
                    && !feature.chars().any(char::is_control)
                    && !feature.contains('\0'),
                "invalid ethtool feature name"
            );
        }
        if let Some(identity) = expected.get(name) {
            ensure!(
                identity.index > 0 && valid_mac(&identity.mac) && !identity.boot.is_empty(),
                "invalid expected offload identity for {name}"
            );
        }
    }
    Ok(())
}

fn check_identity(actual: &RpsIdentity, expected: &RpsIdentity, same_boot: bool) -> Result<()> {
    crate::ensure_unchanged(
        actual.mac == expected.mac
            && (!same_boot || actual.boot == expected.boot)
            && (actual.boot != expected.boot || actual.index == expected.index),
        "offload interface identity changed",
    )
}

fn observe(
    driver: &mut impl Driver,
    name: &str,
    expected: Option<&RpsIdentity>,
) -> Result<(Snapshot, RpsIdentity)> {
    let identity = driver.identity(name)?;
    if let Some(expected) = expected {
        check_identity(&identity, expected, false)?;
    }
    let snapshot = driver.snapshot(name)?;
    check_identity(&driver.identity(name)?, &identity, true)?;
    Ok((snapshot, identity))
}

#[cfg(test)]
fn read(
    driver: &mut impl Driver,
    values: &Values,
    expected: &Identities,
    complete: bool,
) -> Result<(Values, Identities)> {
    read_field(driver, values, expected, complete, false)
}

#[cfg(test)]
fn read_field(
    driver: &mut impl Driver,
    values: &Values,
    expected: &Identities,
    complete: bool,
    requested_field: bool,
) -> Result<(Values, Identities)> {
    let (active, requested, identities) = read_state(driver, values, expected, complete)?;
    Ok((if requested_field { requested } else { active }, identities))
}

fn read_state(
    driver: &mut impl Driver,
    values: &Values,
    expected: &Identities,
    complete: bool,
) -> Result<State> {
    validate(values, expected)?;
    let mut active = BTreeMap::new();
    let mut wishes = BTreeMap::new();
    let mut identities = BTreeMap::new();
    for (name, requested) in values {
        let (snapshot, identity) = observe(driver, name, expected.get(name))
            .with_context(|| format!("read offloads on {name}"))?;
        // A complete rollback baseline must not depend on requested keys still existing.
        let keys: Vec<_> = if complete {
            snapshot.features.keys().collect()
        } else {
            requested.keys().collect()
        };
        let mut active_bits = BTreeMap::new();
        let mut requested_bits = BTreeMap::new();
        for key in keys {
            let feature = snapshot
                .features
                .get(key)
                .with_context(|| format!("ethtool feature {key:?} does not exist"))?;
            active_bits.insert(key.clone(), feature.active);
            requested_bits.insert(key.clone(), feature.requested);
        }
        active.insert(name.clone(), active_bits);
        wishes.insert(name.clone(), requested_bits);
        identities.insert(name.clone(), identity);
    }
    Ok((active, wishes, identities))
}

fn preflight(driver: &mut impl Driver, values: &Values, expected: &Identities) -> Result<()> {
    validate(values, expected)?;
    if !values.is_empty() {
        driver.writable()?;
    }
    for (name, requested) in values {
        let (snapshot, _) = observe(driver, name, expected.get(name))?;
        snapshot
            .validate(requested, true)
            .with_context(|| format!("preflight offloads on {name}"))?;
    }
    Ok(())
}

#[cfg(test)]
fn write(driver: &mut impl Driver, values: &Values, expected: &Identities) -> Result<()> {
    write_inner(driver, values, None, expected)
}

fn write_requested(
    driver: &mut impl Driver,
    values: &Values,
    requested: &Values,
    expected: &Identities,
) -> Result<()> {
    validate(requested, expected)?;
    ensure!(
        values.keys().eq(requested.keys()),
        "active and requested offload targets must name the same interfaces"
    );
    write_inner(driver, values, Some(requested), expected)
}

fn write_inner(
    driver: &mut impl Driver,
    values: &Values,
    requested: Option<&Values>,
    expected: &Identities,
) -> Result<()> {
    validate(values, expected)?;
    if !values.is_empty() {
        driver.writable()?;
    }
    let mut originals = BTreeMap::new();
    let mut desired = BTreeMap::new();
    for (name, active) in values {
        let (snapshot, identity) = observe(driver, name, expected.get(name))?;
        snapshot.validate(active, false)?;
        let mut intended_active = snapshot.active();
        intended_active.extend(active.clone());
        let mut intended_requested = snapshot.requested();
        if let Some(requested) = requested {
            snapshot.validate_field(&requested[name], false, true)?;
            intended_requested.extend(requested[name].clone());
        } else {
            // Test convenience: explicit mutable toggles target both fields,
            // while unchanged immutable active evidence never overwrites wishes.
            for (key, value) in active {
                let feature = &snapshot.features[key];
                if feature.available && !feature.never_changed {
                    intended_requested.insert(key.clone(), *value);
                }
            }
        }
        desired.insert(name.clone(), (intended_active, intended_requested));
        originals.insert(name.clone(), (snapshot, identity));
    }
    for name in values.keys() {
        let (original, identity) = &originals[name];
        let (current, actual_identity) = observe(driver, name, Some(identity))?;
        check_identity(&actual_identity, identity, true)?;
        crate::ensure_unchanged(current == *original, "offload state changed before write")?;
        let (intended_active, intended_requested) = &desired[name];
        let bytes = encode_set(original, intended_requested)?;
        if *intended_requested != original.requested() {
            check_identity(&driver.identity(name)?, identity, true)?;
            let flags = driver
                .set(name, &bytes)
                .with_context(|| format!("set offloads on {name}"))?;
            // WISH means a request was recorded but could not become active.
            // Accept it only through the exact two-map readback below.
            check_set_flags(flags)?;
        }
        let (observed, observed_identity) = observe(driver, name, Some(identity))?;
        check_identity(&observed_identity, identity, true)?;
        ensure!(
            observed.active() == *intended_active && observed.requested() == *intended_requested,
            "kernel rejected exact active/requested offload state on {name} (including unspecified/coupled features)"
        );
    }
    // Detect cross-interface effects and races during the complete operation too.
    for name in values.keys() {
        let (_, identity) = &originals[name];
        let (intended_active, intended_requested) = &desired[name];
        let (observed, actual_identity) = observe(driver, name, Some(identity))?;
        check_identity(&actual_identity, identity, true)?;
        ensure!(
            observed.active() == *intended_active && observed.requested() == *intended_requested,
            "active/requested offload state changed during write on {name}"
        );
    }
    Ok(())
}

impl Io {
    pub(super) fn system() -> Self {
        Self
    }

    #[cfg(test)]
    pub(super) fn complete(
        &self,
        values: &Values,
        expected: &Identities,
    ) -> Result<(Values, Identities)> {
        if values.is_empty() {
            return Ok((Values::new(), Identities::new()));
        }
        read(&mut System::new()?, values, expected, true)
    }

    #[cfg(test)]
    pub(super) fn read(
        &self,
        values: &Values,
        expected: &Identities,
    ) -> Result<(Values, Identities)> {
        if values.is_empty() {
            return Ok((Values::new(), Identities::new()));
        }
        read(&mut System::new()?, values, expected, false)
    }

    #[cfg(test)]
    pub(super) fn requested(
        &self,
        values: &Values,
        expected: &Identities,
    ) -> Result<(Values, Identities)> {
        if values.is_empty() {
            return Ok((Values::new(), Identities::new()));
        }
        read_field(&mut System::new()?, values, expected, false, true)
    }

    pub(super) fn complete_state(&self, values: &Values, expected: &Identities) -> Result<State> {
        if values.is_empty() {
            return Ok((Values::new(), Values::new(), Identities::new()));
        }
        read_state(&mut System::new()?, values, expected, true)
    }

    pub(super) fn read_state(&self, values: &Values, expected: &Identities) -> Result<State> {
        if values.is_empty() {
            return Ok((Values::new(), Values::new(), Identities::new()));
        }
        read_state(&mut System::new()?, values, expected, false)
    }

    pub(super) fn preflight(&self, values: &Values, expected: &Identities) -> Result<()> {
        if values.is_empty() {
            return Ok(());
        }
        preflight(&mut System::new()?, values, expected)
    }

    #[cfg(test)]
    pub(super) fn write(&self, values: &Values, expected: &Identities) -> Result<()> {
        if values.is_empty() {
            return Ok(());
        }
        write(&mut System::new()?, values, expected)
    }

    pub(super) fn write_requested(
        &self,
        active: &Values,
        requested: &Values,
        expected: &Identities,
    ) -> Result<()> {
        if active.is_empty() && requested.is_empty() {
            return Ok(());
        }
        write_requested(&mut System::new()?, active, requested, expected)
    }
}

fn word(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset.checked_add(4).context("ethtool offset overflow")?;
    Ok(u32::from_ne_bytes(
        bytes
            .get(offset..end)
            .context("short ethtool u32")?
            .try_into()?,
    ))
}

fn put(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}

fn request(command: u32, length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    put(&mut bytes, 0, command);
    bytes
}

fn lengths(count: usize) -> Result<(usize, usize)> {
    ensure!(
        count > 0 && count <= MAX_FEATURES,
        "invalid ethtool feature count"
    );
    Ok((12 + count * 32, 8 + count.div_ceil(32) * 16))
}

fn decode(count: usize, strings: &[u8], features: &[u8]) -> Result<Snapshot> {
    let (string_length, feature_length) = lengths(count)?;
    ensure!(
        strings.len() == string_length
            && features.len() == feature_length
            && word(strings, 0)? == GSTRINGS
            && word(strings, 4)? == FEATURE_SET
            && word(strings, 8)? as usize == count
            && word(features, 0)? == GFEATURES
            && word(features, 4)? as usize == count.div_ceil(32),
        "invalid or changed ethtool feature buffers"
    );
    let mut result = BTreeMap::new();
    for bit in 0..count {
        let raw = &strings[12 + bit * 32..12 + (bit + 1) * 32];
        let end = raw
            .iter()
            .position(|byte| *byte == 0)
            .context("unterminated ethtool feature")?;
        let name = std::str::from_utf8(&raw[..end])?;
        ensure!(
            !name.chars().any(char::is_control),
            "invalid ethtool feature string"
        );
        let offset = 8 + (bit / 32) * 16;
        let mask = 1u32 << (bit % 32);
        let feature = Feature {
            bit,
            available: word(features, offset)? & mask != 0,
            requested: word(features, offset + 4)? & mask != 0,
            active: word(features, offset + 8)? & mask != 0,
            never_changed: word(features, offset + 12)? & mask != 0,
        };
        // The global stringset contains unnamed reserved bits, not feature aliases.
        if name.is_empty() {
            ensure!(
                !feature.available
                    && !feature.requested
                    && !feature.active
                    && !feature.never_changed,
                "unnamed ethtool feature has live flags"
            );
            continue;
        }
        ensure!(
            result.insert(name.to_owned(), feature).is_none(),
            "duplicate ethtool feature name"
        );
    }
    // No unaddressable bits may carry state outside the returned stringset.
    if count % 32 != 0 {
        let mask = u32::MAX << (count % 32);
        let offset = 8 + (count / 32) * 16;
        for field in 0..4 {
            ensure!(
                word(features, offset + field * 4)? & mask == 0,
                "flags beyond ethtool feature count"
            );
        }
    }
    Ok(Snapshot {
        count,
        features: result,
    })
}

fn encode_set(snapshot: &Snapshot, values: &BTreeMap<String, bool>) -> Result<Vec<u8>> {
    lengths(snapshot.count)?;
    snapshot.validate_field(values, false, true)?;
    let blocks = snapshot.count.div_ceil(32);
    let mut bytes = request(SFEATURES, 8 + blocks * 8);
    put(&mut bytes, 4, u32::try_from(blocks)?);
    for (name, desired) in values {
        let feature = &snapshot.features[name];
        if feature.requested == *desired {
            continue;
        }
        ensure!(feature.bit < snapshot.count, "invalid ethtool feature bit");
        let offset = 8 + feature.bit / 32 * 8;
        let mask = 1u32 << (feature.bit % 32);
        let valid = word(&bytes, offset)? | mask;
        put(&mut bytes, offset, valid);
        if *desired {
            let requested = word(&bytes, offset + 4)? | mask;
            put(&mut bytes, offset + 4, requested);
        }
    }
    Ok(bytes)
}

struct System {
    socket: OwnedFd,
}

impl System {
    fn new() -> Result<Self> {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("open offload ioctl socket");
        }
        Ok(Self {
            socket: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    fn ifreq(name: &str) -> Result<libc::ifreq> {
        interface_name(name)?;
        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        for (target, byte) in request.ifr_name.iter_mut().zip(name.bytes()) {
            *target = byte as libc::c_char;
        }
        Ok(request)
    }

    fn ioctl(&self, name: &str, bytes: &[u8]) -> Result<(Vec<u8>, i32)> {
        ensure!(
            bytes.len() >= 4 && bytes.len() <= 256 * 1024,
            "invalid ethtool buffer size"
        );
        let mut aligned = vec![0u64; bytes.len().div_ceil(8)];
        let data = unsafe {
            std::slice::from_raw_parts_mut(aligned.as_mut_ptr().cast::<u8>(), aligned.len() * 8)
        };
        data[..bytes.len()].copy_from_slice(bytes);
        let mut request = Self::ifreq(name)?;
        request.ifr_ifru.ifru_data = data.as_mut_ptr().cast();
        let status = unsafe {
            libc::ioctl(
                self.socket.as_raw_fd(),
                libc::SIOCETHTOOL as _,
                &mut request,
            )
        };
        if status < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "ethtool command 0x{:x} on {name}",
                    word(bytes, 0).unwrap_or(0)
                )
            });
        }
        Ok((data[..bytes.len()].to_vec(), status))
    }

    fn get(&self, name: &str, bytes: &[u8]) -> Result<Vec<u8>> {
        let (bytes, status) = self.ioctl(name, bytes)?;
        ensure!(
            status == 0,
            "unexpected ethtool read return flags 0x{status:x}"
        );
        Ok(bytes)
    }

    fn link_identity(&self, name: &str) -> Result<(u32, String)> {
        let mut request = Self::ifreq(name)?;
        if unsafe {
            libc::ioctl(
                self.socket.as_raw_fd(),
                libc::SIOCGIFINDEX as _,
                &mut request,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error()).context("read offload interface index");
        }
        let index = unsafe { request.ifr_ifru.ifru_ifindex };
        ensure!(index > 0, "invalid offload interface index");
        if unsafe {
            libc::ioctl(
                self.socket.as_raw_fd(),
                libc::SIOCGIFHWADDR as _,
                &mut request,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error()).context("read offload interface address");
        }
        let address = unsafe { request.ifr_ifru.ifru_hwaddr };
        ensure!(address.sa_family == 1, "offloads require Ethernet hardware");
        let mac = address.sa_data[..6]
            .iter()
            .map(|b| format!("{:02x}", *b as u8))
            .collect::<Vec<_>>()
            .join(":");
        Ok((u32::try_from(index)?, mac))
    }
}

fn child(directory: &File, name: &str, flags: i32) -> Result<File> {
    let name = std::ffi::CString::new(name)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("open offload identity source");
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn text(file: File) -> Result<String> {
    let mut value = String::new();
    file.take(4097).read_to_string(&mut value)?;
    ensure!(value.len() <= 4096, "oversized offload identity source");
    let value = value.trim();
    ensure!(
        !value.chars().any(char::is_control),
        "invalid offload identity text"
    );
    Ok(value.to_owned())
}

fn valid_mac(mac: &str) -> bool {
    mac.len() == 17
        && mac.split(':').count() == 6
        && mac
            .split(':')
            .all(|part| part.len() == 2 && part.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn check_set_flags(flags: u32) -> Result<()> {
    ensure!(
        flags == 0 || flags == FEATURE_WISH,
        "ethtool SFEATURES returned unsupported/compat/unknown flags 0x{flags:x}; exact request not accepted"
    );
    Ok(())
}

impl Driver for System {
    fn identity(&mut self, name: &str) -> Result<RpsIdentity> {
        interface_name(name)?;
        // sysfs class entries are legitimate symlinks; pin their target, then use openat.
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open("/sys/class/net")?;
        let name_c = std::ffi::CString::new(name)?;
        let fd = unsafe {
            libc::openat(
                root.as_raw_fd(),
                name_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("open offload interface sysfs");
        }
        let directory = unsafe { File::from_raw_fd(fd) };
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe { libc::fstatfs(directory.as_raw_fd(), &mut stat) } == 0
                && stat.f_type as u64 == libc::SYSFS_MAGIC as u64,
            "offload identity must reside on sysfs"
        );
        let device = child(&directory, "device", libc::O_PATH)?;
        let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe { libc::fstat(device.as_raw_fd(), &mut metadata) } == 0
                && metadata.st_mode & libc::S_IFMT == libc::S_IFLNK,
            "offloads require a physical Ethernet device"
        );
        ensure!(
            text(child(&directory, "type", libc::O_RDONLY)?)? == "1",
            "offloads require Ethernet hardware"
        );
        let index: u32 = text(child(&directory, "ifindex", libc::O_RDONLY)?)?.parse()?;
        let mac = text(child(&directory, "address", libc::O_RDONLY)?)?;
        let boot = text(File::open("/proc/sys/kernel/random/boot_id")?)?;
        ensure!(
            index > 0 && valid_mac(&mac) && !boot.is_empty(),
            "invalid offload interface identity"
        );
        let (live_index, live_mac) = self.link_identity(name)?;
        crate::ensure_unchanged(
            index == live_index && mac == live_mac,
            "offload sysfs/network namespace identity mismatch",
        )?;
        Ok(RpsIdentity {
            index,
            mac,
            boot,
            wireguard_public_key: None,
        })
    }

    fn snapshot(&mut self, name: &str) -> Result<Snapshot> {
        let mut info = request(GSSET_INFO, 24);
        info[8..16].copy_from_slice(&(1u64 << FEATURE_SET).to_ne_bytes());
        let info = self.get(name, &info)?;
        ensure!(
            word(&info, 0)? == GSSET_INFO
                && u64::from_ne_bytes(info[8..16].try_into()?) == 1u64 << FEATURE_SET,
            "driver did not expose ethtool feature stringset"
        );
        let count = usize::try_from(word(&info, 16)?)?;
        let (string_length, feature_length) = lengths(count)?;
        let mut strings = request(GSTRINGS, string_length);
        put(&mut strings, 4, FEATURE_SET);
        put(&mut strings, 8, u32::try_from(count)?);
        let strings = self.get(name, &strings)?;
        let mut features = request(GFEATURES, feature_length);
        put(&mut features, 4, u32::try_from(count.div_ceil(32))?);
        let features = self.get(name, &features)?;
        decode(count, &strings, &features)
    }

    fn writable(&mut self) -> Result<()> {
        #[repr(C)]
        struct Header {
            version: u32,
            pid: i32,
        }
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct Caps {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }
        let mut header = Header {
            version: 0x2008_0522,
            pid: 0,
        };
        let mut caps = [Caps {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }; 2];
        if unsafe { libc::syscall(libc::SYS_capget, &mut header, caps.as_mut_ptr()) } < 0 {
            return Err(std::io::Error::last_os_error())
                .context("inspect offload write capability");
        }
        // This is non-mutating evidence only; namespace ownership, LSM and driver
        // restrictions can still deny SFEATURES and must propagate from the ioctl.
        ensure!(
            caps[0].effective & (1 << 12) != 0,
            "offload writes require effective CAP_NET_ADMIN"
        );
        Ok(())
    }

    fn set(&mut self, name: &str, bytes: &[u8]) -> Result<u32> {
        let (_, flags) = self.ioctl(name, bytes)?;
        Ok(u32::try_from(flags)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn buffers(count: usize) -> (Vec<u8>, Vec<u8>) {
        let (s, f) = lengths(count).unwrap();
        let mut strings = request(GSTRINGS, s);
        put(&mut strings, 4, FEATURE_SET);
        put(&mut strings, 8, count as u32);
        for bit in 0..count {
            let name = format!("feature-{bit}");
            strings[12 + bit * 32..12 + bit * 32 + name.len()].copy_from_slice(name.as_bytes());
        }
        let mut features = request(GFEATURES, f);
        put(&mut features, 4, count.div_ceil(32) as u32);
        (strings, features)
    }

    fn fixture() -> Snapshot {
        let (strings, mut features) = buffers(5);
        put(&mut features, 8, 0b0111);
        put(&mut features, 12, 0b0010);
        put(&mut features, 16, 0b1010);
        put(&mut features, 20, 0b0010);
        decode(5, &strings, &features).unwrap()
    }

    fn identity() -> RpsIdentity {
        RpsIdentity {
            index: 7,
            mac: "02:00:00:00:00:01".into(),
            boot: "test-boot".into(),
            wireguard_public_key: None,
        }
    }

    #[derive(Default)]
    struct Fake {
        snapshots: BTreeMap<String, Snapshot>,
        identities: BTreeMap<String, RpsIdentity>,
        sets: usize,
        coupled: bool,
        fail_set: bool,
        deny: bool,
        race: bool,
        read_race: bool,
        dependency: bool,
        requested_side_effect: bool,
        flags: u32,
        reads: usize,
    }

    impl Fake {
        fn new() -> Self {
            Self {
                snapshots: [("eth0".into(), fixture())].into(),
                identities: [("eth0".into(), identity())].into(),
                ..Default::default()
            }
        }
    }

    impl Driver for Fake {
        fn identity(&mut self, name: &str) -> Result<RpsIdentity> {
            let mut identity = self.identities[name].clone();
            if self.race && self.sets > 0 {
                identity.index += 1;
            }
            Ok(identity)
        }
        fn snapshot(&mut self, name: &str) -> Result<Snapshot> {
            self.reads += 1;
            if self.read_race {
                self.identities.get_mut(name).unwrap().index += 1;
            }
            Ok(self.snapshots[name].clone())
        }
        fn writable(&mut self) -> Result<()> {
            ensure!(!self.deny, "permission denied");
            Ok(())
        }
        fn set(&mut self, name: &str, bytes: &[u8]) -> Result<u32> {
            self.sets += 1;
            ensure!(!self.fail_set, "SFEATURES flags 0x2");
            let snapshot = self.snapshots.get_mut(name).unwrap();
            for feature in snapshot.features.values_mut() {
                let offset = 8 + feature.bit / 32 * 8;
                let mask = 1 << (feature.bit % 32);
                if word(bytes, offset)? & mask != 0 {
                    feature.requested = word(bytes, offset + 4)? & mask != 0;
                    feature.active = feature.requested;
                }
            }
            if self.dependency {
                let prerequisite = snapshot.features["feature-0"].active;
                let dependent = snapshot.features.get_mut("feature-2").unwrap();
                dependent.active = dependent.requested && prerequisite;
            }
            if self.coupled {
                snapshot.features.get_mut("feature-2").unwrap().active = true;
            }
            if self.requested_side_effect {
                let feature = snapshot.features.get_mut("feature-2").unwrap();
                feature.requested = !feature.requested;
            }
            let mut flags = self.flags;
            for feature in snapshot.features.values() {
                let mask = 1 << (feature.bit % 32);
                if word(bytes, 8 + feature.bit / 32 * 8)? & mask != 0
                    && feature.active != feature.requested
                {
                    flags |= FEATURE_WISH;
                }
            }
            Ok(flags)
        }
    }

    fn values(name: &str, active: bool) -> Values {
        [("eth0".into(), [(name.into(), active)].into())].into()
    }

    #[test]
    fn decodes_all_four_words_and_cross_block_bits() {
        let (strings, mut features) = buffers(33);
        put(&mut features, 24, 1);
        put(&mut features, 28, 1);
        put(&mut features, 32, 1);
        put(&mut features, 36, 1);
        let snapshot = decode(33, &strings, &features).unwrap();
        assert_eq!(snapshot.features.len(), 33);
        assert_eq!(
            snapshot.features["feature-32"],
            Feature {
                bit: 32,
                available: true,
                requested: true,
                active: true,
                never_changed: true,
            }
        );
        assert!(!snapshot.features["feature-0"].active);
    }

    #[test]
    fn rejects_bounds_short_buffers_duplicate_names_and_unaddressable_flags() {
        assert!(lengths(0).is_err());
        assert!(lengths(4097).is_err());
        assert!(lengths(usize::MAX).is_err());
        let (strings, features) = buffers(4096);
        assert!(decode(4096, &strings, &features).is_ok());
        let (mut strings, mut features) = buffers(2);
        assert!(decode(2, &strings[..20], &features).is_err());
        assert!(word(&features, usize::MAX).is_err());
        let duplicate = strings[12..44].to_vec();
        strings[44..76].copy_from_slice(&duplicate);
        assert!(decode(2, &strings, &features).is_err());
        strings[44..76].fill(0);
        assert_eq!(decode(2, &strings, &features).unwrap().features.len(), 1);
        put(&mut features, 16, 2);
        assert!(decode(2, &strings, &features).is_err());
        put(&mut features, 16, 4);
        assert!(decode(2, &strings, &features).is_err());
        strings[12..44].fill(b'x');
        assert!(decode(2, &strings, &features).is_err());
    }

    #[test]
    fn strict_preflight_rejects_missing_fixed_and_unsupported_even_unchanged() {
        for (name, active) in [
            ("absent", false),
            ("feature-1", true),
            ("feature-3", true),
            ("feature-4", false),
        ] {
            let mut fake = Fake::new();
            assert!(preflight(&mut fake, &values(name, active), &Identities::new()).is_err());
            assert_eq!(fake.sets, 0);
        }
        assert!(
            preflight(
                &mut Fake::new(),
                &values("feature-0", true),
                &Identities::new()
            )
            .is_ok()
        );
        let mut fake = Fake::new();
        fake.deny = true;
        assert!(preflight(&mut fake, &values("feature-0", true), &Identities::new()).is_err());
    }

    #[test]
    fn full_baseline_preserves_disabled_unsupported_and_fixed_active_bits() {
        let mut fake = Fake::new();
        let (baseline, identities) = read(
            &mut fake,
            &values("feature-0", true),
            &Identities::new(),
            true,
        )
        .unwrap();
        assert_eq!(baseline["eth0"].len(), 5);
        assert!(baseline["eth0"]["feature-3"]);
        assert!(!baseline["eth0"]["feature-2"]);
        assert!(!baseline["eth0"]["feature-4"]);
        assert!(!fake.snapshots["eth0"].features["feature-4"].available);
        write(&mut fake, &values("feature-0", true), &identities).unwrap();
        assert_eq!(fake.sets, 1);
        write(&mut fake, &baseline, &identities).unwrap();
        assert_eq!(fake.snapshots["eth0"].active(), baseline["eth0"]);
        assert_eq!(fake.sets, 2);
        write(&mut fake, &baseline, &identities).unwrap();
        assert_eq!(fake.sets, 2);
        assert!(write(&mut fake, &values("feature-1", false), &identities).is_err());
        assert!(write(&mut fake, &values("feature-3", false), &identities).is_err());
    }

    #[test]
    fn selective_reads_reject_missing_but_complete_captures_everything() {
        let request = values("absent", false);
        assert!(read(&mut Fake::new(), &request, &Identities::new(), false).is_err());
        assert_eq!(
            read(&mut Fake::new(), &request, &Identities::new(), true)
                .unwrap()
                .0["eth0"]
                .len(),
            5
        );
        let result = read(
            &mut Fake::new(),
            &values("feature-1", false),
            &Identities::new(),
            false,
        )
        .unwrap();
        assert_eq!(result.0["eth0"], [("feature-1".into(), true)].into());
    }

    #[test]
    fn exact_readback_rejects_dependency_changes_without_silent_restore() {
        let mut fake = Fake::new();
        fake.coupled = true;
        let error = write(&mut fake, &values("feature-0", true), &Identities::new()).unwrap_err();
        assert!(error.to_string().contains("including unspecified/coupled"));
        assert_eq!(fake.sets, 1);
        assert!(fake.snapshots["eth0"].features["feature-2"].active);
    }

    #[test]
    fn paired_reads_use_one_snapshot_and_expose_latent_requested_bits() {
        let mut fake = Fake::new();
        fake.snapshots
            .get_mut("eth0")
            .unwrap()
            .features
            .get_mut("feature-2")
            .unwrap()
            .requested = true;
        let request = values("feature-2", false);
        let (active, requested, identities) =
            read_state(&mut fake, &request, &Identities::new(), false).unwrap();
        assert_eq!(
            fake.reads, 1,
            "both fields must come from the same GFEATURES"
        );
        assert_eq!(active["eth0"], [("feature-2".into(), false)].into());
        assert_eq!(requested["eth0"], [("feature-2".into(), true)].into());
        assert_eq!(identities["eth0"], identity());
        assert_eq!(
            read_field(&mut fake, &request, &identities, false, true)
                .unwrap()
                .0,
            requested
        );
        assert!(read_state(&mut fake, &values("missing", false), &identities, false).is_err());
    }

    #[test]
    fn latent_wishes_survive_dependency_changes_and_full_baseline_roundtrip() {
        let mut fake = Fake::new();
        fake.dependency = true;
        fake.snapshots
            .get_mut("eth0")
            .unwrap()
            .features
            .get_mut("feature-2")
            .unwrap()
            .requested = true;
        let (active, requested, identities) = read_state(
            &mut fake,
            &values("feature-0", true),
            &Identities::new(),
            true,
        )
        .unwrap();
        assert!(!active["eth0"]["feature-2"]);
        assert!(requested["eth0"]["feature-2"]);
        let mut target_active = active.clone();
        target_active
            .get_mut("eth0")
            .unwrap()
            .extend([("feature-0".into(), true), ("feature-2".into(), true)]);
        let mut target_requested = requested.clone();
        target_requested
            .get_mut("eth0")
            .unwrap()
            .insert("feature-0".into(), true);
        let encoded = encode_set(&fake.snapshots["eth0"], &target_requested["eth0"]).unwrap();
        assert_eq!(
            word(&encoded, 8).unwrap(),
            1,
            "untouched latent wish must not be in valid mask"
        );
        write_requested(&mut fake, &target_active, &target_requested, &identities).unwrap();
        write_requested(&mut fake, &active, &requested, &identities).unwrap();
        let restored = &fake.snapshots["eth0"];
        assert_eq!(restored.active(), active["eth0"]);
        assert_eq!(restored.requested(), requested["eth0"]);
        assert_eq!(fake.sets, 2);

        // Clear and restore a wish without any change to active state. Restoring
        // it produces WISH because its prerequisite is still disabled.
        let mut cleared = requested.clone();
        cleared
            .get_mut("eth0")
            .unwrap()
            .insert("feature-2".into(), false);
        write_requested(&mut fake, &active, &cleared, &identities).unwrap();
        write_requested(&mut fake, &active, &requested, &identities).unwrap();
        assert_eq!(fake.sets, 4);
        assert_eq!(fake.snapshots["eth0"].active(), active["eth0"]);
        assert_eq!(fake.snapshots["eth0"].requested(), requested["eth0"]);
    }

    #[test]
    fn wish_flag_requires_exact_both_maps_and_other_flags_always_fail() {
        for flags in [1, 3, 4, 6, 8] {
            let mut fake = Fake::new();
            fake.flags = flags;
            let request = values("feature-0", true);
            assert!(write_requested(&mut fake, &request, &request, &Identities::new()).is_err());
            assert_eq!(fake.sets, 1);
        }
        let mut fake = Fake::new();
        fake.flags = FEATURE_WISH;
        let request = values("feature-0", true);
        write_requested(&mut fake, &request, &request, &Identities::new()).unwrap();

        let mut fake = Fake::new();
        fake.flags = FEATURE_WISH;
        fake.requested_side_effect = true;
        assert!(write_requested(&mut fake, &request, &request, &Identities::new()).is_err());
        assert_eq!(fake.sets, 1);
        assert!(fake.snapshots["eth0"].features["feature-2"].requested);

        let mut fake = Fake::new();
        fake.dependency = true;
        let impossible = values("feature-2", true);
        assert!(write_requested(&mut fake, &impossible, &impossible, &Identities::new()).is_err());
        assert_eq!(fake.sets, 1, "WISH cannot excuse an active-state mismatch");
    }

    #[test]
    fn requested_only_validation_rejects_fixed_changes_and_mismatched_interfaces() {
        let mut fake = Fake::new();
        let fixed_active = values("feature-3", true);
        let fixed_requested = values("feature-3", false);
        write_requested(
            &mut fake,
            &fixed_active,
            &fixed_requested,
            &Identities::new(),
        )
        .unwrap();
        assert_eq!(fake.sets, 0);
        assert!(
            write_requested(&mut fake, &fixed_active, &fixed_active, &Identities::new()).is_err()
        );
        assert!(
            write_requested(&mut fake, &fixed_active, &Values::new(), &Identities::new()).is_err()
        );
        assert_eq!(fake.sets, 0);
    }

    #[test]
    fn ioctl_flags_and_identity_races_propagate_without_another_write() {
        assert!(check_set_flags(0).is_ok());
        assert!(check_set_flags(FEATURE_WISH).is_ok());
        for flags in [1, 3, 4, 6, 7, 8] {
            assert!(check_set_flags(flags).is_err());
        }
        for (fail_set, race) in [(true, false), (false, true)] {
            let mut fake = Fake::new();
            fake.fail_set = fail_set;
            fake.race = race;
            assert!(write(&mut fake, &values("feature-0", true), &Identities::new()).is_err());
            assert_eq!(fake.sets, 1);
        }
        let mut fake = Fake::new();
        fake.read_race = true;
        assert!(
            read(
                &mut fake,
                &values("feature-0", false),
                &Identities::new(),
                false
            )
            .is_err()
        );
        assert_eq!(fake.sets, 0);
    }

    #[test]
    fn validates_all_interfaces_before_first_mutation() {
        let mut fake = Fake::new();
        fake.snapshots.insert("eth1".into(), fixture());
        fake.identities.insert("eth1".into(), identity());
        let mut request = values("feature-0", true);
        request.insert("eth1".into(), [("missing".into(), true)].into());
        assert!(write(&mut fake, &request, &Identities::new()).is_err());
        assert_eq!(fake.sets, 0);
    }

    #[test]
    fn empty_system_operations_are_successful_without_hardware_or_privileges() {
        let io = Io::system();
        let values = Values::new();
        let expected = Identities::new();
        assert_eq!(
            io.complete(&values, &expected).unwrap(),
            (Values::new(), Identities::new())
        );
        assert_eq!(
            io.read(&values, &expected).unwrap(),
            (Values::new(), Identities::new())
        );
        io.preflight(&values, &expected).unwrap();
        io.write(&values, &expected).unwrap();
        assert_eq!(
            io.requested(&values, &expected).unwrap(),
            (Values::new(), Identities::new())
        );
        assert_eq!(
            io.read_state(&values, &expected).unwrap(),
            (Values::new(), Values::new(), Identities::new())
        );
        assert_eq!(
            io.complete_state(&values, &expected).unwrap(),
            (Values::new(), Values::new(), Identities::new())
        );
        io.write_requested(&values, &values, &expected).unwrap();
    }

    #[test]
    #[ignore = "requires NETCONTROL_INTEGRATION=1 and CAP_SYS_ADMIN/CAP_NET_ADMIN; isolated veth only"]
    fn isolated_veth_direct_ioctl_exact_state_and_restore() {
        assert_eq!(std::env::var("NETCONTROL_INTEGRATION").as_deref(), Ok("1"));
        // Never enter or mutate the caller's network namespace. The short-lived
        // thread owns its namespace and the veth pair disappears with it.
        std::thread::spawn(|| -> Result<()> {
            ensure!(
                unsafe { libc::unshare(libc::CLONE_NEWNET) } == 0,
                "unshare offload fixture: {}",
                std::io::Error::last_os_error()
            );
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async {
                let (connection, handle, _) = rtnetlink::new_connection()?;
                let task = tokio::spawn(connection);
                handle
                    .link()
                    .add(rtnetlink::LinkVeth::new(&"nc-offload-a", &"nc-offload-b").build())
                    .execute()
                    .await?;
                struct VethDriver(System, usize);
                impl Driver for VethDriver {
                    fn identity(&mut self, name: &str) -> Result<RpsIdentity> {
                        ensure!(name == "nc-offload-a", "non-fixture device");
                        let (index, mac) = self.0.link_identity(name)?;
                        Ok(RpsIdentity {
                            index,
                            mac,
                            boot: "isolated-veth-fixture".into(),
                            wireguard_public_key: None,
                        })
                    }
                    fn snapshot(&mut self, name: &str) -> Result<Snapshot> {
                        self.0.snapshot(name)
                    }
                    fn writable(&mut self) -> Result<()> {
                        self.0.writable()
                    }
                    fn set(&mut self, name: &str, bytes: &[u8]) -> Result<u32> {
                        let flags = self.0.set(name, bytes)?;
                        if flags & FEATURE_WISH != 0 {
                            self.1 += 1;
                        }
                        Ok(flags)
                    }
                }
                let mut driver = VethDriver(System::new()?, 0);
                let original = driver.snapshot("nc-offload-a")?;
                let gro = original
                    .features
                    .get("rx-gro")
                    .context("veth missing rx-gro")?;
                ensure!(
                    gro.available && !gro.never_changed,
                    "veth rx-gro is not mutable"
                );
                let request = [(
                    "nc-offload-a".into(),
                    [("rx-gro".into(), !gro.active)].into(),
                )]
                .into();
                let (baseline, original_requested, identities) =
                    read_state(&mut driver, &request, &Identities::new(), true)?;
                preflight(&mut driver, &request, &identities)?;
                write_requested(&mut driver, &request, &request, &identities)?;
                write_requested(&mut driver, &baseline, &original_requested, &identities)?;
                ensure!(
                    driver.snapshot("nc-offload-a")?.active() == original.active()
                        && driver.snapshot("nc-offload-a")?.requested() == original.requested(),
                    "veth full baseline was not restored"
                );
                // Deliberately establish a dependency-constrained state in this
                // disposable pair: TSO remains wished for while SG is disabled.
                let sg = original
                    .features
                    .get("tx-scatter-gather")
                    .context("veth missing tx-scatter-gather")?;
                let tso = original
                    .features
                    .get("tx-tcp-segmentation")
                    .context("veth missing tx-tcp-segmentation")?;
                ensure!(
                    sg.available
                        && !sg.never_changed
                        && tso.available
                        && !tso.never_changed
                        && tso.requested,
                    "veth lacks the mutable SG/TSO dependency fixture"
                );
                let bytes = encode_set(&original, &[("tx-scatter-gather".into(), false)].into())?;
                check_set_flags(driver.set("nc-offload-a", &bytes)?)?;
                let (latent_active, latent_requested, latent_identities) =
                    read_state(&mut driver, &request, &Identities::new(), true)?;
                ensure!(
                    !latent_active["nc-offload-a"]["tx-tcp-segmentation"]
                        && latent_requested["nc-offload-a"]["tx-tcp-segmentation"],
                    "veth did not retain the inactive requested TSO wish"
                );
                let mut cleared = latent_requested.clone();
                cleared
                    .get_mut("nc-offload-a")
                    .unwrap()
                    .insert("tx-tcp-segmentation".into(), false);
                write_requested(&mut driver, &latent_active, &cleared, &latent_identities)?;
                write_requested(
                    &mut driver,
                    &latent_active,
                    &latent_requested,
                    &latent_identities,
                )?;
                ensure!(driver.1 > 0, "kernel WISH flag was not exercised");
                write_requested(&mut driver, &baseline, &original_requested, &identities)?;
                let restored = driver.snapshot("nc-offload-a")?;
                ensure!(
                    restored.active() == original.active()
                        && restored.requested() == original.requested(),
                    "veth dependency/wish roundtrip did not restore both full maps"
                );
                // Production identity policy must never accept this virtual pair.
                ensure!(
                    Io::system().complete(&request, &Identities::new()).is_err(),
                    "production physical-device guard accepted veth"
                );
                task.abort();
                let _ = task.await;
                Ok::<(), anyhow::Error>(())
            })
        })
        .join()
        .expect("offload namespace fixture panicked")
        .unwrap();
    }

    #[test]
    fn identities_use_mac_and_same_boot_index_and_require_stability_within_operation() {
        let expected = identity();
        let mut actual = expected.clone();
        actual.index += 1;
        assert!(check_identity(&actual, &expected, false).is_err());
        actual.boot = "another-boot".into();
        assert!(check_identity(&actual, &expected, false).is_ok());
        assert!(check_identity(&actual, &expected, true).is_err());
        actual.mac = "02:00:00:00:00:02".into();
        assert!(check_identity(&actual, &expected, false).is_err());
    }

    #[test]
    fn set_encoding_does_not_touch_fixed_or_unspecified_features() {
        let snapshot = fixture();
        let mut values = snapshot.requested();
        values.insert("feature-0".into(), true);
        let bytes = encode_set(&snapshot, &values).unwrap();
        assert_eq!(word(&bytes, 0).unwrap(), SFEATURES);
        assert_eq!(word(&bytes, 4).unwrap(), 1);
        assert_eq!(word(&bytes, 8).unwrap(), 1);
        assert_eq!(word(&bytes, 12).unwrap(), 1);
    }

    #[test]
    fn set_encoding_addresses_second_block_without_setting_neighbors() {
        let (strings, mut features) = buffers(33);
        put(&mut features, 24, 1);
        let snapshot = decode(33, &strings, &features).unwrap();
        let bytes = encode_set(&snapshot, &[("feature-32".into(), true)].into()).unwrap();
        assert_eq!(bytes.len(), 24);
        assert_eq!(word(&bytes, 4).unwrap(), 2);
        assert_eq!(word(&bytes, 8).unwrap(), 0);
        assert_eq!(word(&bytes, 12).unwrap(), 0);
        assert_eq!(word(&bytes, 16).unwrap(), 1);
        assert_eq!(word(&bytes, 20).unwrap(), 1);
    }

    #[test]
    fn validates_names_before_driver_access() {
        for name in [
            "",
            "../eth0",
            "eth0/x",
            ".",
            "..",
            "eth 0",
            "eth0:1",
            "eth0\0",
            "0123456789abcdef",
        ] {
            assert!(interface_name(name).is_err(), "{name:?}");
        }
        assert!(interface_name("enp1s0.20").is_ok());
        assert!(validate(&values("ethtool:feature-0", false), &Identities::new()).is_ok());
        assert!(
            read(
                &mut Fake::new(),
                &values("ethtool:feature-0", false),
                &Identities::new(),
                false
            )
            .is_err()
        );
    }
}
