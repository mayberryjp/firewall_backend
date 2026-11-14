use anyhow::{Result, ensure};
use std::{
    collections::BTreeSet,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::atomic::{AtomicU32, Ordering},
    time::Instant,
};

const RING_BYTES: usize = 4 << 20;
const FRAME_BYTES: usize = 8192;
const SNAP_BYTES: u32 = 4608;

pub(super) struct Egress {
    fd: OwnedFd,
    ring: *mut libc::c_void,
    frame: usize,
}

fn option<T>(fd: &OwnedFd, level: i32, name: i32, value: &T) -> Result<()> {
    ensure!(
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                level,
                name,
                (value as *const T).cast(),
                std::mem::size_of::<T>() as libc::socklen_t,
            )
        } == 0,
        "configure experience egress capture: {}",
        io::Error::last_os_error()
    );
    Ok(())
}

fn instruction(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

fn filter(indices: &BTreeSet<u32>) -> Vec<libc::sock_filter> {
    let mut code = vec![
        instruction(0x20, 0, 0, 0xffff_f004),
        instruction(0x15, 1, 0, u32::from(libc::PACKET_OUTGOING)),
        instruction(0x06, 0, 0, 0),
        instruction(0x20, 0, 0, 0xffff_f008),
    ];
    for (position, index) in indices.iter().enumerate() {
        code.push(instruction(0x15, 0, 1, *index));
        code.push(instruction(
            0x05,
            0,
            0,
            ((indices.len() - position - 1) * 2 + 1) as u32,
        ));
    }
    code.push(instruction(0x06, 0, 0, 0));
    // Ancillary protocol/ifindex refer to the logical device; SOCK_DGRAM starts at IP.
    code.extend([
        instruction(0x20, 0, 0, 0xffff_f000),
        instruction(0x15, 2, 0, 0x0800),
        instruction(0x15, 12, 0, 0x86dd),
        instruction(0x06, 0, 0, 0),
        instruction(0x30, 0, 0, 9),
        instruction(0x15, 1, 0, 6),
        instruction(0x15, 0, 7, 17),
        instruction(0xb1, 0, 0, 0),
        instruction(0x48, 0, 0, 0),
        instruction(0x15, 19, 0, 53),
        instruction(0x48, 0, 0, 2),
        instruction(0x15, 17, 0, 53),
        instruction(0x30, 0, 0, 9),
        instruction(0x15, 14, 0, 6),
        instruction(0x06, 0, 0, 0),
        instruction(0x30, 0, 0, 6),
        instruction(0x15, 5, 0, 6),
        instruction(0x15, 4, 0, 17),
        instruction(0x15, 10, 0, 0),
        instruction(0x15, 9, 0, 43),
        instruction(0x15, 8, 0, 60),
        instruction(0x15, 7, 8, 51),
        instruction(0x28, 0, 0, 40),
        instruction(0x15, 5, 0, 53),
        instruction(0x28, 0, 0, 42),
        instruction(0x15, 3, 0, 53),
        instruction(0x30, 0, 0, 6),
        instruction(0x15, 0, 2, 6),
        instruction(0x06, 0, 0, 256),
        instruction(0x06, 0, 0, SNAP_BYTES),
        instruction(0x15, 1, 0, 44),
        instruction(0x06, 0, 0, 0),
        instruction(0x06, 0, 0, SNAP_BYTES),
    ]);
    code
}

impl Egress {
    pub(super) fn open(indices: &BTreeSet<u32>) -> Result<Self> {
        let raw = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        };
        ensure!(
            raw >= 0,
            "open experience egress socket: {}",
            io::Error::last_os_error()
        );
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        option(&fd, libc::SOL_PACKET, libc::PACKET_VERSION, &1i32)?;
        let mut code = filter(indices);
        ensure!(
            code.len() <= 4096,
            "experience egress filter exceeds kernel instruction bound"
        );
        let program = libc::sock_fprog {
            len: code.len().try_into()?,
            filter: code.as_mut_ptr(),
        };
        option(&fd, libc::SOL_SOCKET, libc::SO_ATTACH_FILTER, &program)?;
        let request = libc::tpacket_req {
            tp_block_size: 1 << 20,
            tp_block_nr: 4,
            tp_frame_size: FRAME_BYTES as u32,
            tp_frame_nr: (RING_BYTES / FRAME_BYTES) as u32,
        };
        option(&fd, libc::SOL_PACKET, libc::PACKET_RX_RING, &request)?;
        let ring = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                RING_BYTES,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        ensure!(
            ring != libc::MAP_FAILED,
            "map experience egress ring: {}",
            io::Error::last_os_error()
        );
        let capture = Self { fd, ring, frame: 0 };
        let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        address.sll_family = libc::AF_PACKET as u16;
        address.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        ensure!(
            unsafe {
                libc::bind(
                    capture.fd.as_raw_fd(),
                    (&address as *const libc::sockaddr_ll).cast(),
                    std::mem::size_of_val(&address) as libc::socklen_t,
                )
            } == 0,
            "bind experience egress socket: {}",
            io::Error::last_os_error()
        );
        Ok(capture)
    }

    pub(super) fn drain(
        &mut self,
        deadline: Instant,
        mut visit: impl FnMut(u32, u64, u32, &[u8]) -> Result<()>,
    ) -> Result<()> {
        for _ in 0..RING_BYTES / FRAME_BYTES {
            let frame = unsafe { self.ring.cast::<u8>().add(self.frame * FRAME_BYTES) };
            // TPACKET transfers frame ownership through the aligned status word.
            let status = unsafe { &*frame.cast::<AtomicU32>() };
            if status.load(Ordering::Acquire) & 1 == 0 {
                break;
            }
            let result = (|| {
                let header = unsafe { std::ptr::read(frame.cast::<libc::tpacket2_hdr>()) };
                let address = unsafe { std::ptr::read(frame.add(32).cast::<libc::sockaddr_ll>()) };
                let start = usize::from(header.tp_net);
                let length = usize::try_from(header.tp_snaplen)?;
                ensure!(
                    start >= 32 + std::mem::size_of::<libc::sockaddr_ll>()
                        && start + length <= FRAME_BYTES,
                    "invalid experience egress frame"
                );
                ensure!(
                    address.sll_pkttype == libc::PACKET_OUTGOING && address.sll_ifindex > 0,
                    "unexpected experience egress direction"
                );
                let packet = unsafe { std::slice::from_raw_parts(frame.add(start), length) };
                visit(
                    address.sll_ifindex as u32,
                    u64::from(header.tp_sec),
                    header.tp_nsec,
                    packet,
                )
            })();
            status.store(0, Ordering::Release);
            self.frame = (self.frame + 1) % (RING_BYTES / FRAME_BYTES);
            result?;
            if Instant::now() >= deadline {
                break;
            }
        }
        Ok(())
    }

    pub(super) fn take_drops(&self) -> Result<u64> {
        let mut stats = [0u32; 2];
        let mut length = std::mem::size_of_val(&stats) as libc::socklen_t;
        ensure!(
            unsafe {
                libc::getsockopt(
                    self.fd.as_raw_fd(),
                    libc::SOL_PACKET,
                    libc::PACKET_STATISTICS,
                    stats.as_mut_ptr().cast(),
                    &mut length,
                )
            } == 0
                && length as usize == std::mem::size_of_val(&stats),
            "read experience egress loss: {}",
            io::Error::last_os_error()
        );
        Ok(u64::from(stats[1]))
    }
}

impl Drop for Egress {
    fn drop(&mut self) {
        if unsafe { libc::munmap(self.ring, RING_BYTES) } != 0 {
            tracing::error!(error = %io::Error::last_os_error(), "unmap experience egress ring failed");
        }
    }
}
