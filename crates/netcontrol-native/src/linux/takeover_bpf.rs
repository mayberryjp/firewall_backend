use anyhow::{Result, ensure};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

#[repr(C)]
#[derive(Default)]
struct Query {
    interface: u32,
    attach_type: u32,
    query_flags: u32,
    attach_flags: u32,
    programs: u64,
    count: u32,
    padding: u32,
    program_flags: u64,
    links: u64,
    link_flags: u64,
    revision: u64,
}

fn query(interface: u32, attach_type: u32) -> Result<Vec<(u32, u32)>> {
    let mut capacity = 0usize;
    loop {
        let mut programs = vec![0u32; capacity];
        let mut links = vec![0u32; capacity];
        let mut query = Query {
            interface,
            attach_type,
            count: capacity.try_into()?,
            programs: if capacity == 0 {
                0
            } else {
                programs.as_mut_ptr() as u64
            },
            links: if capacity == 0 {
                0
            } else {
                links.as_mut_ptr() as u64
            },
            ..Default::default()
        };
        let status =
            unsafe { libc::syscall(libc::SYS_bpf, 16, &mut query, std::mem::size_of::<Query>()) };
        if status < 0 {
            let error = std::io::Error::last_os_error();
            // Older kernels without TCX cannot have TCX attachments.
            if matches!(error.raw_os_error(), Some(libc::EINVAL | libc::EOPNOTSUPP)) {
                return Ok(Vec::new());
            }
            if error.raw_os_error() != Some(libc::ENOSPC) {
                return Err(error.into());
            }
        }
        if query.count as usize <= capacity {
            ensure!(status == 0, "TCX query failed");
            programs.truncate(query.count as usize);
            links.truncate(query.count as usize);
            return Ok(programs.into_iter().zip(links).collect());
        }
        capacity = query.count as usize;
        ensure!(
            capacity <= 65536,
            "TCX attachment count exceeds capture bound"
        );
    }
}

pub(super) fn capture(interface: u32) -> Result<Vec<(u32, u32, u32)>> {
    let mut attachments = Vec::new();
    for hook in [46, 47] {
        attachments.extend(
            query(interface, hook)?
                .into_iter()
                .map(|(program, link)| (hook, program, link)),
        );
    }
    Ok(attachments)
}

fn open_id(command: i32, id: u32) -> Result<OwnedFd> {
    let input = [id, 0u32, 0u32];
    let raw = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            command,
            input.as_ptr(),
            std::mem::size_of_val(&input),
        )
    };
    ensure!(
        raw >= 0,
        "open unsupported BPF attachment {id}: {}",
        std::io::Error::last_os_error()
    );
    Ok(unsafe { OwnedFd::from_raw_fd(i32::try_from(raw)?) })
}

pub(super) fn clear(interface: u32) -> Result<()> {
    for (hook, program, link) in capture(interface)? {
        let result = if link != 0 {
            let fd = open_id(30, link)?;
            let input = [fd.as_raw_fd() as u32];
            unsafe {
                libc::syscall(
                    libc::SYS_bpf,
                    34,
                    input.as_ptr(),
                    std::mem::size_of_val(&input),
                )
            }
        } else {
            let fd = open_id(13, program)?;
            let input = [interface, fd.as_raw_fd() as u32, hook, 0u32];
            unsafe {
                libc::syscall(
                    libc::SYS_bpf,
                    9,
                    input.as_ptr(),
                    std::mem::size_of_val(&input),
                )
            }
        };
        ensure!(
            result == 0,
            "detach unsupported TCX program {program}: {}",
            std::io::Error::last_os_error()
        );
    }
    ensure!(
        capture(interface)?.is_empty(),
        "TCX attachments remain after takeover"
    );
    Ok(())
}
