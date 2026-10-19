use anyhow::{Context, Result, ensure};
use std::{
    ffi::CString,
    io, mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::{FromRawFd, OwnedFd, RawFd},
};

pub(crate) fn check(result: i32) -> Result<i32> {
    if result < 0 {
        Err(io::Error::last_os_error().into())
    } else {
        Ok(result)
    }
}
pub(crate) fn socket(family: i32, kind: i32, protocol: i32) -> Result<OwnedFd> {
    let fd = check(unsafe {
        libc::socket(
            family,
            kind | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            protocol,
        )
    })?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
pub(crate) fn option<T>(fd: RawFd, level: i32, key: i32, value: &T) -> Result<()> {
    check(unsafe {
        libc::setsockopt(
            fd,
            level,
            key,
            value as *const T as *const libc::c_void,
            mem::size_of::<T>() as libc::socklen_t,
        )
    })?;
    Ok(())
}
pub(crate) fn ifindex(name: &str) -> Result<u32> {
    let name = CString::new(name)?;
    let idx = unsafe { libc::if_nametoindex(name.as_ptr()) };
    ensure!(
        idx != 0,
        "interface unavailable: {}",
        io::Error::last_os_error()
    );
    Ok(idx)
}
pub(crate) fn bind_device(fd: RawFd, name: &str) -> Result<()> {
    let name = CString::new(name)?;
    check(unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr() as *const _,
            name.as_bytes_with_nul().len() as libc::socklen_t,
        )
    })?;
    Ok(())
}
pub(crate) fn sockaddr(
    address: SocketAddr,
    scope: u32,
) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let len = match address {
        SocketAddr::V4(a) => {
            let p = &mut storage as *mut _ as *mut libc::sockaddr_in;
            unsafe {
                (*p).sin_family = libc::AF_INET as u16;
                (*p).sin_port = a.port().to_be();
                (*p).sin_addr.s_addr = u32::from_ne_bytes(a.ip().octets());
            }
            mem::size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(a) => {
            let p = &mut storage as *mut _ as *mut libc::sockaddr_in6;
            unsafe {
                (*p).sin6_family = libc::AF_INET6 as u16;
                (*p).sin6_port = a.port().to_be();
                (*p).sin6_addr.s6_addr = a.ip().octets();
                (*p).sin6_scope_id = scope;
            }
            mem::size_of::<libc::sockaddr_in6>()
        }
    };
    (storage, len as libc::socklen_t)
}
pub(crate) fn from_sockaddr(storage: &libc::sockaddr_storage) -> Result<SocketAddr> {
    match storage.ss_family as i32 {
        libc::AF_INET => {
            let a = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            Ok(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(a.sin_addr.s_addr.to_ne_bytes())),
                u16::from_be(a.sin_port),
            ))
        }
        libc::AF_INET6 => {
            let a = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            Ok(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(a.sin6_addr.s6_addr)),
                u16::from_be(a.sin6_port),
            ))
        }
        _ => anyhow::bail!("unexpected socket address family"),
    }
}
pub(crate) fn bind(fd: RawFd, address: SocketAddr, scope: u32) -> Result<()> {
    let (a, len) = sockaddr(address, scope);
    check(unsafe { libc::bind(fd, &a as *const _ as *const libc::sockaddr, len) })?;
    Ok(())
}
pub(crate) fn send(fd: RawFd, payload: &[u8], address: SocketAddr, scope: u32) -> Result<()> {
    let (a, len) = sockaddr(address, scope);
    let n = unsafe {
        libc::sendto(
            fd,
            payload.as_ptr() as *const _,
            payload.len(),
            libc::MSG_NOSIGNAL,
            &a as *const _ as *const libc::sockaddr,
            len,
        )
    };
    ensure!(n >= 0, "socket send: {}", io::Error::last_os_error());
    ensure!(n as usize == payload.len(), "short socket send");
    Ok(())
}
pub(crate) fn recv(fd: RawFd, buffer: &mut [u8]) -> Result<Option<(usize, SocketAddr)>> {
    let mut a: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut len = mem::size_of_val(&a) as libc::socklen_t;
    let n = unsafe {
        libc::recvfrom(
            fd,
            buffer.as_mut_ptr() as *mut _,
            buffer.len(),
            libc::MSG_TRUNC,
            &mut a as *mut _ as *mut libc::sockaddr,
            &mut len,
        )
    };
    if n < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::Interrupted {
            return Ok(None);
        }
        return Err(e.into());
    }
    ensure!(n as usize <= buffer.len(), "truncated socket datagram");
    Ok(Some((n as usize, from_sockaddr(&a)?)))
}
pub(crate) fn capabilities(bit: u32) -> Result<()> {
    let text = std::fs::read_to_string("/proc/self/status")?;
    let caps = text
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:\t"))
        .context("CapEff missing")?;
    let caps = u64::from_str_radix(caps.trim(), 16)?;
    ensure!(
        caps & (1u64 << bit) != 0,
        "required Linux capability {bit} missing"
    );
    Ok(())
}
pub(crate) fn interface_snapshot(name: &str) -> Result<(u32, Vec<IpAddr>)> {
    let index = ifindex(name)?;
    let mut first = std::ptr::null_mut();
    check(unsafe { libc::getifaddrs(&mut first) })?;
    struct Guard(*mut libc::ifaddrs);
    impl Drop for Guard {
        fn drop(&mut self) {
            unsafe { libc::freeifaddrs(self.0) }
        }
    }
    let _guard = Guard(first);
    let mut p = first;
    let mut ips = Vec::new();
    let mut up = false;
    while !p.is_null() {
        let a = unsafe { &*p };
        if !a.ifa_name.is_null()
            && unsafe { std::ffi::CStr::from_ptr(a.ifa_name) }.to_bytes() == name.as_bytes()
        {
            up |= a.ifa_flags & libc::IFF_UP as u32 != 0;
            if !a.ifa_addr.is_null() {
                let family = unsafe { (*a.ifa_addr).sa_family } as i32;
                match family {
                    libc::AF_INET => {
                        let v = unsafe { &*(a.ifa_addr as *const libc::sockaddr_in) };
                        ips.push(IpAddr::V4(Ipv4Addr::from(v.sin_addr.s_addr.to_ne_bytes())));
                    }
                    libc::AF_INET6 => {
                        let v = unsafe { &*(a.ifa_addr as *const libc::sockaddr_in6) };
                        ips.push(IpAddr::V6(Ipv6Addr::from(v.sin6_addr.s6_addr)));
                    }
                    _ => {}
                }
            }
        }
        p = a.ifa_next;
    }
    ensure!(up, "interface {name} is down");
    Ok((index, ips))
}
