use anyhow::{Result, ensure};
use netcontrol_core::DNSLookupRequest;
use serde_json::{Value, json};
#[cfg(target_os = "linux")]
use std::net::{SocketAddr, UdpSocket};
use std::{
    io::{Read, Write},
    net::{IpAddr, TcpStream},
    time::{Duration, Instant},
};

fn question(request: &DNSLookupRequest) -> Vec<u8> {
    let mut bytes = Vec::new();
    for label in request.hostname.split('.') {
        bytes.push(label.len() as u8);
        bytes.extend(label.as_bytes());
    }
    bytes.push(0);
    bytes.extend(request.record_type.number().to_be_bytes());
    bytes.extend(1u16.to_be_bytes());
    bytes
}

fn echo(bytes: &[u8], id: u16, question: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() >= 12
            && bytes[..2] == id.to_be_bytes()
            && bytes[2] & 0xf8 == 0x80
            && bytes[4..6] == 1u16.to_be_bytes()
            && bytes.get(12..12 + question.len()) == Some(question),
        "DNS response ID, flags or question mismatch"
    );
    Ok(())
}

fn decode(bytes: &[u8], id: u16, question: &[u8]) -> Result<(u8, Vec<IpAddr>)> {
    echo(bytes, id, question)?;
    ensure!(bytes[2] & 2 == 0, "DNS response remains truncated");
    let rcode = bytes[3] & 15;
    let mut normal = bytes.to_vec();
    normal[3] &= 0xf0;
    let addresses = crate::resolve::parse(&normal, id, question)?;
    Ok((rcode, if rcode == 0 { addresses } else { Vec::new() }))
}

fn remaining(deadline: Instant) -> Result<Duration> {
    let value = deadline.saturating_duration_since(Instant::now());
    ensure!(!value.is_zero(), "DNS query deadline exceeded");
    Ok(value)
}

#[cfg(target_os = "linux")]
fn tcp(address: SocketAddr, interface: Option<&str>, deadline: Instant) -> Result<TcpStream> {
    use std::os::fd::AsRawFd;
    let fd = crate::linux::socket(
        if address.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        },
        libc::SOCK_STREAM,
        0,
    )?;
    if !address.ip().is_loopback() {
        if let Some(interface) = interface {
            crate::linux::bind_device(fd.as_raw_fd(), interface)?;
        }
    }
    let (target, length) = crate::linux::sockaddr(address, 0);
    let result = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&target as *const libc::sockaddr_storage).cast(),
            length,
        )
    };
    if result != 0 {
        ensure!(
            std::io::Error::last_os_error().raw_os_error() == Some(libc::EINPROGRESS),
            "DNS TCP connect: {}",
            std::io::Error::last_os_error()
        );
        let mut poll = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        ensure!(
            unsafe { libc::poll(&mut poll, 1, remaining(deadline)?.as_millis().max(1) as i32) } > 0,
            "DNS TCP connection timed out"
        );
        let mut error = 0i32;
        let mut size = std::mem::size_of_val(&error) as libc::socklen_t;
        crate::linux::check(unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut error as *mut i32).cast(),
                &mut size,
            )
        })?;
        ensure!(
            error == 0,
            "DNS TCP connect: {}",
            std::io::Error::from_raw_os_error(error)
        );
    }
    let stream = TcpStream::from(fd);
    stream.set_nonblocking(false)?;
    Ok(stream)
}

#[cfg(target_os = "linux")]
fn exchange(request: &DNSLookupRequest, server: SocketAddr, deadline: Instant) -> Result<Value> {
    use std::os::fd::AsRawFd;
    let interface = request.interface.as_deref();
    let socket = UdpSocket::bind(if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })?;
    if !server.ip().is_loopback() {
        if let Some(interface) = interface {
            crate::linux::bind_device(socket.as_raw_fd(), interface)?;
        }
    }
    socket.connect(server)?;
    let id = rand::random::<u16>();
    let question = question(request);
    let mut packet = vec![0; 12];
    packet[..2].copy_from_slice(&id.to_be_bytes());
    packet[2] = 1;
    packet[5] = 1;
    packet.extend(&question);
    socket.set_write_timeout(Some(remaining(deadline)?))?;
    let mut started = Instant::now();
    ensure!(socket.send(&packet)? == packet.len(), "short DNS UDP send");
    socket.set_read_timeout(Some(remaining(deadline)?))?;
    let mut response = vec![0; 65535];
    let size = socket.recv(&mut response)?;
    response.truncate(size);
    echo(&response, id, &question)?;
    let mut transport = "udp";
    if response[2] & 2 != 0 {
        transport = "tcp";
        let mut stream = tcp(server, interface, deadline)?;
        let mut frame = (packet.len() as u16).to_be_bytes().to_vec();
        frame.extend(&packet);
        started = Instant::now();
        while !frame.is_empty() {
            stream.set_write_timeout(Some(remaining(deadline)?))?;
            let size = stream.write(&frame)?;
            ensure!(size > 0, "DNS TCP closed during query");
            frame.drain(..size);
        }
        let mut length = [0; 2];
        read_deadline(&mut stream, &mut length, deadline)?;
        let size = usize::from(u16::from_be_bytes(length));
        ensure!(size >= 12, "short DNS TCP message");
        response.resize(size, 0);
        read_deadline(&mut stream, &mut response, deadline)?;
    }
    let rtt = started.elapsed().as_secs_f64() * 1000.0;
    let (rcode, addresses) = decode(&response, id, &question)?;
    Ok(
        json!({"server":server.ip(),"transport":transport,"rcode":rcode,
        "addresses":addresses,"rtt_ms":rtt,"status":"answered","error":null}),
    )
}

fn read_deadline(stream: &mut TcpStream, mut buffer: &mut [u8], deadline: Instant) -> Result<()> {
    while !buffer.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        let size = stream.read(buffer)?;
        ensure!(size > 0, "DNS TCP closed during response");
        buffer = &mut buffer[size..];
    }
    Ok(())
}

pub fn lookup(request: &DNSLookupRequest, servers: &[IpAddr]) -> Result<Value> {
    let mut request = request.clone();
    request.validate()?;
    ensure!(
        !servers.is_empty() && servers.len() <= 16,
        "DNS lookup requires 1..16 configured servers"
    );
    #[cfg(not(target_os = "linux"))]
    {
        let _ = servers;
        anyhow::bail!("native DNS lookup requires Linux");
    }
    #[cfg(target_os = "linux")]
    {
        let started = Instant::now();
        let deadline = started + Duration::from_millis(request.timeout_ms);
        let mut attempts = Vec::new();
        let mut result = json!({"status":"failed","rtt_ms":null,"server":null,"transport":null,"rcode":null,"addresses":[]});
        for (index, server) in servers.iter().enumerate() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            let budget = left / (servers.len() - index) as u32;
            match exchange(&request,SocketAddr::new(*server,53),Instant::now()+budget) {
                Ok(answer)=> {
                    attempts.push(answer.clone());
                    // Negative DNS answers are measured responses, not timeouts.
                    result=answer;
                    break;
                }
                Err(error)=>attempts.push(json!({"server":server,"status":"failed","rtt_ms":null,"error":format!("{error:#}")})),
            }
        }
        result["interface"] = json!(request.interface);
        result["hostname"] = json!(request.hostname);
        result["record_type"] = json!(request.record_type);
        result["elapsed_ms"] = json!(started.elapsed().as_secs_f64() * 1000.0);
        result["attempts"] = json!(attempts);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn negative_answers_have_no_invented_addresses_and_mismatches_fail() {
        let mut request: DNSLookupRequest =
            serde_json::from_str(r#"{"interface":"wan0","hostname":"example.test"}"#).unwrap();
        request.validate().unwrap();
        let question = question(&request);
        let mut reply = vec![0; 12];
        reply[..2].copy_from_slice(&7u16.to_be_bytes());
        reply[2] = 0x81;
        reply[3] = 0x83;
        reply[5] = 1;
        reply.extend(&question);
        assert_eq!(decode(&reply, 7, &question).unwrap(), (3, vec![]));
        assert!(decode(&reply, 8, &question).is_err());
        reply[2] |= 2;
        assert!(decode(&reply, 7, &question).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unanswered_query_obeys_deadline_without_an_rtt() -> Result<()> {
        let server = UdpSocket::bind("127.0.0.1:0")?;
        let request: DNSLookupRequest = serde_json::from_str(
            r#"{"interface":"lo","hostname":"example.test","timeout_ms":100}"#,
        )?;
        let started = Instant::now();
        assert!(
            exchange(
                &request,
                server.local_addr()?,
                started + Duration::from_millis(100)
            )
            .is_err()
        );
        assert!(started.elapsed() < Duration::from_millis(500));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_udp_query_is_timed_and_tcp_truncation_fallback_works() -> Result<()> {
        use std::{net::TcpListener, thread};
        for (truncated, interface) in [
            (false, Some("wan0")),
            (true, Some("wan0")),
            (false, None),
            (true, None),
        ] {
            let udp = UdpSocket::bind("127.0.0.1:0")?;
            let address = udp.local_addr()?;
            let tcp = TcpListener::bind(address)?;
            let fixture = thread::spawn(move || -> Result<()> {
                udp.set_read_timeout(Some(Duration::from_secs(2)))?;
                let mut bytes = [0; 512];
                let (size, peer) = udp.recv_from(&mut bytes)?;
                let mut response = bytes[..size].to_vec();
                response[2] = if truncated { 0x83 } else { 0x81 };
                response[3] = 0x80;
                if !truncated {
                    response[7] = 1;
                    response.extend([0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7]);
                }
                thread::sleep(Duration::from_millis(10));
                udp.send_to(&response, peer)?;
                if truncated {
                    tcp.set_nonblocking(true)?;
                    let deadline = Instant::now() + Duration::from_secs(2);
                    let (mut client, _) = loop {
                        match tcp.accept() {
                            Ok(client) => break client,
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                ensure!(Instant::now() < deadline, "TCP fixture timed out");
                                thread::sleep(Duration::from_millis(2));
                            }
                            Err(error) => return Err(error.into()),
                        }
                    };
                    let mut size = [0; 2];
                    read_deadline(&mut client, &mut size, deadline)?;
                    let mut query = vec![0; usize::from(u16::from_be_bytes(size))];
                    read_deadline(&mut client, &mut query, deadline)?;
                    query[2] = 0x81;
                    query[3] = 0x80;
                    query[7] = 1;
                    query.extend([0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7]);
                    client.write_all(&(query.len() as u16).to_be_bytes())?;
                    client.write_all(&query)?;
                }
                Ok(())
            });
            let mut request: DNSLookupRequest = serde_json::from_value(json!({
                "interface":interface,"hostname":"example.test","server":address.ip()
            }))?;
            request.validate()?;
            let value = exchange(&request, address, Instant::now() + Duration::from_secs(2))?;
            fixture.join().unwrap()?;
            ensure!(
                value["addresses"] == json!(["192.0.2.7"])
                    && value["rtt_ms"].as_f64().is_some_and(|v| v > 0.0),
                "invalid DNS result: {value}"
            );
            ensure!(
                value["transport"] == if truncated { "tcp" } else { "udp" },
                "wrong DNS transport"
            );
            if !truncated {
                ensure!(
                    value["rtt_ms"].as_f64().is_some_and(|v| v >= 8.0),
                    "DNS RTT did not include fixture delay"
                );
            }
        }
        Ok(())
    }
}
