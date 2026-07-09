// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use super::model::{ProcScan, Protocol, SocketEntry};

pub(crate) fn scan_proc() -> io::Result<ProcScan> {
    let mut sockets = Vec::new();
    for (path, protocol, ipv6) in [
        ("/proc/net/tcp", Protocol::Tcp, false),
        ("/proc/net/tcp6", Protocol::Tcp, true),
        ("/proc/net/udp", Protocol::Udp, false),
        ("/proc/net/udp6", Protocol::Udp, true),
    ] {
        match parse_proc_net_file(Path::new(path), protocol, ipv6) {
            Ok(mut entries) => sockets.append(&mut entries),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }

    let inodes: BTreeSet<u64> = sockets.iter().map(|socket| socket.inode).collect();
    let (owners, stats) = super::owners::map_socket_owners(Path::new("/proc"), &inodes);
    Ok((sockets, owners, stats))
}

fn parse_proc_net_file(
    path: &Path,
    protocol: Protocol,
    ipv6: bool,
) -> io::Result<Vec<SocketEntry>> {
    let content = fs::read_to_string(path)?;
    Ok(parse_proc_net_content(&content, protocol, ipv6))
}

pub fn parse_proc_net_content(content: &str, protocol: Protocol, ipv6: bool) -> Vec<SocketEntry> {
    content
        .lines()
        .skip(1)
        .filter_map(|line| parse_proc_net_line(line, protocol, ipv6))
        .collect()
}

pub fn parse_proc_net_line(line: &str, protocol: Protocol, ipv6: bool) -> Option<SocketEntry> {
    let columns: Vec<&str> = line.split_whitespace().collect();
    let local = *columns.get(1)?;
    let remote = *columns.get(2)?;
    let state_code = *columns.get(3)?;
    let inode = columns.get(9)?.parse().ok()?;
    let (address, port) = parse_local_address(local, ipv6)?;
    let (remote_address, remote_port) = parse_local_address(remote, ipv6).unwrap_or_default();
    let state = match protocol {
        Protocol::Tcp => Some(tcp_state_name(state_code).to_owned()),
        Protocol::Udp => None,
    };

    Some(SocketEntry {
        protocol,
        address,
        port,
        remote_address,
        remote_port,
        state,
        inode,
    })
}

pub fn parse_local_address(input: &str, ipv6: bool) -> Option<(String, u16)> {
    let (address_hex, port_hex) = input.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let address = if ipv6 {
        parse_ipv6_address(address_hex)?
    } else {
        parse_ipv4_address(address_hex)?
    };
    Some((address, port))
}

fn parse_ipv4_address(input: &str) -> Option<String> {
    if input.len() != 8 {
        return None;
    }

    let raw = u32::from_str_radix(input, 16).ok()?;
    Some(Ipv4Addr::from(raw.to_le_bytes()).to_string())
}

fn parse_ipv6_address(input: &str) -> Option<String> {
    if input.len() != 32 {
        return None;
    }

    let mut bytes = [0_u8; 16];
    for (chunk_index, chunk) in input.as_bytes().chunks(8).enumerate() {
        let chunk = std::str::from_utf8(chunk).ok()?;
        let value = u32::from_str_radix(chunk, 16).ok()?;
        let start = chunk_index * 4;
        bytes[start..start + 4].copy_from_slice(&value.to_le_bytes());
    }
    Some(Ipv6Addr::from(bytes).to_string())
}

pub fn is_tcp_listen(state: Option<&str>) -> bool {
    state == Some("LISTEN")
}

fn tcp_state_name(state: &str) -> &'static str {
    match state {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_local_address_hex_and_port() {
        assert_eq!(
            parse_local_address("0100007F:0BB8", false),
            Some(("127.0.0.1".to_owned(), 3000))
        );
    }

    #[test]
    fn parses_ipv6_line_without_panicking() {
        let line = "0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 42 1 0000000000000000 100 0 0 10 0";
        let entry = parse_proc_net_line(line, Protocol::Tcp, true).unwrap();
        assert_eq!(entry.port, 8080);
        assert_eq!(entry.state, Some("LISTEN".to_owned()));
    }

    #[test]
    fn detects_tcp_listen_state() {
        let line = "0: 0100007F:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345 1 0000000000000000 100 0 0 10 0";
        let entry = parse_proc_net_line(line, Protocol::Tcp, false).unwrap();
        assert!(is_tcp_listen(entry.state.as_deref()));
    }
}
