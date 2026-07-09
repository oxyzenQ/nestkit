// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Network interfaces, addresses, statistics, routes, and resolver.

use std::error::Error;
use std::fs;
use std::path::Path;

const SYS_CLASS_NET: &str = "/sys/class/net";
const PROC_NET_ROUTE: &str = "/proc/net/route";
const PROC_NET_IF_INET6: &str = "/proc/net/if_inet6";
const PROC_NET_ARP: &str = "/proc/net/arp";
const RESOLV_CONF: &str = "/etc/resolv.conf";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceEntry {
    pub name: String,
    pub state: Option<String>,
    pub mtu: Option<u32>,
    pub mac: Option<String>,
    pub flags: Option<u32>,
    pub iftype: Option<u32>,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
    pub rx_packets: Option<u64>,
    pub tx_packets: Option<u64>,
    pub rx_errors: Option<u64>,
    pub tx_errors: Option<u64>,
    pub rx_dropped: Option<u64>,
    pub tx_dropped: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpEntry {
    pub ip: String,
    pub hw_type: String,
    pub flags: String,
    pub mac: String,
    pub iface: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    pub iface: String,
    pub destination: String,
    pub gateway: String,
    pub flags: String,
    pub metric: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverConfig {
    pub nameservers: Vec<String>,
    pub search: Vec<String>,
    pub options: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetReport {
    pub interfaces: Vec<InterfaceEntry>,
    pub arp_neighbors: Vec<ArpEntry>,
    pub routes: Vec<RouteEntry>,
    pub default_route: Option<String>,
    pub resolver: Option<ResolverConfig>,
}

pub fn run() -> Result<(), Box<dyn Error>> {
    let report = collect_report();
    println!("{}", render_report(&report));
    Ok(())
}

fn collect_report() -> NetReport {
    let interfaces = read_interfaces();
    let arp_neighbors = read_arp();
    let routes = read_routes();
    let default_route = routes
        .iter()
        .find(|r| r.destination == "default")
        .map(|r| r.iface.clone());
    let resolver = read_resolver_config();

    NetReport {
        interfaces,
        arp_neighbors,
        routes,
        default_route,
        resolver,
    }
}

fn read_interfaces() -> Vec<InterfaceEntry> {
    let dir = match fs::read_dir(SYS_CLASS_NET) {
        Ok(d) => d,
        Err(_) => return vec![],
    };

    let mut entries: Vec<InterfaceEntry> = Vec::new();
    for entry in dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let iface_path = entry.path();

        let state = read_sysfs_str(&iface_path, "operstate");
        let mtu = read_sysfs_u32(&iface_path, "mtu");
        let mac = read_sysfs_str(&iface_path, "address");
        let flags = read_sysfs_u32(&iface_path, "flags");
        let iftype = read_sysfs_u32(&iface_path, "type");

        // Stats
        let rx_bytes = read_sysfs_u64(&iface_path, "statistics/rx_bytes");
        let tx_bytes = read_sysfs_u64(&iface_path, "statistics/tx_bytes");
        let rx_packets = read_sysfs_u64(&iface_path, "statistics/rx_packets");
        let tx_packets = read_sysfs_u64(&iface_path, "statistics/tx_packets");
        let rx_errors = read_sysfs_u64(&iface_path, "statistics/rx_errors");
        let tx_errors = read_sysfs_u64(&iface_path, "statistics/tx_errors");
        let rx_dropped = read_sysfs_u64(&iface_path, "statistics/rx_dropped");
        let tx_dropped = read_sysfs_u64(&iface_path, "statistics/tx_dropped");

        // Addresses — try IPv4 via /proc/net/fib_trie is complex; use if_inet6 for v6
        // For IPv4, fall back to parsing /proc/net/fib_trie (local IPs marked LOCAL)
        let ipv4 = read_ipv4_addresses(&name);
        let ipv6 = read_ipv6_addresses(&name);

        entries.push(InterfaceEntry {
            name,
            state,
            mtu,
            mac,
            flags,
            iftype,
            ipv4,
            ipv6,
            rx_bytes,
            tx_bytes,
            rx_packets,
            tx_packets,
            rx_errors,
            tx_errors,
            rx_dropped,
            tx_dropped,
        });
    }

    entries.sort_by(|a, b| a.name.cmp(&b.name));
    entries
}

fn read_sysfs_str(iface_path: &Path, file: &str) -> Option<String> {
    let path = iface_path.join(file);
    let content = fs::read_to_string(path).ok()?;
    let trimmed = content.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn read_sysfs_u32(iface_path: &Path, file: &str) -> Option<u32> {
    let path = iface_path.join(file);
    let content = fs::read_to_string(path).ok()?;
    content.trim().parse::<u32>().ok()
}

fn read_sysfs_u64(iface_path: &Path, file: &str) -> Option<u64> {
    let path = iface_path.join(file);
    let content = fs::read_to_string(path).ok()?;
    content.trim().parse::<u64>().ok()
}

/// Parse /proc/net/if_inet6 to get IPv6 addresses per interface.
/// Format: addr_index prefix_len scope flags ifname
/// addr is 32 hex chars (no colons).
fn read_ipv6_addresses(iface_name: &str) -> Vec<String> {
    let mut addrs = Vec::new();
    let Ok(content) = fs::read_to_string(PROC_NET_IF_INET6) else {
        return addrs;
    };
    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        if fields[5] != iface_name {
            continue;
        }
        let raw = fields[0];
        if raw.len() != 32 {
            continue;
        }
        // Insert colon every 4 chars to form standard IPv6 notation
        let mut formatted = String::with_capacity(39);
        for (i, c) in raw.chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                formatted.push(':');
            }
            formatted.push(c);
        }
        // Could canonicalize (compress zeros) but raw form is fine for display
        addrs.push(formatted);
    }
    addrs
}

/// Parse /proc/net/fib_trie to extract IPv4 addresses assigned to interfaces.
/// This is a best-effort heuristic: the file's structure is a tree of leaf
/// nodes with /32 host addresses marked "LOCAL". We pick unique LOCAL IPs.
fn read_ipv4_addresses(_iface_name: &str) -> Vec<String> {
    let mut addrs = Vec::new();
    let Ok(content) = fs::read_to_string("/proc/net/fib_trie") else {
        return addrs;
    };
    // Walk lines looking for "32 host LOCAL" preceded by an IP-like string.
    // This is fragile but works on Linux 4.x+.
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;
    while i + 1 < lines.len() {
        let _cur = lines[i].trim();
        let next = lines[i + 1].trim();
        // Pattern: "32 host LOCAL" follows an IP-containing line.
        // We look for the IP in the line *before* the "32 host LOCAL" line.
        if next.contains("32 host") && next.contains("LOCAL") {
            // Walk backwards to find a line that looks like an IP
            if i > 0 {
                let candidate = lines[i - 1].trim();
                if let Some(ip) = extract_ip_from_fib_line(candidate) {
                    if !addrs.contains(&ip) && ip != "127.0.0.1" && ip != "0.0.0.0" {
                        addrs.push(ip);
                    }
                }
            }
        }
        i += 1;
    }
    addrs
}

fn extract_ip_from_fib_line(line: &str) -> Option<String> {
    // Lines look like: "|--127.0.0.1" or "127.0.0.1" or just an IP
    let trimmed = line
        .trim_start_matches("|--")
        .trim_start_matches("|")
        .trim();
    if trimmed.is_empty() {
        return None;
    }
    // Take first whitespace-separated token
    let token = trimmed.split_whitespace().next()?;
    // Validate it's an IPv4
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    for p in parts {
        if p.parse::<u8>().is_err() {
            return None;
        }
    }
    Some(token.to_owned())
}

/// Read /proc/net/arp for L2 neighbors.
fn read_arp() -> Vec<ArpEntry> {
    let mut entries = Vec::new();
    let Ok(content) = fs::read_to_string(PROC_NET_ARP) else {
        return entries;
    };
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        entries.push(ArpEntry {
            ip: fields[0].to_owned(),
            hw_type: fields[1].to_owned(),
            flags: fields[2].to_owned(),
            mac: fields[3].to_owned(),
            iface: fields[5].to_owned(),
        });
    }
    entries
}

/// Read /proc/net/route (IPv4 routing table).
fn read_routes() -> Vec<RouteEntry> {
    let mut routes = Vec::new();
    let Ok(content) = fs::read_to_string(PROC_NET_ROUTE) else {
        return routes;
    };
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 {
            continue;
        }
        let iface = fields[0].to_owned();
        let dest_hex = fields[1];
        let gw_hex = fields[2];
        let flags = fields[3].to_owned();
        let metric = fields[6].parse::<u32>().ok();

        let destination = if dest_hex == "00000000" {
            "default".to_owned()
        } else {
            hex_to_ipv4(dest_hex).unwrap_or_else(|| dest_hex.to_owned())
        };
        let gateway = if gw_hex == "00000000" {
            "0.0.0.0".to_owned()
        } else {
            hex_to_ipv4(gw_hex).unwrap_or_else(|| gw_hex.to_owned())
        };

        routes.push(RouteEntry {
            iface,
            destination,
            gateway,
            flags,
            metric,
        });
    }
    routes
}

/// Convert little-endian hex (from /proc/net/route) to dotted IPv4.
fn hex_to_ipv4(hex: &str) -> Option<String> {
    if hex.len() != 8 {
        return None;
    }
    let n = u32::from_str_radix(hex, 16).ok()?;
    // /proc/net/route stores IPs in little-endian (network byte order in reverse)
    let a = (n & 0xFF) as u8;
    let b = ((n >> 8) & 0xFF) as u8;
    let c = ((n >> 16) & 0xFF) as u8;
    let d = ((n >> 24) & 0xFF) as u8;
    Some(format!("{a}.{b}.{c}.{d}"))
}

/// Parse /etc/resolv.conf for nameservers, search domains, options.
fn read_resolver_config() -> Option<ResolverConfig> {
    let content = fs::read_to_string(RESOLV_CONF).ok()?;
    let mut nameservers = Vec::new();
    let mut search = Vec::new();
    let mut options = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        match parts.next() {
            Some("nameserver") => {
                if let Some(ns) = parts.next() {
                    nameservers.push(ns.to_owned());
                }
            }
            Some("search") => {
                search.extend(parts.map(str::to_owned));
            }
            Some("options") => {
                options.extend(parts.map(str::to_owned));
            }
            _ => {}
        }
    }
    Some(ResolverConfig {
        nameservers,
        search,
        options,
    })
}

pub fn render_report(report: &NetReport) -> String {
    let mut lines = vec!["net".to_owned()];

    let has_arp = !report.arp_neighbors.is_empty();
    let has_routes = !report.routes.is_empty();
    let has_resolver = report.resolver.is_some();
    let has_more = has_arp || has_routes || has_resolver;

    render_interfaces_section(&mut lines, report, has_more);
    render_arp_section(&mut lines, report, has_routes || has_resolver);
    render_routes_section(&mut lines, report, has_resolver);
    render_resolver_section(&mut lines, report);

    lines.join("\n")
}

fn render_interfaces_section(lines: &mut Vec<String>, report: &NetReport, has_more: bool) {
    let branch = if has_more { "├" } else { "└" };
    lines.push(format!("{branch}── interfaces"));
    let indent = if has_more { "│" } else { " " };

    if report.interfaces.is_empty() {
        lines.push(format!("{indent}   └── none visible"));
        return;
    }

    for (i, iface) in report.interfaces.iter().enumerate() {
        let is_last = i + 1 == report.interfaces.len();
        let leaf = if is_last { "└" } else { "├" };
        let leaf_indent = if is_last { " " } else { "│" };
        lines.push(format!(
            "{indent}   {leaf}── {}",
            format_iface_summary(iface)
        ));
        // Render address + stats sub-rows
        render_iface_details(lines, iface, &format!("{indent}   {leaf_indent}   "));
    }
}

fn render_iface_details(lines: &mut Vec<String>, iface: &InterfaceEntry, prefix: &str) {
    let mut sub: Vec<String> = Vec::new();
    for ip in &iface.ipv4 {
        sub.push(format!("ipv4 {ip}"));
    }
    for ip in &iface.ipv6 {
        sub.push(format!("ipv6 {ip}"));
    }
    if let Some(flags) = iface.flags {
        let flag_str = decode_flags(flags);
        if !flag_str.is_empty() {
            sub.push(format!("flags {flag_str}"));
        }
        if flags & 0x100 != 0 {
            sub.push("⚠ promiscuous-mode".to_owned());
        }
    }
    if let (Some(rx), Some(tx)) = (iface.rx_bytes, iface.tx_bytes) {
        sub.push(format!("rx {} tx {}", human_bytes(rx), human_bytes(tx)));
    }
    if let (Some(rxp), Some(txp)) = (iface.rx_packets, iface.tx_packets) {
        sub.push(format!("pkts rx={rxp} tx={txp}"));
    }
    let total_errors = iface.rx_errors.unwrap_or(0) + iface.tx_errors.unwrap_or(0);
    let total_drops = iface.rx_dropped.unwrap_or(0) + iface.tx_dropped.unwrap_or(0);
    if total_errors > 0 || total_drops > 0 {
        sub.push(format!("errors={total_errors} drops={total_drops}"));
    }

    for (i, line) in sub.iter().enumerate() {
        let is_last = i + 1 == sub.len();
        let leaf = if is_last { "└" } else { "├" };
        lines.push(format!("{prefix}{leaf}── {line}"));
    }
}

fn decode_flags(flags: u32) -> String {
    let mut parts = Vec::new();
    if flags & 0x1 != 0 {
        parts.push("UP");
    }
    if flags & 0x2 != 0 {
        parts.push("BROADCAST");
    }
    if flags & 0x8 != 0 {
        parts.push("LOOPBACK");
    }
    if flags & 0x10 != 0 {
        parts.push("POINTOPOINT");
    }
    if flags & 0x40 != 0 {
        parts.push("RUNNING");
    }
    if flags & 0x100 != 0 {
        parts.push("PROMISC");
    }
    if flags & 0x1000 != 0 {
        parts.push("MULTICAST");
    }
    parts.join(",")
}

fn format_iface_summary(iface: &InterfaceEntry) -> String {
    let mut parts = vec![iface.name.clone()];
    if let Some(ref state) = iface.state {
        parts.push(state.clone());
    }
    if let Some(mtu) = iface.mtu {
        parts.push(format!("mtu={mtu}"));
    }
    if let Some(ref mac) = iface.mac {
        // Skip MAC for loopback (00:00:00:00:00:00)
        if mac != "00:00:00:00:00:00" {
            parts.push(format!("mac={mac}"));
        }
    }
    parts.join(" ")
}

fn render_arp_section(lines: &mut Vec<String>, report: &NetReport, has_more: bool) {
    let branch = if has_more { "├" } else { "└" };
    lines.push(format!("{branch}── arp-neighbors"));
    let indent = if has_more { "│" } else { " " };

    if report.arp_neighbors.is_empty() {
        lines.push(format!("{indent}   └── none visible"));
        return;
    }
    for (i, entry) in report.arp_neighbors.iter().enumerate() {
        let is_last = i + 1 == report.arp_neighbors.len();
        let leaf = if is_last { "└" } else { "├" };
        lines.push(format!(
            "{indent}   {leaf}── {} {} {}",
            entry.ip, entry.mac, entry.iface
        ));
    }
}

fn render_routes_section(lines: &mut Vec<String>, report: &NetReport, has_more: bool) {
    let branch = if has_more { "├" } else { "└" };
    lines.push(format!("{branch}── routes"));
    let indent = if has_more { "│" } else { " " };

    if report.routes.is_empty() {
        lines.push(format!("{indent}   └── none visible"));
        return;
    }
    for (i, route) in report.routes.iter().enumerate() {
        let is_last = i + 1 == report.routes.len();
        let leaf = if is_last { "└" } else { "├" };
        let metric_str = route
            .metric
            .map(|m| format!(" metric={m}"))
            .unwrap_or_default();
        lines.push(format!(
            "{indent}   {leaf}── {} via {} {}{metric_str}",
            route.destination, route.gateway, route.iface
        ));
    }
}

fn render_resolver_section(lines: &mut Vec<String>, report: &NetReport) {
    lines.push("└── resolver".to_owned());
    match &report.resolver {
        None => {
            lines.push("    └── /etc/resolv.conf missing".to_owned());
        }
        Some(cfg) => {
            if cfg.nameservers.is_empty() && cfg.search.is_empty() && cfg.options.is_empty() {
                lines.push("    └── /etc/resolv.conf empty".to_owned());
            } else {
                let mut sub: Vec<String> = Vec::new();
                for ns in &cfg.nameservers {
                    sub.push(format!("nameserver {ns}"));
                }
                if !cfg.search.is_empty() {
                    sub.push(format!("search {}", cfg.search.join(" ")));
                }
                if !cfg.options.is_empty() {
                    sub.push(format!("options {}", cfg.options.join(" ")));
                }
                for (i, line) in sub.iter().enumerate() {
                    let is_last = i + 1 == sub.len();
                    let leaf = if is_last { "└" } else { "├" };
                    lines.push(format!("    {leaf}── {line}"));
                }
            }
        }
    }
}

fn human_bytes(b: u64) -> String {
    if b >= 1024 * 1024 * 1024 {
        format!("{:.2}GB", b as f64 / 1024.0 / 1024.0 / 1024.0)
    } else if b >= 1024 * 1024 {
        format!("{:.1}MB", b as f64 / 1024.0 / 1024.0)
    } else if b >= 1024 {
        format!("{:.1}KB", b as f64 / 1024.0)
    } else {
        format!("{b}B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_to_ipv4_decodes_little_endian() {
        // 0x0100007F in little-endian = 127.0.0.1
        assert_eq!(hex_to_ipv4("0100007F"), Some("127.0.0.1".to_owned()));
        // 0x00000000 = 0.0.0.0
        assert_eq!(hex_to_ipv4("00000000"), Some("0.0.0.0".to_owned()));
        // Invalid length
        assert_eq!(hex_to_ipv4("abc"), None);
    }

    #[test]
    fn decode_flags_includes_up_and_promisc() {
        let flags = 0x1 | 0x100; // UP | PROMISC
        let decoded = decode_flags(flags);
        assert!(decoded.contains("UP"));
        assert!(decoded.contains("PROMISC"));
    }

    #[test]
    fn decode_flags_loopback_only() {
        let decoded = decode_flags(0x8 | 0x1 | 0x40); // LOOPBACK | UP | RUNNING
        assert!(decoded.contains("LOOPBACK"));
        assert!(decoded.contains("UP"));
        assert!(decoded.contains("RUNNING"));
        assert!(!decoded.contains("PROMISC"));
    }

    #[test]
    fn human_bytes_formats_correctly() {
        assert_eq!(human_bytes(0), "0B");
        assert_eq!(human_bytes(512), "512B");
        assert_eq!(human_bytes(1024), "1.0KB");
        assert_eq!(human_bytes(1024 * 1024), "1.0MB");
        assert_eq!(human_bytes(1024 * 1024 * 1024), "1.00GB");
    }

    #[test]
    fn format_iface_summary_skips_zero_mac() {
        let iface = InterfaceEntry {
            name: "lo".to_owned(),
            state: Some("unknown".to_owned()),
            mtu: Some(65536),
            mac: Some("00:00:00:00:00:00".to_owned()),
            flags: None,
            iftype: None,
            ipv4: vec![],
            ipv6: vec![],
            rx_bytes: None,
            tx_bytes: None,
            rx_packets: None,
            tx_packets: None,
            rx_errors: None,
            tx_errors: None,
            rx_dropped: None,
            tx_dropped: None,
        };
        let s = format_iface_summary(&iface);
        assert!(!s.contains("mac="));
        assert!(s.contains("lo unknown mtu=65536"));
    }

    #[test]
    fn render_full_report_has_all_sections() {
        let report = NetReport {
            interfaces: vec![InterfaceEntry {
                name: "eth0".to_owned(),
                state: Some("up".to_owned()),
                mtu: Some(1500),
                mac: Some("aa:bb:cc:dd:ee:ff".to_owned()),
                flags: Some(0x1 | 0x40 | 0x100), // UP | RUNNING | PROMISC
                iftype: Some(1),
                ipv4: vec!["10.0.0.5".to_owned()],
                ipv6: vec!["fe80::1".to_owned()],
                rx_bytes: Some(123456),
                tx_bytes: Some(654321),
                rx_packets: Some(100),
                tx_packets: Some(200),
                rx_errors: Some(0),
                tx_errors: Some(0),
                rx_dropped: Some(0),
                tx_dropped: Some(0),
            }],
            arp_neighbors: vec![ArpEntry {
                ip: "10.0.0.1".to_owned(),
                hw_type: "0x1".to_owned(),
                flags: "0x2".to_owned(),
                mac: "ff:ff:ff:ff:ff:ff".to_owned(),
                iface: "eth0".to_owned(),
            }],
            routes: vec![RouteEntry {
                iface: "eth0".to_owned(),
                destination: "default".to_owned(),
                gateway: "10.0.0.1".to_owned(),
                flags: "0003".to_owned(),
                metric: Some(100),
            }],
            default_route: Some("eth0".to_owned()),
            resolver: Some(ResolverConfig {
                nameservers: vec!["8.8.8.8".to_owned()],
                search: vec!["example.com".to_owned()],
                options: vec!["timeout:5".to_owned()],
            }),
        };
        let out = render_report(&report);
        assert!(out.contains("interfaces"));
        assert!(out.contains("eth0 up mtu=1500 mac=aa:bb:cc:dd:ee:ff"));
        assert!(out.contains("ipv4 10.0.0.5"));
        assert!(out.contains("ipv6 fe80::1"));
        assert!(out.contains("PROMISC"));
        assert!(out.contains("rx 120.6KB tx 639.0KB"));
        assert!(out.contains("pkts rx=100 tx=200"));
        assert!(out.contains("arp-neighbors"));
        assert!(out.contains("10.0.0.1 ff:ff:ff:ff:ff:ff eth0"));
        assert!(out.contains("routes"));
        assert!(out.contains("default via 10.0.0.1 eth0 metric=100"));
        assert!(out.contains("resolver"));
        assert!(out.contains("nameserver 8.8.8.8"));
        assert!(out.contains("search example.com"));
        assert!(out.contains("options timeout:5"));
    }

    #[test]
    fn render_empty_report() {
        let report = NetReport {
            interfaces: vec![],
            arp_neighbors: vec![],
            routes: vec![],
            default_route: None,
            resolver: None,
        };
        let out = render_report(&report);
        assert!(out.contains("interfaces"));
        assert!(out.contains("none visible"));
        assert!(out.contains("resolver"));
        assert!(out.contains("missing"));
    }
}
