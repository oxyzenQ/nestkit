// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::BTreeSet;

use super::model::{
    GroupKey, OwnerIdentity, OwnerMap, PortOptions, ProcessInfo, ScanStats, SocketEntry,
    SocketGroup,
};

pub fn format_report(
    sockets: &[SocketEntry],
    owners: &OwnerMap,
    stats: &ScanStats,
    options: &PortOptions,
) -> String {
    if options.group {
        return format_grouped_report(sockets, owners, stats, options);
    }

    let mut lines = Vec::new();

    if let Some(port) = options.port {
        if sockets.is_empty() {
            lines.push(format!("No sockets found for port {port}."));
            return lines.join("\n");
        }
        lines.push(format!(":{port}"));
        append_socket_lines(&mut lines, sockets, owners, options, "");
    } else {
        lines.push("ports".to_owned());
        if sockets.is_empty() {
            lines.push("No sockets found.".to_owned());
            return lines.join("\n");
        }
        append_socket_lines(&mut lines, sockets, owners, options, "");
        let owner_count = unique_owner_count(sockets, owners);
        lines.push(String::new());
        lines.push(format!(
            "{} {} · {} {}",
            sockets.len(),
            plural(sockets.len(), "port", "ports"),
            owner_count,
            plural(owner_count, "owner", "owners")
        ));
        // State breakdown for TCP sockets — investigators want to see at a
        // glance "5 LISTEN · 12 ESTABLISHED · 3 TIME_WAIT".
        let state_breakdown = state_breakdown(sockets);
        if !state_breakdown.is_empty() {
            lines.push(format!("states: {state_breakdown}"));
        }
    }

    append_note(&mut lines, stats);
    lines.join("\n")
}

fn format_grouped_report(
    sockets: &[SocketEntry],
    owners: &OwnerMap,
    stats: &ScanStats,
    options: &PortOptions,
) -> String {
    let mut lines = Vec::new();

    if let Some(port) = options.port {
        if sockets.is_empty() {
            lines.push(format!("No sockets found for port {port}."));
            return lines.join("\n");
        }
        lines.push(format!(":{port}"));
    } else {
        lines.push("ports".to_owned());
        if sockets.is_empty() {
            lines.push("No sockets found.".to_owned());
            return lines.join("\n");
        }
    }

    let groups = group_sockets(sockets, owners);
    append_group_lines(&mut lines, &groups, options, "");

    let socket_count: usize = groups.iter().map(|group| group.count).sum();
    let owner_count = unique_group_owner_count(&groups);
    lines.push(String::new());
    lines.push(format!(
        "{} {} · {} {} · {} {}",
        groups.len(),
        plural(groups.len(), "group", "groups"),
        socket_count,
        plural(socket_count, "socket", "sockets"),
        owner_count,
        plural(owner_count, "owner", "owners")
    ));

    append_note(&mut lines, stats);
    lines.join("\n")
}

pub(crate) fn group_sockets(sockets: &[SocketEntry], owners: &OwnerMap) -> Vec<SocketGroup> {
    let mut groups: Vec<(GroupKey, SocketGroup)> = Vec::new();

    for socket in sockets {
        let group_owners = owners.get(&socket.inode).cloned().unwrap_or_default();
        let key = GroupKey {
            protocol: socket.protocol,
            address: socket.address.clone(),
            port: socket.port,
            state: socket.state.clone(),
            owners: group_owners.iter().map(OwnerIdentity::from).collect(),
        };

        if let Some((_, group)) = groups.iter_mut().find(|(existing, _)| existing == &key) {
            group.count += 1;
        } else {
            groups.push((
                key,
                SocketGroup {
                    socket: socket.clone(),
                    owners: group_owners,
                    count: 1,
                },
            ));
        }
    }

    groups.into_iter().map(|(_, group)| group).collect()
}

fn unique_owner_count(sockets: &[SocketEntry], owners: &OwnerMap) -> usize {
    let mut unique = BTreeSet::new();
    for process in sockets
        .iter()
        .filter_map(|socket| owners.get(&socket.inode))
        .flatten()
    {
        unique.insert(process.pid);
    }
    unique.len()
}

fn unique_group_owner_count(groups: &[SocketGroup]) -> usize {
    let mut unique = BTreeSet::new();
    for process in groups.iter().flat_map(|group| &group.owners) {
        unique.insert(process.pid);
    }
    unique.len()
}

fn append_socket_lines(
    lines: &mut Vec<String>,
    sockets: &[SocketEntry],
    owners: &OwnerMap,
    options: &PortOptions,
    indent: &str,
) {
    for (index, socket) in sockets.iter().enumerate() {
        let last_socket = index + 1 == sockets.len();
        let branch = if last_socket {
            "└──"
        } else {
            "├──"
        };
        let child_indent = if last_socket { "    " } else { "│   " };
        lines.push(format!("{indent}{branch} {}", format_socket(socket)));
        append_owner_lines(
            lines,
            owners.get(&socket.inode),
            options,
            &format!("{indent}{child_indent}"),
        );
    }
}

fn append_group_lines(
    lines: &mut Vec<String>,
    groups: &[SocketGroup],
    options: &PortOptions,
    indent: &str,
) {
    for (index, group) in groups.iter().enumerate() {
        let last_group = index + 1 == groups.len();
        let branch = if last_group { "└──" } else { "├──" };
        let child_indent = if last_group { "    " } else { "│   " };
        lines.push(format!("{indent}{branch} {}", format_group(group)));
        append_owner_lines(
            lines,
            Some(&group.owners),
            options,
            &format!("{indent}{child_indent}"),
        );
    }
}

fn format_group(group: &SocketGroup) -> String {
    let mut value = format_socket(&group.socket);
    if group.count > 1 {
        value.push_str(&format!(" ×{}", group.count));
    }
    value
}

fn append_owner_lines(
    lines: &mut Vec<String>,
    processes: Option<&Vec<ProcessInfo>>,
    options: &PortOptions,
    indent: &str,
) {
    let Some(processes) = processes.filter(|processes| !processes.is_empty()) else {
        lines.push(format!("{indent}└── {}", format_unknown_owner()));
        return;
    };

    for (index, process) in processes.iter().enumerate() {
        let last = index + 1 == processes.len();
        let branch = if last { "└──" } else { "├──" };
        lines.push(format!(
            "{indent}{branch} {}",
            format_owner(process, options.no_pid)
        ));
        if options.port.is_some()
            && let Some(cwd) = &process.cwd
        {
            let cwd_indent = if last { "    " } else { "│   " };
            lines.push(format!("{indent}{cwd_indent}cwd {}", cwd.display()));
        }
    }
}

fn format_socket(socket: &SocketEntry) -> String {
    let endpoint = if socket.address.contains(':') {
        format!("[{}]:{}", socket.address, socket.port)
    } else {
        format!("{}:{}", socket.address, socket.port)
    };
    let mut value = format!("{} {}", socket.protocol.label(), endpoint);
    if let Some(state) = &socket.state {
        value.push(' ');
        value.push_str(state);
    }
    // Show remote endpoint when non-zero (i.e., connection is established or
    // has a peer — LISTEN sockets have 0.0.0.0:0).
    if socket.remote_port != 0 {
        let remote = if socket.remote_address.contains(':') {
            format!("[{}]:{}", socket.remote_address, socket.remote_port)
        } else {
            format!("{}:{}", socket.remote_address, socket.remote_port)
        };
        value.push_str(&format!(" <- {remote}"));
    }
    value
}

pub fn format_owner(process: &ProcessInfo, no_pid: bool) -> String {
    let mut parts = Vec::new();
    parts.push(process.name.clone());
    if !no_pid {
        parts.push(format!("pid={}", process.pid));
    }
    parts.push(format!("user={}", process.user));
    if let Some(fd) = process.fd {
        parts.push(format!("fd={fd}"));
    }
    parts.join(" ")
}

pub fn format_unknown_owner() -> &'static str {
    "unknown"
}

/// Build a "5 LISTEN · 12 ESTABLISHED · 3 TIME_WAIT" style summary of TCP
/// socket states. Returns empty string when no TCP sockets have a state.
fn state_breakdown(sockets: &[SocketEntry]) -> String {
    use std::collections::BTreeMap;
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for socket in sockets {
        if let Some(state) = socket.state.as_deref() {
            *counts.entry(state).or_default() += 1;
        }
    }
    // Sort by count descending for the most useful states first
    let mut entries: Vec<(&&str, &usize)> = counts.iter().collect();
    entries.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    entries
        .iter()
        .map(|(state, count)| format!("{count} {state}"))
        .collect::<Vec<_>>()
        .join(" · ")
}

pub fn should_show_unreadable_note(stats: &ScanStats) -> bool {
    stats.unreadable_processes > 0 || stats.unreadable_fds > 0
}

fn append_note(lines: &mut Vec<String>, stats: &ScanStats) {
    if should_show_unreadable_note(stats) {
        lines.push(String::new());
        lines.push(
            "note: some processes were not readable; try sudo for complete owner details"
                .to_owned(),
        );
    }
}

fn plural<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

#[cfg(test)]
mod tests {
    use super::super::model::Protocol;
    use super::*;
    use std::path::PathBuf;

    fn socket_with_inode(
        protocol: Protocol,
        port: u16,
        state: Option<&str>,
        inode: u64,
    ) -> SocketEntry {
        socket_at(protocol, "127.0.0.1", port, state, inode)
    }

    fn socket_at(
        protocol: Protocol,
        address: &str,
        port: u16,
        state: Option<&str>,
        inode: u64,
    ) -> SocketEntry {
        SocketEntry {
            protocol,
            address: address.to_owned(),
            port,
            state: state.map(ToOwned::to_owned),
            inode,
            remote_address: "0.0.0.0".to_owned(),
            remote_port: 0,
        }
    }

    fn options() -> PortOptions {
        PortOptions {
            port: None,
            tcp: false,
            udp: false,
            listen: false,
            all: false,
            numeric: false,
            group: false,
            no_pid: false,
        }
    }

    fn process(pid: u32, name: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            name: name.to_owned(),
            user: "rezky".to_owned(),
            cwd: None,
            cmdline: None,
            fd: None,
        }
    }

    #[test]
    fn report_summary_uses_rendered_socket_count_after_filtering() {
        let sockets = vec![
            socket_with_inode(Protocol::Tcp, 80, Some("LISTEN"), 100),
            socket_with_inode(Protocol::Tcp, 443, Some("ESTABLISHED"), 200),
        ];
        let selected = super::super::filter_sockets(&sockets, &options());
        let mut owners = OwnerMap::new();
        owners.insert(200, vec![process(7, "curl")]);

        let report = format_report(&selected, &owners, &ScanStats::default(), &options());

        assert!(report.contains("1 port · 0 owners"));
        assert!(!report.contains("443"));
    }

    #[test]
    fn owner_summary_counts_unique_known_rendered_processes() {
        let sockets = vec![
            socket_with_inode(Protocol::Tcp, 80, Some("LISTEN"), 100),
            socket_with_inode(Protocol::Udp, 53, None, 200),
            socket_with_inode(Protocol::Udp, 5353, None, 300),
        ];
        let mut owners = OwnerMap::new();
        owners.insert(100, vec![process(7, "daemon")]);
        owners.insert(200, vec![process(7, "daemon")]);

        let report = format_report(&sockets, &owners, &ScanStats::default(), &options());

        assert!(report.contains("3 ports · 1 owner"));
    }

    #[test]
    fn cwd_is_only_rendered_for_specific_port_reports() {
        let sockets = vec![socket_with_inode(Protocol::Tcp, 3000, Some("LISTEN"), 100)];
        let mut process = process(1234, "node");
        process.cwd = Some(PathBuf::from("/home/rezky/project"));
        let mut owners = OwnerMap::new();
        owners.insert(100, vec![process]);

        let list_report = format_report(&sockets, &owners, &ScanStats::default(), &options());
        let detail_report = format_report(
            &sockets,
            &owners,
            &ScanStats::default(),
            &PortOptions {
                port: Some(3000),
                ..options()
            },
        );

        assert!(!list_report.contains("cwd /home/rezky/project"));
        assert!(detail_report.contains("cwd /home/rezky/project"));
    }

    #[test]
    fn report_respects_no_pid_owner_formatting() {
        let sockets = vec![socket_with_inode(Protocol::Tcp, 3000, Some("LISTEN"), 100)];
        let mut owners = OwnerMap::new();
        owners.insert(100, vec![process(1234, "node")]);

        let report = format_report(
            &sockets,
            &owners,
            &ScanStats::default(),
            &PortOptions {
                no_pid: true,
                ..options()
            },
        );

        assert!(report.contains("node user=rezky"));
        assert!(!report.contains("pid=1234"));
    }

    #[test]
    fn grouped_report_combines_repeated_sockets() {
        let sockets = vec![
            socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 100),
            socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 200),
        ];

        let report = format_report(
            &sockets,
            &OwnerMap::new(),
            &ScanStats::default(),
            &PortOptions {
                group: true,
                ..options()
            },
        );

        assert!(report.contains("tcp 127.0.0.1:53 LISTEN ×2"));
        assert!(report.contains("1 group · 2 sockets · 0 owners"));
        assert_eq!(report.matches("unknown").count(), 1);
    }

    #[test]
    fn grouped_report_keeps_different_owners_separate() {
        let sockets = vec![
            socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 100),
            socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 200),
        ];
        let mut owners = OwnerMap::new();
        owners.insert(100, vec![process(10, "unbound")]);
        owners.insert(200, vec![process(20, "dnsmasq")]);

        let report = format_report(
            &sockets,
            &owners,
            &ScanStats::default(),
            &PortOptions {
                group: true,
                ..options()
            },
        );

        assert_eq!(report.matches("tcp 127.0.0.1:53 LISTEN").count(), 2);
        assert!(!report.contains("×2"));
        assert!(report.contains("2 groups · 2 sockets · 2 owners"));
    }

    #[test]
    fn grouped_report_keeps_socket_identity_separate() {
        let sockets = vec![
            socket_at(Protocol::Tcp, "127.0.0.1", 53, Some("LISTEN"), 100),
            socket_at(Protocol::Tcp, "127.0.0.2", 53, Some("LISTEN"), 200),
            socket_at(Protocol::Tcp, "127.0.0.1", 54, Some("LISTEN"), 300),
            socket_at(Protocol::Tcp, "127.0.0.1", 53, Some("ESTABLISHED"), 400),
            socket_at(Protocol::Udp, "127.0.0.1", 53, None, 500),
        ];

        let report = format_report(
            &sockets,
            &OwnerMap::new(),
            &ScanStats::default(),
            &PortOptions {
                group: true,
                all: true,
                ..options()
            },
        );

        assert!(report.contains("5 groups · 5 sockets · 0 owners"));
        assert!(!report.contains('×'));
    }

    #[test]
    fn grouped_summary_counts_groups_sockets_and_unique_owners() {
        let sockets = vec![
            socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 100),
            socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 200),
            socket_with_inode(Protocol::Udp, 5353, None, 300),
        ];
        let mut owners = OwnerMap::new();
        owners.insert(100, vec![process(10, "unbound")]);
        owners.insert(200, vec![process(10, "unbound")]);

        let report = format_report(
            &sockets,
            &owners,
            &ScanStats::default(),
            &PortOptions {
                group: true,
                ..options()
            },
        );

        assert!(report.contains("2 groups · 3 sockets · 1 owner"));
    }

    #[test]
    fn grouped_report_respects_no_pid_owner_formatting() {
        let sockets = vec![socket_with_inode(Protocol::Tcp, 3000, Some("LISTEN"), 100)];
        let mut owners = OwnerMap::new();
        owners.insert(100, vec![process(1234, "node")]);

        let report = format_report(
            &sockets,
            &owners,
            &ScanStats::default(),
            &PortOptions {
                group: true,
                no_pid: true,
                ..options()
            },
        );

        assert!(report.contains("node user=rezky"));
        assert!(!report.contains("pid=1234"));
    }

    #[test]
    fn grouped_specific_port_keeps_detail_header() {
        let sockets = vec![
            socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 100),
            socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 200),
        ];

        let report = format_report(
            &sockets,
            &OwnerMap::new(),
            &ScanStats::default(),
            &PortOptions {
                port: Some(53),
                group: true,
                ..options()
            },
        );

        assert!(report.starts_with(":53\n"));
        assert!(report.contains("tcp 127.0.0.1:53 LISTEN ×2"));
        assert!(report.contains("1 group · 2 sockets · 0 owners"));
    }

    #[test]
    fn no_match_specific_port_omits_unreadable_note() {
        let report = format_report(
            &[],
            &OwnerMap::new(),
            &ScanStats {
                unreadable_processes: 1,
                unreadable_fds: 1,
            },
            &PortOptions {
                port: Some(22),
                ..options()
            },
        );

        assert_eq!(report, "No sockets found for port 22.");
    }

    #[test]
    fn grouped_no_match_specific_port_omits_unreadable_note() {
        let report = format_report(
            &[],
            &OwnerMap::new(),
            &ScanStats {
                unreadable_processes: 1,
                unreadable_fds: 1,
            },
            &PortOptions {
                port: Some(22),
                group: true,
                ..options()
            },
        );

        assert_eq!(report, "No sockets found for port 22.");
    }

    #[test]
    fn rendered_sockets_keep_unreadable_note() {
        let sockets = vec![socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 100)];

        let report = format_report(
            &sockets,
            &OwnerMap::new(),
            &ScanStats {
                unreadable_processes: 1,
                unreadable_fds: 0,
            },
            &PortOptions {
                group: true,
                ..options()
            },
        );

        assert!(report.contains("tcp 127.0.0.1:53 LISTEN"));
        assert!(report.contains(
            "note: some processes were not readable; try sudo for complete owner details"
        ));
    }

    #[test]
    fn raw_report_does_not_group_by_default() {
        let sockets = vec![
            socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 100),
            socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 200),
        ];

        let report = format_report(
            &sockets,
            &OwnerMap::new(),
            &ScanStats::default(),
            &options(),
        );

        assert_eq!(report.matches("tcp 127.0.0.1:53 LISTEN").count(), 2);
        assert!(report.contains("2 ports · 0 owners"));
        assert!(!report.contains('×'));
    }
}
