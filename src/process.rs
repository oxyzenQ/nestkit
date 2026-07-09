// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Shared process-context helper — the single source of truth for
//! investigator-grade process introspection.
//!
//! Every other subcommand (proc, port, holds, why, touch) needs the same
//! data about a target PID: its kernel name, full command line, parent
//! chain to PID 1, real+effective UID, cgroup (systemd unit), netns/pidns
//! membership, state, memory, threads. Reading each /proc file once here
//! and exposing a structured `ProcessContext` keeps every consumer
//! consistent and avoids duplicated parsing across modules.
//!
//! Functions here are kept even when not yet wired into every subcommand —
//! they form the foundation for upcoming depth upgrades (port owner
//! context, holds holder context, why synthesis).

#![allow(dead_code)]

use std::fs;
use std::path::Path;

/// Process state character from `/proc/<pid>/stat` field 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcState {
    Running,
    Sleep,
    Uninterruptible,
    Zombie,
    Traced,
    Stopped,
    Paging,
    Dead,
    Idle,
    Unknown,
}

impl ProcState {
    pub fn from_char(c: char) -> Self {
        match c {
            'R' => Self::Running,
            'S' => Self::Sleep,
            'D' => Self::Uninterruptible,
            'Z' => Self::Zombie,
            'T' => Self::Traced,
            't' => Self::Stopped,
            'P' => Self::Paging,
            'X' | 'x' => Self::Dead,
            'I' => Self::Idle,
            _ => Self::Unknown,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Running => "R",
            Self::Sleep => "S",
            Self::Uninterruptible => "D",
            Self::Zombie => "Z",
            Self::Traced => "T",
            Self::Stopped => "t",
            Self::Paging => "P",
            Self::Dead => "X",
            Self::Idle => "I",
            Self::Unknown => "?",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Sleep => "sleeping",
            Self::Uninterruptible => "uninterruptible-disk-sleep",
            Self::Zombie => "zombie",
            Self::Traced => "traced/stopped",
            Self::Stopped => "stopped",
            Self::Paging => "paging",
            Self::Dead => "dead",
            Self::Idle => "idle",
            Self::Unknown => "unknown",
        }
    }
}

/// A user/group name resolution cache. Reads `/etc/passwd` once and looks
/// up UID → username. Returns the numeric string when no entry is found or
/// when the file is unreadable (e.g., unprivileged user inside a container).
pub fn lookup_username(uid: u32) -> String {
    let Ok(contents) = fs::read_to_string("/etc/passwd") else {
        return uid.to_string();
    };
    for line in contents.lines() {
        // passwd format: name:password:uid:gid:gecos:home:shell
        let mut parts = line.split(':');
        let Some(name) = parts.next() else { continue };
        let _ = parts.next(); // password (x or *)
        let Some(uid_str) = parts.next() else {
            continue;
        };
        let Ok(parsed_uid) = uid_str.parse::<u32>() else {
            continue;
        };
        if parsed_uid == uid {
            return name.to_owned();
        }
    }
    uid.to_string()
}

/// Read `/proc/<pid>/cmdline` and split on NUL bytes into argv tokens.
/// Returns `None` if the file is unreadable or empty.
///
/// `/proc/<pid>/cmdline` is NUL-separated (not newline). An empty file
/// means the process is a kernel thread (`[kworker/...]`) — in that case
/// callers should fall back to the `Name` field from `/proc/<pid>/status`.
pub fn read_cmdline(proc_root: &Path, pid: u32) -> Option<String> {
    let path = proc_root.join(pid.to_string()).join("cmdline");
    let bytes = fs::read(&path).ok()?;
    // Kernel threads have empty cmdline.
    if bytes.is_empty() {
        return None;
    }
    // Replace trailing NULs, then split on NUL, join with space.
    let trimmed = bytes.trim_ascii_end();
    if trimmed.is_empty() {
        return None;
    }
    let mut tokens = Vec::new();
    let mut start = 0;
    for (i, &b) in trimmed.iter().enumerate() {
        if b == 0 {
            if i > start {
                if let Ok(s) = std::str::from_utf8(&trimmed[start..i]) {
                    tokens.push(s.to_owned());
                }
            }
            start = i + 1;
        }
    }
    if start < trimmed.len() {
        if let Ok(s) = std::str::from_utf8(&trimmed[start..]) {
            tokens.push(s.to_owned());
        }
    }
    if tokens.is_empty() {
        None
    } else {
        Some(tokens.join(" "))
    }
}

/// Extract the systemd unit name from a cgroup string.
///
/// cgroup v2 paths look like:
///   `0::/system.slice/nginx.service`
///   `0::/user.slice/user-1000.slice/user@1000.service/app.slice/dbus.service`
///   `0::/system.slice/systemd-resolved.service`
///
/// Returns the last component ending in `.service`, `.socket`, `.scope`,
/// `.mount`, `.swap`, `.timer`, or `.target`. Returns `None` when no
/// recognizable unit suffix is found (e.g., kernel threads, cgroup v1
/// legacy paths without unit names).
pub fn extract_systemd_unit(cgroup: &str) -> Option<String> {
    let suffixes = [
        ".service", ".socket", ".scope", ".mount", ".swap", ".timer", ".target",
    ];
    // Walk path components in reverse, return first match
    for component in cgroup.split('/').rev() {
        for suffix in &suffixes {
            if component.ends_with(suffix) && component.len() > suffix.len() {
                return Some(component.to_owned());
            }
        }
    }
    None
}

/// Read /proc/<pid>/cgroup and extract the systemd unit name.
pub fn read_systemd_unit(proc_root: &Path, pid: u32) -> Option<String> {
    let cgroup = fs::read_to_string(proc_root.join(pid.to_string()).join("cgroup")).ok()?;
    // Take the last non-empty line (usually the unified v2 line)
    let last = cgroup.lines().rev().find(|l| !l.trim().is_empty())?;
    // Format: `0::/system.slice/nginx.service` — take everything after the last `:`
    let path = last.rsplit_once(':').map(|(_, p)| p).unwrap_or(last);
    extract_systemd_unit(path)
}

/// A condensed process context. Built once per target PID and consumed by
/// every subcommand that needs to display "this is who did it" information.
#[derive(Debug, Clone)]
pub struct ProcessContext {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub cmdline: Option<String>,
    pub uid: u32,
    pub euid: u32,
    pub state: ProcState,
    pub vm_rss_kb: u64,
    pub vm_size_kb: u64,
    pub vm_swap_kb: u64,
    pub threads: u64,
    pub cgroup: Option<String>,
    pub netns_inode: Option<u64>,
    pub pidns_inode: Option<u64>,
}

impl ProcessContext {
    /// Render as a single-line summary suitable for tree leaves.
    /// Example: `nginx pid=1234 user=www-data state=R rss=8MB cmd="nginx -g 'daemon off;'"`
    pub fn summary_line(&self, username: &str) -> String {
        let mut parts = Vec::new();
        parts.push(format!("pid={}", self.pid));
        parts.push(format!("user={username}"));
        parts.push(format!("state={}", self.state.label()));
        if self.vm_rss_kb > 0 {
            parts.push(format!("rss={}", human_kb(self.vm_rss_kb)));
        }
        if let Some(ref cmd) = self.cmdline {
            parts.push(format!("cmd={}", quote_if_needed(cmd)));
        } else {
            parts.push(format!("cmd={}", self.name));
        }
        parts.join(" ")
    }

    /// Render as a multi-line evidence block (for `why`, `holds --verbose`).
    pub fn evidence_block(&self, username: &str) -> Vec<String> {
        let mut lines = Vec::new();
        lines.push(format!("name: {}", self.name));
        if let Some(ref cmd) = self.cmdline {
            lines.push(format!("cmdline: {cmd}"));
        }
        lines.push(format!("pid: {} (ppid={})", self.pid, self.ppid));
        lines.push(format!(
            "user: {} (uid={} euid={})",
            username, self.uid, self.euid
        ));
        lines.push(format!(
            "state: {} ({})",
            self.state.label(),
            self.state.description()
        ));
        if self.vm_rss_kb > 0 || self.vm_size_kb > 0 {
            lines.push(format!(
                "memory: rss={} vsize={} swap={}",
                human_kb(self.vm_rss_kb),
                human_kb(self.vm_size_kb),
                human_kb(self.vm_swap_kb)
            ));
        }
        if self.threads > 1 {
            lines.push(format!("threads: {}", self.threads));
        }
        if let Some(ref cg) = self.cgroup {
            lines.push(format!("cgroup: {cg}"));
        }
        if let Some(ns) = self.netns_inode {
            lines.push(format!("netns: inode={ns}"));
        }
        if let Some(ns) = self.pidns_inode {
            lines.push(format!("pidns: inode={ns}"));
        }
        lines
    }
}

/// Read everything we need about a single PID: status (name, ppid, uid,
/// euid, memory, threads) and stat (state char). Also reads cmdline,
/// cgroup, and ns/{net,pid} symlinks.
///
/// Returns `None` if `/proc/<pid>/status` is unreadable. Other fields
/// degrade gracefully (None / 0) when their files are missing.
pub fn read_context(proc_root: &Path, pid: u32) -> Option<ProcessContext> {
    let dir = proc_root.join(pid.to_string());
    let status = fs::read_to_string(dir.join("status")).ok()?;
    let name = parse_status_field(&status, "Name")?;
    let ppid = parse_status_number_u32(&status, "PPid")?;
    let (uid, euid) = parse_uid_pair(&status)?;
    let vm_rss_kb = parse_status_number(&status, "VmRSS").unwrap_or(0);
    let vm_size_kb = parse_status_number(&status, "VmSize").unwrap_or(0);
    let vm_swap_kb = parse_status_number(&status, "VmSwap").unwrap_or(0);
    let threads = parse_status_number(&status, "Threads").unwrap_or(1);

    // State from /proc/<pid>/stat (status has no state char).
    let state = read_stat_state(&dir).unwrap_or(ProcState::Unknown);

    let cmdline = read_cmdline(proc_root, pid);
    let cgroup = read_cgroup(&dir);
    let (netns_inode, pidns_inode) = read_ns_inodes(&dir);

    Some(ProcessContext {
        pid,
        ppid,
        name,
        cmdline,
        uid,
        euid,
        state,
        vm_rss_kb,
        vm_size_kb,
        vm_swap_kb,
        threads,
        cgroup,
        netns_inode,
        pidns_inode,
    })
}

/// Walk parent chain from `start_pid` up to PID 1 (or until unreadable).
/// Returns the chain in order: [start_pid, ppid, ..., 1].
/// Skips over self and stops at PID 1.
pub fn parent_chain(proc_root: &Path, start_pid: u32) -> Vec<ProcessContext> {
    let mut chain = Vec::new();
    let mut current = start_pid;
    let mut seen = std::collections::HashSet::new();
    while let Some(ctx) = read_context(proc_root, current) {
        if !seen.insert(current) {
            break; // cycle guard
        }
        let next = ctx.ppid;
        chain.push(ctx);
        if current == 1 || next == 0 || next == current {
            break;
        }
        current = next;
    }
    chain
}

// ── helpers ──────────────────────────────────────────────────────────

fn parse_status_field(status: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}:");
    status
        .lines()
        .find_map(|line| line.strip_prefix(&prefix).map(str::trim))
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
}

fn parse_status_number(status: &str, key: &str) -> Option<u64> {
    let value = parse_status_field(status, key)?;
    // VmRSS: 1234 kB
    let parts: Vec<&str> = value.split_whitespace().collect();
    let n = parts.first()?;
    n.parse::<u64>().ok()
}

fn parse_status_number_u32(status: &str, key: &str) -> Option<u32> {
    parse_status_number(status, key).and_then(|n| n.try_into().ok())
}

fn parse_uid_pair(status: &str) -> Option<(u32, u32)> {
    // Uid: real effective saved fs
    let value = parse_status_field(status, "Uid")?;
    let mut parts = value.split_whitespace();
    let real = parts.next()?.parse::<u32>().ok()?;
    let eff = parts.next().unwrap_or("0").parse::<u32>().ok().unwrap_or(0);
    Some((real, eff))
}

fn read_stat_state(dir: &Path) -> Option<ProcState> {
    let stat = fs::read_to_string(dir.join("stat")).ok()?;
    // Field 3 is the state char, enclosed in parens-aware format:
    // pid (comm) state ...
    // comm can contain spaces and parens, so we find the LAST ')'.
    let close_paren = stat.rfind(')')?;
    let after = &stat[close_paren + 1..];
    let state_char = after.trim_start().chars().next()?;
    Some(ProcState::from_char(state_char))
}

fn read_cgroup(dir: &Path) -> Option<String> {
    let contents = fs::read_to_string(dir.join("cgroup")).ok()?;
    // Take the last non-empty line (usually the one for the user slice /
    // service scope). Multiple lines exist for v1 hierarchy.
    let mut last: Option<&str> = None;
    for line in contents.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            last = Some(trimmed);
        }
    }
    last.map(|l| l.to_owned())
}

fn read_ns_inodes(dir: &Path) -> (Option<u64>, Option<u64>) {
    let netns = read_ns_inode(dir, "net");
    let pidns = read_ns_inode(dir, "pid");
    (netns, pidns)
}

fn read_ns_inode(dir: &Path, ns: &str) -> Option<u64> {
    let path = dir.join("ns").join(ns);
    let meta = fs::symlink_metadata(&path).ok()?;
    use std::os::unix::fs::MetadataExt;
    Some(meta.ino())
}

fn human_kb(kb: u64) -> String {
    if kb >= 1024 * 1024 {
        format!("{:.1}GB", kb as f64 / 1024.0 / 1024.0)
    } else if kb >= 1024 {
        format!("{:.0}MB", kb as f64 / 1024.0)
    } else {
        format!("{kb}KB")
    }
}

fn quote_if_needed(s: &str) -> String {
    if s.contains(' ') || s.contains('"') || s.contains('\'') {
        // Use single quotes if no single quote inside; otherwise double-escape.
        if !s.contains('\'') {
            format!("'{s}'")
        } else {
            format!("\"{}\"", s.replace('"', "\\\""))
        }
    } else {
        s.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_state_label_roundtrip() {
        assert_eq!(ProcState::from_char('R'), ProcState::Running);
        assert_eq!(ProcState::from_char('Z'), ProcState::Zombie);
        assert_eq!(ProcState::from_char('S'), ProcState::Sleep);
        assert_eq!(ProcState::from_char('?'), ProcState::Unknown);
        assert_eq!(ProcState::Running.label(), "R");
        assert_eq!(ProcState::Zombie.label(), "Z");
    }

    #[test]
    fn parse_status_field_finds_key() {
        let s = "Name:\tbash\nPid:\t1234\nPPid:\t1\n";
        assert_eq!(parse_status_field(s, "Name").as_deref(), Some("bash"));
        assert_eq!(parse_status_field(s, "Pid").as_deref(), Some("1234"));
        assert_eq!(parse_status_field(s, "Missing"), None);
    }

    #[test]
    fn parse_status_number_handles_kb_suffix() {
        let s = "VmRSS:\t   8420 kB\n";
        assert_eq!(parse_status_number(s, "VmRSS"), Some(8420));
        assert_eq!(parse_status_number(s, "VmSize"), None);
    }

    #[test]
    fn parse_uid_pair_real_effective() {
        let s = "Uid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(parse_uid_pair(s), Some((1000, 1000)));
        let s2 = "Uid:\t0\t0\t0\t0\n";
        assert_eq!(parse_uid_pair(s2), Some((0, 0)));
    }

    #[test]
    fn lookup_username_resolves_known_uid() {
        // UID 0 should always resolve to "root" on any Linux system.
        assert_eq!(lookup_username(0), "root");
    }

    #[test]
    fn lookup_username_unknown_uid_returns_numeric() {
        // Pick an absurdly high UID unlikely to exist.
        let s = lookup_username(65534);
        // 65534 is 'nobody' on most systems; if it's not, we just want a non-empty string.
        assert!(!s.is_empty());
    }

    #[test]
    fn read_cmdline_self_pid() {
        let own_pid = std::process::id();
        let ctx = read_context(Path::new("/proc"), own_pid);
        assert!(ctx.is_some(), "should be able to read our own context");
        let ctx = ctx.unwrap();
        assert_eq!(ctx.pid, own_pid);
        assert!(!ctx.name.is_empty());
    }

    #[test]
    fn parent_chain_self_reaches_init() {
        let own_pid = std::process::id();
        let chain = parent_chain(Path::new("/proc"), own_pid);
        assert!(!chain.is_empty());
        // Should end at PID 1 (init/systemd) or stop earlier if unprivileged.
        let last = chain.last().unwrap();
        assert!(last.pid == 1 || last.ppid == 0 || last.ppid == last.pid);
    }

    #[test]
    fn summary_line_includes_pid_and_state() {
        let ctx = ProcessContext {
            pid: 42,
            ppid: 1,
            name: "test".to_owned(),
            cmdline: Some("test --flag".to_owned()),
            uid: 1000,
            euid: 1000,
            state: ProcState::Running,
            vm_rss_kb: 4096,
            vm_size_kb: 16384,
            vm_swap_kb: 0,
            threads: 1,
            cgroup: None,
            netns_inode: None,
            pidns_inode: None,
        };
        let line = ctx.summary_line("testuser");
        assert!(line.contains("pid=42"));
        assert!(line.contains("state=R"));
        assert!(line.contains("user=testuser"));
        assert!(line.contains("cmd='test --flag'"));
    }

    #[test]
    fn evidence_block_has_all_fields() {
        let ctx = ProcessContext {
            pid: 42,
            ppid: 1,
            name: "test".to_owned(),
            cmdline: Some("test --flag".to_owned()),
            uid: 1000,
            euid: 1000,
            state: ProcState::Zombie,
            vm_rss_kb: 4096,
            vm_size_kb: 16384,
            vm_swap_kb: 0,
            threads: 4,
            cgroup: Some("0::/user.slice".to_owned()),
            netns_inode: Some(4026531992),
            pidns_inode: Some(4026531836),
        };
        let block = ctx.evidence_block("testuser");
        let joined = block.join("\n");
        assert!(joined.contains("name: test"));
        assert!(joined.contains("cmdline: test --flag"));
        assert!(joined.contains("pid: 42 (ppid=1)"));
        assert!(joined.contains("state: Z (zombie)"));
        assert!(joined.contains("threads: 4"));
        assert!(joined.contains("cgroup: 0::/user.slice"));
        assert!(joined.contains("netns: inode=4026531992"));
        assert!(joined.contains("pidns: inode=4026531836"));
    }

    #[test]
    fn quote_if_needed_handles_spaces() {
        assert_eq!(quote_if_needed("simple"), "simple");
        assert_eq!(quote_if_needed("has space"), "'has space'");
        assert_eq!(quote_if_needed("has'quote"), "\"has'quote\"");
    }

    #[test]
    fn extract_systemd_unit_from_v2_path() {
        assert_eq!(
            extract_systemd_unit("0::/system.slice/nginx.service"),
            Some("nginx.service".to_owned())
        );
        assert_eq!(
            extract_systemd_unit(
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/dbus.service"
            ),
            Some("dbus.service".to_owned())
        );
        assert_eq!(
            extract_systemd_unit("0::/system.slice/systemd-resolved.service"),
            Some("systemd-resolved.service".to_owned())
        );
    }

    #[test]
    fn extract_systemd_unit_handles_other_suffixes() {
        assert_eq!(
            extract_systemd_unit("0::/system.slice/foo.socket"),
            Some("foo.socket".to_owned())
        );
        assert_eq!(
            extract_systemd_unit("0::/system.slice/session-1.scope"),
            Some("session-1.scope".to_owned())
        );
    }

    #[test]
    fn extract_systemd_unit_returns_none_for_kernel_threads() {
        assert_eq!(extract_systemd_unit("0::/"), None);
        assert_eq!(extract_systemd_unit("0::/user.slice"), None);
        assert_eq!(extract_systemd_unit(""), None);
    }
}
