// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{self, BufRead};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    Port(u16),
    Path(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldsError(String);

impl fmt::Display for HoldsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for HoldsError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Holder {
    pub(crate) pid: u32,
    pub(crate) name: String,
    pub(crate) user: String,
    pub(crate) cwd: Option<PathBuf>,
    pub(crate) evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Evidence {
    Fd(i32, FdMode),
    Mmap(MmapPerms),
}

/// FD access mode decoded from /proc/<pid>/fdinfo/<fd> flags field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum FdMode {
    Read,
    Write,
    ReadWrite,
    Unknown,
}

impl FdMode {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Read => "r",
            Self::Write => "w",
            Self::ReadWrite => "rw",
            Self::Unknown => "?",
        }
    }

    pub(crate) fn from_flags(flags: u64) -> Self {
        // O_RDONLY=0, O_WRONLY=1, O_RDWR=2 — lower 2 bits of flags
        match flags & 0o3 {
            0 => Self::Read,
            1 => Self::Write,
            2 => Self::ReadWrite,
            _ => Self::Unknown,
        }
    }
}

/// mmap permissions decoded from /proc/<pid>/maps column 2 (e.g., "r-xp").
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct MmapPerms {
    pub(crate) read: bool,
    pub(crate) write: bool,
    pub(crate) execute: bool,
    pub(crate) private: bool,
}

impl MmapPerms {
    pub(crate) fn label(&self) -> String {
        let mut s = String::with_capacity(4);
        s.push(if self.read { 'r' } else { '-' });
        s.push(if self.write { 'w' } else { '-' });
        s.push(if self.execute { 'x' } else { '-' });
        s.push(if self.private { 'p' } else { 's' });
        s
    }

    pub(crate) fn parse(s: &str) -> Option<Self> {
        if s.len() != 4 {
            return None;
        }
        let bytes = s.as_bytes();
        Some(Self {
            read: bytes[0] == b'r',
            write: bytes[1] == b'w',
            execute: bytes[2] == b'x',
            private: bytes[3] == b'p',
        })
    }
}

impl Evidence {
    pub(crate) fn label(&self) -> String {
        match self {
            Self::Fd(fd, mode) => format!("fd {fd} ({})", mode.label()),
            Self::Mmap(perms) => format!("mmap {}", perms.label()),
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ScanStats {
    pub(crate) unreadable_processes: usize,
    pub(crate) unreadable_fds: usize,
    pub(crate) unreadable_maps: usize,
}

impl ScanStats {
    pub(crate) fn has_unreadable(self) -> bool {
        self.unreadable_processes > 0 || self.unreadable_fds > 0 || self.unreadable_maps > 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FileId {
    dev: u64,
    inode: u64,
}

impl FileId {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SocketEntry {
    protocol: Protocol,
    port: u16,
    inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MapEntry {
    dev_major: u32,
    dev_minor: u32,
    inode: u64,
    perms: MmapPerms,
}

pub fn run(target: &str) -> Result<(), Box<dyn Error>> {
    let target = parse_target(target)?;
    let output = match target {
        Target::Port(port) => {
            let (holders, stats) = scan_port_holders(port)?;
            format_port_report(port, &holders, &stats)
        }
        Target::Path(path) => {
            let display = path.display().to_string();
            let (holders, stats) = scan_path_holders(&path)?;
            format_path_report(&display, &holders, &stats)
        }
    };
    println!("{output}");
    Ok(())
}

fn parse_target(input: &str) -> Result<Target, HoldsError> {
    if input.chars().all(|character| character.is_ascii_digit()) {
        let port = input
            .parse::<u32>()
            .map_err(|_| HoldsError(format!("invalid port: {input}")))?;
        if !(1..=u32::from(u16::MAX)).contains(&port) {
            return Err(HoldsError(format!("invalid port: {input}")));
        }
        return Ok(Target::Port(port as u16));
    }

    Ok(Target::Path(PathBuf::from(input)))
}

pub(crate) fn scan_port_holders(port: u16) -> Result<(Vec<Holder>, ScanStats), HoldsError> {
    let sockets = read_proc_net_sockets().map_err(|error| HoldsError(error.to_string()))?;
    let target_inodes: BTreeSet<u64> = sockets
        .into_iter()
        .filter(|socket| socket.port == port)
        .map(|socket| socket.inode)
        .collect();

    if target_inodes.is_empty() {
        return Ok((Vec::new(), ScanStats::default()));
    }

    scan_socket_holders(&target_inodes)
}

pub(crate) fn scan_path_holders(path: &Path) -> Result<(Vec<Holder>, ScanStats), HoldsError> {
    let metadata = fs::metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            HoldsError(format!("{}: no such file or directory", path.display()))
        } else {
            HoldsError(format!("{}: {error}", path.display()))
        }
    })?;
    let target = FileId::from_metadata(&metadata);
    let (target_major, target_minor) = dev_major_minor(target.dev);
    let pids = list_pids().map_err(|error| HoldsError(error.to_string()))?;
    let mut holders = Vec::new();
    let mut stats = ScanStats::default();

    for pid in pids {
        let mut evidence = Vec::new();
        match scan_pid_fds_for_file(pid, target) {
            ProcRead::Ok(mut fds) => {
                evidence.extend(fds.drain(..).map(|(fd, mode)| Evidence::Fd(fd, mode)));
            }
            ProcRead::PermissionDenied => stats.unreadable_processes += 1,
            ProcRead::Gone => continue,
            ProcRead::Fatal(error) => return Err(HoldsError(error.to_string())),
        }

        match scan_pid_maps_for_file(pid, target_major, target_minor, target.inode) {
            ProcRead::Ok(Some(perms)) => evidence.push(Evidence::Mmap(perms)),
            ProcRead::Ok(None) => {}
            ProcRead::PermissionDenied => stats.unreadable_maps += 1,
            ProcRead::Gone => continue,
            ProcRead::Fatal(error) => return Err(HoldsError(error.to_string())),
        }

        if evidence.is_empty() {
            continue;
        }

        evidence.sort();
        evidence.dedup();
        if let Some(holder) = read_holder(pid, evidence) {
            holders.push(holder);
        }
    }

    holders.sort_by_key(|holder| holder.pid);
    Ok((holders, stats))
}

fn scan_socket_holders(
    target_inodes: &BTreeSet<u64>,
) -> Result<(Vec<Holder>, ScanStats), HoldsError> {
    let pids = list_pids().map_err(|error| HoldsError(error.to_string()))?;
    let mut holders = Vec::new();
    let mut stats = ScanStats::default();

    for pid in pids {
        match scan_pid_fds_for_sockets(pid, target_inodes) {
            ProcRead::Ok(fds) if !fds.is_empty() => {
                let mut evidence: Vec<Evidence> = fds
                    .into_iter()
                    .map(|fd| {
                        let mode = read_fd_mode(pid, fd);
                        Evidence::Fd(fd, mode)
                    })
                    .collect();
                evidence.sort();
                evidence.dedup();
                if let Some(holder) = read_holder(pid, evidence) {
                    holders.push(holder);
                }
            }
            ProcRead::Ok(_) => {}
            ProcRead::PermissionDenied => stats.unreadable_processes += 1,
            ProcRead::Gone => {}
            ProcRead::Fatal(error) => return Err(HoldsError(error.to_string())),
        }
    }

    holders.sort_by_key(|holder| holder.pid);
    Ok((holders, stats))
}

fn read_holder(pid: u32, evidence: Vec<Evidence>) -> Option<Holder> {
    let process_dir = PathBuf::from(format!("/proc/{pid}"));
    let status = match fs::read_to_string(process_dir.join("status")) {
        Ok(status) => status,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return None,
        Err(_) => String::new(),
    };
    let name = parse_status_value(&status, "Name").unwrap_or_else(|| "unknown".to_owned());
    let uid = parse_status_value(&status, "Uid")
        .and_then(|value| value.split_whitespace().next().map(str::to_owned));
    let user = uid
        .as_deref()
        .and_then(resolve_username)
        .or_else(|| uid.map(|uid| format!("uid={uid}")))
        .unwrap_or_else(|| "uid=unknown".to_owned());
    let cwd = fs::read_link(process_dir.join("cwd")).ok();

    Some(Holder {
        pid,
        name,
        user,
        cwd,
        evidence,
    })
}

fn format_port_report(port: u16, holders: &[Holder], stats: &ScanStats) -> String {
    if holders.is_empty() {
        let mut lines = vec![format!("No holders found for port {port}.")];
        append_note(&mut lines, stats);
        return lines.join("\n");
    }

    let mut lines = vec![format!(":{port}")];
    append_holder_lines(&mut lines, holders, true);
    lines.push(String::new());
    lines.push(format!(
        "{} {}",
        holders.len(),
        plural(holders.len(), "holder", "holders")
    ));
    append_note(&mut lines, stats);
    lines.join("\n")
}

fn format_path_report(path: &str, holders: &[Holder], stats: &ScanStats) -> String {
    if holders.is_empty() {
        let mut lines = vec![format!("No holders found for '{path}'.")];
        append_note(&mut lines, stats);
        return lines.join("\n");
    }

    let mut lines = vec![path.to_owned()];
    append_holder_lines(&mut lines, holders, false);
    lines.push(String::new());
    lines.push(format!(
        "{} {}",
        holders.len(),
        plural(holders.len(), "holder", "holders")
    ));
    append_note(&mut lines, stats);
    lines.join("\n")
}

fn append_holder_lines(lines: &mut Vec<String>, holders: &[Holder], show_cwd: bool) {
    for (index, holder) in holders.iter().enumerate() {
        let last = index + 1 == holders.len();
        let branch = if last { "└──" } else { "├──" };
        let child_indent = if last { "    " } else { "│   " };
        lines.push(format!(
            "{branch} {} pid={} user={}",
            holder.name, holder.pid, holder.user
        ));

        // Build a list of sub-rows: cwd first (if requested), then evidence.
        let mut sub_rows: Vec<String> = Vec::new();
        if show_cwd {
            if let Some(cwd) = &holder.cwd {
                sub_rows.push(format!("cwd {}", cwd.display()));
            } else {
                sub_rows.push("cwd (unreadable)".to_owned());
            }
        }
        for evidence in &holder.evidence {
            sub_rows.push(evidence.label());
        }

        for (sub_index, row) in sub_rows.iter().enumerate() {
            let sub_last = sub_index + 1 == sub_rows.len();
            let sub_branch = if sub_last { "└──" } else { "├──" };
            lines.push(format!("{child_indent}{sub_branch} {row}"));
        }
    }
}

fn append_note(lines: &mut Vec<String>, stats: &ScanStats) {
    if stats.has_unreadable() {
        lines.push(String::new());
        lines.push(
            "note: some processes were not readable; try sudo for complete holder details"
                .to_owned(),
        );
    }
}

fn plural<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

enum ProcRead<T> {
    Ok(T),
    PermissionDenied,
    Gone,
    Fatal(io::Error),
}

fn classify_proc_error<T>(error: io::Error) -> ProcRead<T> {
    match error.kind() {
        io::ErrorKind::NotFound => ProcRead::Gone,
        io::ErrorKind::PermissionDenied => ProcRead::PermissionDenied,
        _ => ProcRead::Fatal(error),
    }
}

fn list_pids() -> io::Result<Vec<u32>> {
    let mut pids = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        if let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        {
            pids.push(pid);
        }
    }
    pids.sort_unstable();
    Ok(pids)
}

fn scan_pid_fds_for_file(pid: u32, target: FileId) -> ProcRead<Vec<(i32, FdMode)>> {
    let fd_entries = match fs::read_dir(format!("/proc/{pid}/fd")) {
        Ok(entries) => entries,
        Err(error) => return classify_proc_error(error),
    };
    let mut fds = Vec::new();

    for fd_entry in fd_entries {
        let fd_entry = match fd_entry {
            Ok(entry) => entry,
            Err(error) => {
                if error.kind() == io::ErrorKind::PermissionDenied {
                    return ProcRead::PermissionDenied;
                }
                continue;
            }
        };
        let Some(fd) = fd_entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        match fs::metadata(fd_entry.path()) {
            Ok(metadata) if FileId::from_metadata(&metadata) == target => {
                let mode = read_fd_mode(pid, fd);
                fds.push((fd, mode));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                return ProcRead::PermissionDenied;
            }
            Err(_) => {}
        }
    }

    fds.sort_unstable_by_key(|a| a.0);
    ProcRead::Ok(fds)
}

/// Read /proc/<pid>/fdinfo/<fd> and parse the `flags:` field to determine
/// the FD access mode (O_RDONLY=0, O_WRONLY=1, O_RDWR=2). Returns
/// FdMode::Unknown when fdinfo is unreadable or the flags line is missing.
fn read_fd_mode(pid: u32, fd: i32) -> FdMode {
    let Ok(content) = fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}")) else {
        return FdMode::Unknown;
    };
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("flags:") {
            let flags = rest.trim().parse::<u64>().unwrap_or(0);
            return FdMode::from_flags(flags);
        }
    }
    FdMode::Unknown
}

fn scan_pid_fds_for_sockets(pid: u32, target_inodes: &BTreeSet<u64>) -> ProcRead<Vec<i32>> {
    let fd_entries = match fs::read_dir(format!("/proc/{pid}/fd")) {
        Ok(entries) => entries,
        Err(error) => return classify_proc_error(error),
    };
    let mut fds = Vec::new();

    for fd_entry in fd_entries {
        let fd_entry = match fd_entry {
            Ok(entry) => entry,
            Err(error) => {
                if error.kind() == io::ErrorKind::PermissionDenied {
                    return ProcRead::PermissionDenied;
                }
                continue;
            }
        };
        let Some(fd) = fd_entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        let target = match fs::read_link(fd_entry.path()) {
            Ok(target) => target,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                return ProcRead::PermissionDenied;
            }
            Err(_) => continue,
        };
        if parse_socket_inode(&target).is_some_and(|inode| target_inodes.contains(&inode)) {
            fds.push(fd);
        }
    }

    fds.sort_unstable();
    ProcRead::Ok(fds)
}

fn scan_pid_maps_for_file(
    pid: u32,
    target_major: u32,
    target_minor: u32,
    target_inode: u64,
) -> ProcRead<Option<MmapPerms>> {
    let maps = match read_proc_maps(pid) {
        ProcRead::Ok(maps) => maps,
        ProcRead::PermissionDenied => return ProcRead::PermissionDenied,
        ProcRead::Gone => return ProcRead::Gone,
        ProcRead::Fatal(error) => return ProcRead::Fatal(error),
    };

    for entry in maps {
        if entry.inode != 0
            && entry.inode == target_inode
            && entry.dev_major == target_major
            && entry.dev_minor == target_minor
        {
            return ProcRead::Ok(Some(entry.perms));
        }
    }
    ProcRead::Ok(None)
}

fn read_proc_maps(pid: u32) -> ProcRead<Vec<MapEntry>> {
    let file = match fs::File::open(format!("/proc/{pid}/maps")) {
        Ok(file) => file,
        Err(error) => return classify_proc_error(error),
    };
    let reader = io::BufReader::new(file);
    let mut entries = Vec::new();

    for line in reader.lines() {
        let line = match line {
            Ok(line) => line,
            Err(error) => return classify_proc_error(error),
        };
        let mut parts = line.split_whitespace();
        parts.next(); // address range (col 1)
        let perms_str = parts.next(); // perms (col 2: "r-xp")
        parts.next(); // offset (col 3)
        let Some(dev) = parts.next() else {
            continue;
        };
        let Some(inode) = parts.next().and_then(|value| value.parse::<u64>().ok()) else {
            continue;
        };
        let Some((dev_major, dev_minor)) = parse_dev_hex(dev) else {
            continue;
        };
        let perms = perms_str.and_then(MmapPerms::parse).unwrap_or(MmapPerms {
            read: false,
            write: false,
            execute: false,
            private: true,
        });
        entries.push(MapEntry {
            dev_major,
            dev_minor,
            inode,
            perms,
        });
    }

    ProcRead::Ok(entries)
}

fn read_proc_net_sockets() -> io::Result<Vec<SocketEntry>> {
    let mut sockets = Vec::new();
    for (path, protocol) in [
        ("/proc/net/tcp", Protocol::Tcp),
        ("/proc/net/tcp6", Protocol::Tcp),
        ("/proc/net/udp", Protocol::Udp),
        ("/proc/net/udp6", Protocol::Udp),
    ] {
        match parse_proc_net_file(Path::new(path), protocol) {
            Ok(mut entries) => sockets.append(&mut entries),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(sockets)
}

fn parse_proc_net_file(path: &Path, protocol: Protocol) -> io::Result<Vec<SocketEntry>> {
    let file = fs::File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut entries = Vec::new();

    for (index, line) in reader.lines().enumerate() {
        let line = line?;
        if index == 0 {
            continue;
        }
        if let Some(entry) = parse_proc_net_line(&line, protocol) {
            entries.push(entry);
        }
    }
    Ok(entries)
}

fn parse_proc_net_line(line: &str, protocol: Protocol) -> Option<SocketEntry> {
    let columns: Vec<&str> = line.split_whitespace().collect();
    let local = *columns.get(1)?;
    let inode = columns.get(9)?.parse().ok()?;
    let (_, port_hex) = local.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some(SocketEntry {
        protocol,
        port,
        inode,
    })
}

fn parse_socket_inode(path: &Path) -> Option<u64> {
    let text = path.to_string_lossy();
    let inode = text.strip_prefix("socket:[")?.strip_suffix(']')?;
    inode.parse().ok()
}

fn parse_status_value(status: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}:");
    status
        .lines()
        .find_map(|line| line.strip_prefix(&prefix).map(str::trim))
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn resolve_username(uid: &str) -> Option<String> {
    let passwd = fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        fields.next()?;
        let entry_uid = fields.next()?;
        (entry_uid == uid).then(|| name.to_owned())
    })
}

fn dev_major_minor(dev: u64) -> (u32, u32) {
    let major = ((dev & 0x0000_0000_000f_ff00) >> 8) | ((dev & 0xffff_f000_0000_0000) >> 32);
    let minor = (dev & 0x0000_0000_0000_00ff) | ((dev & 0x0000_0000_fff0_0000) >> 12);
    (major as u32, minor as u32)
}

fn parse_dev_hex(dev: &str) -> Option<(u32, u32)> {
    let (major, minor) = dev.split_once(':')?;
    Some((
        u32::from_str_radix(major, 16).ok()?,
        u32::from_str_radix(minor, 16).ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    fn holder(pid: u32, name: &str, evidence: Vec<Evidence>) -> Holder {
        Holder {
            pid,
            name: name.to_owned(),
            user: "rezky".to_owned(),
            cwd: None,
            evidence,
        }
    }

    #[test]
    fn target_detection_valid_port() {
        assert_eq!(parse_target("3000").unwrap(), Target::Port(3000));
        assert_eq!(parse_target("65535").unwrap(), Target::Port(65535));
    }

    #[test]
    fn target_detection_invalid_port() {
        assert_eq!(
            parse_target("0").unwrap_err().to_string(),
            "invalid port: 0"
        );
        assert_eq!(
            parse_target("65536").unwrap_err().to_string(),
            "invalid port: 65536"
        );
    }

    #[test]
    fn target_detection_path() {
        assert_eq!(
            parse_target("/tmp/file with spaces").unwrap(),
            Target::Path(PathBuf::from("/tmp/file with spaces"))
        );
    }

    #[test]
    fn renders_one_port_holder() {
        let mut row = holder(1234, "bun", vec![Evidence::Fd(8, FdMode::Read)]);
        row.cwd = Some(PathBuf::from("/home/rezky/project"));

        assert_eq!(
            format_port_report(3000, &[row], &ScanStats::default()),
            ":3000\n└── bun pid=1234 user=rezky\n    ├── cwd /home/rezky/project\n    └── fd 8 (r)\n\n1 holder"
        );
    }

    #[test]
    fn renders_multiple_port_holders() {
        let mut first = holder(1234, "bun", vec![Evidence::Fd(8, FdMode::Read)]);
        first.cwd = Some(PathBuf::from("/home/rezky/project"));
        let mut second = holder(2222, "node", vec![Evidence::Fd(9, FdMode::Read)]);
        second.cwd = Some(PathBuf::from("/home/rezky/other"));

        assert_eq!(
            format_port_report(3000, &[first, second], &ScanStats::default()),
            ":3000\n├── bun pid=1234 user=rezky\n│   ├── cwd /home/rezky/project\n│   └── fd 8 (r)\n└── node pid=2222 user=rezky\n    ├── cwd /home/rezky/other\n    └── fd 9 (r)\n\n2 holders"
        );
    }

    #[test]
    fn renders_no_port_holders() {
        assert_eq!(
            format_port_report(3000, &[], &ScanStats::default()),
            "No holders found for port 3000."
        );
    }

    #[test]
    fn renders_path_holder() {
        assert_eq!(
            format_path_report(
                "/tmp/file with spaces",
                &[holder(1234, "cat", vec![Evidence::Fd(12, FdMode::Read)])],
                &ScanStats::default()
            ),
            "/tmp/file with spaces\n└── cat pid=1234 user=rezky\n    └── fd 12 (r)\n\n1 holder"
        );
    }

    #[test]
    fn renders_path_holder_with_multiple_evidence() {
        assert_eq!(
            format_path_report(
                "/tmp/lib.so",
                &[holder(
                    1234,
                    "app",
                    vec![
                        Evidence::Fd(4, FdMode::Read),
                        Evidence::Mmap(MmapPerms {
                            read: true,
                            write: false,
                            execute: false,
                            private: true
                        })
                    ]
                )],
                &ScanStats::default()
            ),
            "/tmp/lib.so\n└── app pid=1234 user=rezky\n    ├── fd 4 (r)\n    └── mmap r--p\n\n1 holder"
        );
    }

    #[test]
    fn renders_no_path_holders() {
        assert_eq!(
            format_path_report("/tmp/empty", &[], &ScanStats::default()),
            "No holders found for '/tmp/empty'."
        );
    }

    #[test]
    fn missing_path_error_is_clean() {
        let directory = TempDir::new().unwrap();
        let missing = directory.path().join("missing file");

        assert_eq!(
            scan_path_holders(&missing).unwrap_err().to_string(),
            format!("{}: no such file or directory", missing.display())
        );
    }

    #[test]
    fn broken_symlink_error_is_clean() {
        let directory = TempDir::new().unwrap();
        let link = directory.path().join("broken link");
        symlink(directory.path().join("missing target"), &link).unwrap();

        assert_eq!(
            scan_path_holders(&link).unwrap_err().to_string(),
            format!("{}: no such file or directory", link.display())
        );
    }

    #[test]
    fn vanished_holder_is_skipped() {
        assert!(read_holder(u32::MAX, vec![Evidence::Fd(1, FdMode::Read)]).is_none());
    }

    #[test]
    fn unreadable_note_appears_only_when_relevant() {
        assert!(!format_port_report(53, &[], &ScanStats::default()).contains("note:"));
        assert!(
            format_port_report(
                53,
                &[],
                &ScanStats {
                    unreadable_processes: 1,
                    unreadable_fds: 0,
                    unreadable_maps: 0,
                },
            )
            .contains("note: some processes were not readable")
        );
    }

    #[test]
    fn stable_summary_counts() {
        let holders = vec![
            holder(1, "one", vec![Evidence::Fd(1, FdMode::Read)]),
            holder(2, "two", vec![Evidence::Fd(2, FdMode::Read)]),
        ];

        assert!(
            format_path_report("/tmp/x", &holders, &ScanStats::default()).contains("2 holders")
        );
    }

    #[test]
    fn proc_net_line_parses_local_port_and_inode() {
        let line = "0: 0100007F:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345 1 0000000000000000 100 0 0 10 0";
        assert_eq!(
            parse_proc_net_line(line, Protocol::Tcp),
            Some(SocketEntry {
                protocol: Protocol::Tcp,
                port: 3000,
                inode: 12345,
            })
        );
    }

    #[test]
    fn parse_socket_inode_from_fd_link() {
        assert_eq!(parse_socket_inode(Path::new("socket:[12345]")), Some(12345));
        assert_eq!(parse_socket_inode(Path::new("pipe:[12345]")), None);
    }

    #[test]
    fn classifies_vanished_proc_errors() {
        match classify_proc_error::<()>(io::Error::new(io::ErrorKind::NotFound, "gone")) {
            ProcRead::Gone => {}
            _ => panic!("expected gone"),
        }
    }
}
