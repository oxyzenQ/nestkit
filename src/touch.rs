// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use chrono::{DateTime, Local};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{self, BufRead};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TouchError(String);

impl fmt::Display for TouchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for TouchError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileMeta {
    pub(crate) file_type: String,
    pub(crate) size: u64,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) perms_octal: String,
    pub(crate) inode: u64,
    pub(crate) dev: u64,
    pub(crate) modified: SystemTime,
    pub(crate) accessed: SystemTime,
    pub(crate) changed: SystemTime,
    pub(crate) is_symlink: bool,
    pub(crate) symlink_target: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TouchInfo {
    pub(crate) path: PathBuf,
    pub(crate) modified: SystemTime,
    pub(crate) source: EvidenceSource,
    pub(crate) actor: String,
    pub(crate) process: Option<ProcessEvidence>,
    pub(crate) meta: Option<FileMeta>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EvidenceSource {
    Metadata,
    Audit,
    Journal,
}

impl EvidenceSource {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Metadata => "filesystem metadata",
            Self::Audit => "audit evidence",
            Self::Journal => "journal evidence",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessEvidence {
    pub(crate) name: String,
    pub(crate) pid: Option<u32>,
}

impl ProcessEvidence {
    pub(crate) fn label(&self) -> String {
        match self.pid {
            Some(pid) => format!("{} pid={pid}", self.name),
            None => self.name.clone(),
        }
    }
}

pub fn run(path: &Path) -> Result<(), Box<dyn Error>> {
    let info = inspect_path(path)?;
    println!("{}", format_report(&info));
    Ok(())
}

pub(crate) fn inspect_path(path: &Path) -> Result<TouchInfo, TouchError> {
    // Use symlink_metadata so we can detect symlinks and report their target
    let symlink_meta = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            TouchError(format!("path not found: {}", path.display()))
        } else {
            TouchError(format!("{}: {error}", path.display()))
        }
    })?;

    // For target metadata (size, type), follow the symlink
    let target_meta = if symlink_meta.file_type().is_symlink() {
        fs::metadata(path).ok()
    } else {
        Some(symlink_meta.clone())
    };

    let modified = symlink_meta
        .modified()
        .map_err(|error| TouchError(format!("{}: {error}", path.display())))?;

    // Build full FileMeta
    let meta = build_file_meta(path, &symlink_meta, target_meta.as_ref());

    let display_path = path.to_path_buf();
    let lookup_path = absolute_path(path).unwrap_or_else(|| path.to_path_buf());
    let users = parse_passwd().unwrap_or_default();

    if let Some(mut info) = try_audit_log(&display_path, &lookup_path, &users) {
        info.meta = Some(meta);
        return Ok(info);
    }

    if let Some(mut info) = try_journalctl(&display_path, &lookup_path, &users) {
        info.meta = Some(meta);
        return Ok(info);
    }

    Ok(TouchInfo {
        path: display_path,
        modified,
        source: EvidenceSource::Metadata,
        actor: "unknown".to_owned(),
        process: None,
        meta: Some(meta),
    })
}

fn build_file_meta(
    path: &Path,
    symlink_meta: &fs::Metadata,
    target_meta: Option<&fs::Metadata>,
) -> FileMeta {
    let is_symlink = symlink_meta.file_type().is_symlink();
    let symlink_target = if is_symlink {
        fs::read_link(path)
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    } else {
        None
    };

    let m = target_meta.unwrap_or(symlink_meta);
    let file_type = if is_symlink {
        "symlink".to_owned()
    } else if m.is_dir() {
        "directory".to_owned()
    } else if m.is_file() {
        "file".to_owned()
    } else {
        "special".to_owned()
    };

    let perms_octal = format!("{:04o}", m.permissions().mode() & 0o7777);

    FileMeta {
        file_type,
        size: m.len(),
        uid: m.uid(),
        gid: m.gid(),
        perms_octal,
        inode: m.ino(),
        dev: m.dev(),
        modified: m.modified().unwrap_or(UNIX_EPOCH),
        accessed: m.accessed().unwrap_or(UNIX_EPOCH),
        changed: SystemTime::UNIX_EPOCH + Duration::from_secs(m.ctime() as u64),
        is_symlink,
        symlink_target,
    }
}

fn absolute_path(path: &Path) -> Option<PathBuf> {
    if path.is_absolute() {
        return Some(path.to_path_buf());
    }
    std::env::current_dir().ok().map(|cwd| cwd.join(path))
}

fn format_report(info: &TouchInfo) -> String {
    let mut lines = vec![info.path.display().to_string()];

    // Metadata block (size, owner, perms, timestamps, inode)
    if let Some(ref meta) = info.meta {
        let uname = parse_passwd()
            .ok()
            .and_then(|u| u.get(&meta.uid).cloned())
            .unwrap_or_else(|| meta.uid.to_string());
        let gname = parse_passwd()
            .ok()
            .and_then(|u| u.get(&meta.gid).cloned())
            .unwrap_or_else(|| meta.gid.to_string());

        lines.push(format!("├── type: {}", meta.file_type));
        if meta.is_symlink {
            if let Some(ref target) = meta.symlink_target {
                lines.push(format!("├── symlink-target: {target}"));
            }
        }
        lines.push(format!("├── size: {} bytes", meta.size));
        lines.push(format!(
            "├── owner: {}:{} (uid={} gid={})",
            uname, gname, meta.uid, meta.gid
        ));
        lines.push(format!("├── perms: {}", meta.perms_octal));
        lines.push(format!("├── inode: {} (dev={})", meta.inode, meta.dev));
        lines.push(format!(
            "├── modified: {}",
            format_system_time(meta.modified)
        ));
        lines.push(format!(
            "├── accessed: {}",
            format_system_time(meta.accessed)
        ));
        lines.push(format!(
            "├── changed:  {}",
            format_system_time(meta.changed)
        ));
    } else {
        lines.push(format!(
            "├── modified: {}",
            format_system_time(info.modified)
        ));
    }

    lines.push(format!("├── source: {}", info.source.label()));

    if let Some(process) = &info.process {
        lines.push(format!("├── actor: {}", info.actor));
        lines.push(format!("└── process: {}", process.label()));
    } else {
        lines.push(format!("└── actor: {}", info.actor));
    }

    lines.push(String::new());
    lines.push(match info.source {
        EvidenceSource::Metadata => {
            "note: filesystem metadata shows when the path changed, not who changed it".to_owned()
        }
        EvidenceSource::Audit | EvidenceSource::Journal => {
            "note: actor inference is best-effort and depends on available logs".to_owned()
        }
    });

    lines.join("\n")
}

pub(crate) fn format_system_time(time: SystemTime) -> String {
    let datetime: DateTime<Local> = time.into();
    datetime.format("%Y-%m-%d %H:%M:%S").to_string()
}

fn parse_passwd() -> io::Result<HashMap<u32, String>> {
    parse_passwd_contents(&fs::read_to_string("/etc/passwd")?)
}

fn parse_passwd_contents(contents: &str) -> io::Result<HashMap<u32, String>> {
    let mut users = HashMap::new();
    for line in contents.lines() {
        let mut fields = line.split(':');
        let Some(name) = fields.next().filter(|name| !name.is_empty()) else {
            continue;
        };
        fields.next();
        let Some(uid) = fields.next().and_then(|uid| uid.parse::<u32>().ok()) else {
            continue;
        };
        users.insert(uid, name.to_owned());
    }
    Ok(users)
}

fn uid_to_user(uid: u32, users: &HashMap<u32, String>) -> String {
    users.get(&uid).cloned().unwrap_or_else(|| uid.to_string())
}

fn try_audit_log(
    display_path: &Path,
    lookup_path: &Path,
    users: &HashMap<u32, String>,
) -> Option<TouchInfo> {
    let audit_path = Path::new("/var/log/audit/audit.log");
    let file = fs::File::open(audit_path).ok()?;
    let reader = io::BufReader::new(file);
    let lookup = lookup_path.to_string_lossy();

    #[derive(Default)]
    struct AuditEvent {
        sec: u64,
        uid: Option<u32>,
        comm: Option<String>,
        pid: Option<u32>,
        syscall: Option<u64>,
        a1: Option<u64>,
        a2: Option<u64>,
        has_target_path: bool,
        success: Option<bool>,
    }

    let mut events: HashMap<String, AuditEvent> = HashMap::new();
    let mut last_match: Option<(u64, String)> = None;

    for line in reader.lines().map_while(Result::ok) {
        let Some(msg_id) = extract_audit_msg_id(&line) else {
            continue;
        };
        let is_syscall = line.contains("type=SYSCALL");
        let is_path = line.contains("type=PATH");
        if !is_syscall && !is_path {
            continue;
        }

        let entry = events.entry(msg_id.clone()).or_default();
        if entry.sec == 0
            && let Some(sec) = extract_audit_seconds(&line)
        {
            entry.sec = sec;
        }

        if is_syscall {
            entry.syscall = extract_kv_u64(&line, "syscall");
            entry.uid = extract_kv_u32(&line, "uid");
            entry.comm = extract_kv_string(&line, "comm");
            entry.pid = extract_kv_u32(&line, "pid");
            entry.a1 = extract_kv_hex_u64(&line, "a1");
            entry.a2 = extract_kv_hex_u64(&line, "a2");
            entry.success = extract_kv_string(&line, "success").map(|value| value == "yes");
        }

        if is_path
            && let Some(name) = extract_kv_string(&line, "name")
            && name == lookup
        {
            entry.has_target_path = true;
        }

        if entry.has_target_path
            && entry.success == Some(true)
            && entry
                .syscall
                .is_some_and(|syscall| audit_event_is_modification(syscall, entry.a1, entry.a2))
            && entry.sec > 0
        {
            let update = match &last_match {
                Some((last_sec, _)) => entry.sec >= *last_sec,
                None => true,
            };
            if update {
                last_match = Some((entry.sec, msg_id));
            }
        }
    }

    let (sec, id) = last_match?;
    let event = events.get(&id)?;
    let actor = event
        .uid
        .map(|uid| uid_to_user(uid, users))
        .unwrap_or_else(|| "unknown".to_owned());
    let process = event.comm.clone().map(|name| ProcessEvidence {
        name,
        pid: event.pid,
    });

    Some(TouchInfo {
        path: display_path.to_path_buf(),
        modified: UNIX_EPOCH + Duration::from_secs(sec),
        source: EvidenceSource::Audit,
        actor,
        process,
        meta: None,
    })
}

fn try_journalctl(
    display_path: &Path,
    lookup_path: &Path,
    users: &HashMap<u32, String>,
) -> Option<TouchInfo> {
    try_journalctl_command("journalctl", display_path, lookup_path, users)
}

fn try_journalctl_command(
    command: &str,
    display_path: &Path,
    lookup_path: &Path,
    users: &HashMap<u32, String>,
) -> Option<TouchInfo> {
    let escaped = escape_journal_regex(&lookup_path.to_string_lossy());
    let output = Command::new(command)
        .arg("--no-pager")
        .arg("-o")
        .arg("export")
        .arg("-r")
        .arg("--grep")
        .arg(escaped)
        .arg("-n")
        .arg("1")
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return None;
    }

    let mut fields = HashMap::new();
    for line in stdout.lines() {
        if line.trim().is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once('=') {
            fields.insert(key.to_owned(), value.to_owned());
        }
    }

    let microseconds = fields
        .get("__REALTIME_TIMESTAMP")
        .and_then(|value| value.parse::<u64>().ok())?;
    let actor = fields
        .get("_UID")
        .and_then(|uid| uid.parse::<u32>().ok())
        .map(|uid| uid_to_user(uid, users))
        .unwrap_or_else(|| "unknown".to_owned());
    let process_name = fields
        .get("_COMM")
        .cloned()
        .or_else(|| fields.get("SYSLOG_IDENTIFIER").cloned());
    let process_pid = fields.get("_PID").and_then(|pid| pid.parse::<u32>().ok());
    let process = process_name.map(|name| ProcessEvidence {
        name,
        pid: process_pid,
    });

    Some(TouchInfo {
        path: display_path.to_path_buf(),
        modified: UNIX_EPOCH + Duration::from_micros(microseconds),
        source: EvidenceSource::Journal,
        actor,
        process,
        meta: None,
    })
}

const MODIFY_SYSCALLS_X86_64: &[u64] = &[76, 77, 82, 87, 90, 92, 260, 263, 264, 268, 280, 316];
const MODIFY_SYSCALLS_AARCH64: &[u64] = &[46, 48, 49, 52, 53, 54, 55, 56, 58, 59, 64, 67];
const SYSCALL_OPEN_X86_64: u64 = 2;
const SYSCALL_OPENAT_X86_64: u64 = 257;
const SYSCALL_OPENAT_AARCH64: u64 = 56;

fn audit_event_is_modification(syscall: u64, a1: Option<u64>, a2: Option<u64>) -> bool {
    match std::env::consts::ARCH {
        "x86_64" => {
            if syscall == SYSCALL_OPEN_X86_64 {
                return open_flags_modify(a1.unwrap_or(0));
            }
            if syscall == SYSCALL_OPENAT_X86_64 {
                return open_flags_modify(a2.unwrap_or(0));
            }
            MODIFY_SYSCALLS_X86_64.contains(&syscall)
        }
        "aarch64" => {
            if syscall == SYSCALL_OPENAT_AARCH64 {
                return open_flags_modify(a2.unwrap_or(0));
            }
            MODIFY_SYSCALLS_AARCH64.contains(&syscall)
        }
        _ => {
            if syscall == SYSCALL_OPEN_X86_64 {
                return open_flags_modify(a1.unwrap_or(0));
            }
            if syscall == SYSCALL_OPENAT_X86_64 {
                return open_flags_modify(a2.unwrap_or(0));
            }
            MODIFY_SYSCALLS_X86_64.contains(&syscall)
        }
    }
}

fn open_flags_modify(flags: u64) -> bool {
    const O_WRONLY: u64 = 0o1;
    const O_RDWR: u64 = 0o2;
    const O_TRUNC: u64 = 0o1000;
    const O_CREAT: u64 = 0o100;

    (flags & (O_WRONLY | O_RDWR | O_TRUNC | O_CREAT)) != 0
}

fn extract_audit_msg_id(line: &str) -> Option<String> {
    let start = line.find("msg=audit(")?;
    let rest = &line[start + "msg=audit(".len()..];
    let end = rest.find(')')?;
    Some(rest[..end].to_owned())
}

fn extract_audit_seconds(line: &str) -> Option<u64> {
    let start = line.find("msg=audit(")?;
    let rest = &line[start + "msg=audit(".len()..];
    let end = rest.find(':')?;
    rest[..end].split('.').next()?.parse().ok()
}

fn extract_kv_string(line: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=");
    let index = line.find(&needle)?;
    let rest = &line[index + needle.len()..];

    if let Some(rest) = rest.strip_prefix('"') {
        let end = rest.find('"')?;
        return Some(rest[..end].to_owned());
    }

    let end = rest.find(' ').unwrap_or(rest.len());
    Some(rest[..end].to_owned())
}

fn extract_kv_u64(line: &str, key: &str) -> Option<u64> {
    extract_kv_string(line, key)?.parse().ok()
}

fn extract_kv_u32(line: &str, key: &str) -> Option<u32> {
    extract_kv_string(line, key)?.parse().ok()
}

fn extract_kv_hex_u64(line: &str, key: &str) -> Option<u64> {
    u64::from_str_radix(&extract_kv_string(line, key)?, 16).ok()
}

fn escape_journal_regex(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '.' | '^' | '$' | '|' | '?' | '*' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '\\'
            | '-' => {
                escaped.push('\\');
                escaped.push(character);
            }
            _ => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    fn metadata_info(path: &str) -> TouchInfo {
        TouchInfo {
            path: PathBuf::from(path),
            modified: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            source: EvidenceSource::Metadata,
            actor: "unknown".to_owned(),
            process: None,
            meta: None,
        }
    }

    #[test]
    fn renders_metadata_fallback_for_file() {
        let output = format_report(&metadata_info("/tmp/example"));

        assert!(output.contains("/tmp/example\n├── modified: "));
        assert!(output.contains("├── source: filesystem metadata"));
        assert!(output.contains("└── actor: unknown"));
        assert!(
            output.contains(
                "note: filesystem metadata shows when the path changed, not who changed it"
            )
        );
    }

    #[test]
    fn renders_audit_evidence_with_process() {
        let info = TouchInfo {
            path: PathBuf::from("/tmp/example"),
            modified: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            source: EvidenceSource::Audit,
            actor: "rezky".to_owned(),
            process: Some(ProcessEvidence {
                name: "nano".to_owned(),
                pid: Some(1234),
            }),
            meta: None,
        };

        assert!(format_report(&info).contains("└── process: nano pid=1234"));
        assert!(format_report(&info).contains("note: actor inference is best-effort"));
    }

    #[test]
    fn accepts_directory_metadata() {
        let directory = TempDir::new().unwrap();
        let info = inspect_path(directory.path()).unwrap();

        assert_eq!(info.source, EvidenceSource::Metadata);
        assert_eq!(info.actor, "unknown");
    }

    #[test]
    fn accepts_path_with_spaces() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("file with spaces");
        fs::write(&path, "hello").unwrap();
        let info = inspect_path(&path).unwrap();

        assert_eq!(info.path, path);
    }

    #[test]
    fn missing_path_error_is_clean() {
        let directory = TempDir::new().unwrap();
        let missing = directory.path().join("missing");

        assert_eq!(
            inspect_path(&missing).unwrap_err().to_string(),
            format!("path not found: {}", missing.display())
        );
    }

    #[test]
    fn broken_symlink_reports_as_symlink_with_target() {
        // Previously broken symlinks returned Err; now they're reported as
        // symlinks with their target (which may or may not exist).
        let directory = TempDir::new().unwrap();
        let link = directory.path().join("broken");
        symlink(directory.path().join("missing"), &link).unwrap();

        let info = inspect_path(&link).unwrap();
        assert_eq!(info.path, link);
        let meta = info.meta.expect("meta should be set");
        assert!(meta.is_symlink);
        assert_eq!(meta.file_type, "symlink");
        assert!(
            meta.symlink_target
                .as_ref()
                .map(|t| t.contains("missing"))
                .unwrap_or(false)
        );
    }

    #[test]
    fn inspect_does_not_change_mtime() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("file");
        fs::write(&path, "hello").unwrap();
        let before = fs::metadata(&path).unwrap().modified().unwrap();
        let _ = inspect_path(&path).unwrap();
        let after = fs::metadata(&path).unwrap().modified().unwrap();

        assert_eq!(before, after);
    }

    #[test]
    fn timestamp_format_is_stable_shape() {
        let formatted = format_system_time(UNIX_EPOCH + Duration::from_secs(1_700_000_000));

        assert_eq!(formatted.len(), 19);
        assert_eq!(&formatted[4..5], "-");
        assert_eq!(&formatted[7..8], "-");
        assert_eq!(&formatted[10..11], " ");
        assert_eq!(&formatted[13..14], ":");
        assert_eq!(&formatted[16..17], ":");
    }

    #[test]
    fn parses_passwd_contents() {
        let users = parse_passwd_contents(
            "root:x:0:0::/root:/bin/sh\nrezky:x:1000:1000::/home/rezky:/bin/zsh\n",
        )
        .unwrap();

        assert_eq!(users.get(&0).map(String::as_str), Some("root"));
        assert_eq!(users.get(&1000).map(String::as_str), Some("rezky"));
    }

    #[test]
    fn extracts_audit_fields() {
        let line = r#"type=SYSCALL msg=audit(1700000000.123:456): uid=1000 pid=1234 comm="nano" syscall=257 success=yes a2=8001"#;

        assert_eq!(
            extract_audit_msg_id(line),
            Some("1700000000.123:456".to_owned())
        );
        assert_eq!(extract_audit_seconds(line), Some(1_700_000_000));
        assert_eq!(extract_kv_u32(line, "uid"), Some(1000));
        assert_eq!(extract_kv_u32(line, "pid"), Some(1234));
        assert_eq!(extract_kv_string(line, "comm"), Some("nano".to_owned()));
        assert_eq!(extract_kv_hex_u64(line, "a2"), Some(0x8001));
    }

    #[test]
    fn open_flags_detect_modification() {
        assert!(open_flags_modify(0o1));
        assert!(open_flags_modify(0o2));
        assert!(open_flags_modify(0o100));
        assert!(open_flags_modify(0o1000));
        assert!(!open_flags_modify(0));
    }

    #[test]
    fn journal_regex_escapes_specials() {
        assert_eq!(escape_journal_regex("/etc/foo.bar"), r"/etc/foo\.bar");
        assert_eq!(escape_journal_regex("test[0]"), r"test\[0\]");
    }

    #[test]
    fn missing_journalctl_is_optional() {
        let users = HashMap::new();
        let info = try_journalctl_command(
            "zejtron-missing-journalctl-test-command",
            Path::new("/tmp/example"),
            Path::new("/tmp/example"),
            &users,
        );

        assert_eq!(info, None);
    }
}
