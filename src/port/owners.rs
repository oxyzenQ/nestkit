// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io;
use std::path::Path;

use super::model::{OwnerMap, ProcessInfo, ScanStats};

pub(crate) fn map_socket_owners(
    proc_root: &Path,
    wanted_inodes: &BTreeSet<u64>,
) -> (OwnerMap, ScanStats) {
    let mut owners: OwnerMap = HashMap::new();
    let mut stats = ScanStats::default();
    let Ok(entries) = fs::read_dir(proc_root) else {
        return (owners, stats);
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(pid) = file_name.to_str().and_then(|name| name.parse::<u32>().ok()) else {
            continue;
        };

        let process_dir = entry.path();
        let fd_dir = process_dir.join("fd");
        let fd_entries = match fs::read_dir(&fd_dir) {
            Ok(entries) => entries,
            Err(error) if is_permission_or_disappeared(&error) => {
                stats.unreadable_processes += 1;
                continue;
            }
            Err(_) => continue,
        };

        let mut matched_inodes: BTreeSet<(u64, Option<i32>)> = BTreeSet::new();
        for fd_entry in fd_entries {
            let Ok(fd_entry) = fd_entry else {
                stats.unreadable_fds += 1;
                continue;
            };
            let target = match fs::read_link(fd_entry.path()) {
                Ok(target) => target,
                Err(error) if is_permission_or_disappeared(&error) => {
                    stats.unreadable_fds += 1;
                    continue;
                }
                Err(_) => continue,
            };
            let Some(inode) = parse_socket_inode(&target) else {
                continue;
            };
            if wanted_inodes.contains(&inode) {
                let fd_num = fd_entry
                    .file_name()
                    .to_str()
                    .and_then(|s| s.parse::<i32>().ok());
                matched_inodes.insert((inode, fd_num));
            }
        }

        if matched_inodes.is_empty() {
            continue;
        }

        let mut process = read_process_info(&process_dir, pid);
        // Read cmdline once per process to share across all its sockets
        process.cmdline = crate::process::read_cmdline(Path::new("/proc"), pid);

        for (inode, fd) in matched_inodes {
            let mut entry = process.clone();
            entry.fd = fd;
            owners.entry(inode).or_default().push(entry);
        }
    }

    for processes in owners.values_mut() {
        processes.sort_by_key(|process| process.pid);
    }
    (owners, stats)
}

fn is_permission_or_disappeared(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound
    )
}

fn parse_socket_inode(path: &Path) -> Option<u64> {
    let text = path.to_string_lossy();
    let inode = text.strip_prefix("socket:[")?.strip_suffix(']')?;
    inode.parse().ok()
}

fn read_process_info(process_dir: &Path, pid: u32) -> ProcessInfo {
    let status = fs::read_to_string(process_dir.join("status")).unwrap_or_default();
    let name = parse_status_value(&status, "Name").unwrap_or_else(|| "unknown".to_owned());
    let uid = parse_status_value(&status, "Uid")
        .and_then(|value| value.split_whitespace().next().map(ToOwned::to_owned));
    let user = uid
        .as_deref()
        .and_then(resolve_username)
        .or_else(|| uid.map(|uid| format!("uid={uid}")))
        .unwrap_or_else(|| "uid=unknown".to_owned());
    let cwd = fs::read_link(process_dir.join("cwd")).ok();

    ProcessInfo {
        pid,
        name,
        user,
        cwd,
        cmdline: None,
        fd: None,
    }
}

fn parse_status_value(status: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}:");
    status
        .lines()
        .find_map(|line| line.strip_prefix(&prefix).map(str::trim))
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
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
