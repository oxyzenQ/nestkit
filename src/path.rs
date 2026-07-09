// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::HashSet;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const MAX_DISPLAYED_SYMLINKS: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathMatch {
    pub path: PathBuf,
    pub executable: bool,
    pub symlink_chain: Vec<PathBuf>,
}

pub fn run(command: &str, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    let path_env = env::var_os("PATH");
    let matches = find_in_path(command, path_env.as_deref())?;

    if matches.is_empty() {
        println!("command not found in PATH: {command}");
        if verbose {
            if let Some(ref pe) = path_env {
                print_path_audit(pe);
            }
        }
        return Ok(());
    }

    let report = format_path_report(command, &matches, verbose);
    println!("{report}");

    if verbose {
        if let Some(ref pe) = path_env {
            print_path_audit(pe);
        }
    }

    Ok(())
}

pub fn format_path_report(command: &str, matches: &[PathMatch], verbose: bool) -> String {
    let Some((active, duplicates)) = matches.split_first() else {
        return format!("command not found in PATH: {command}");
    };

    let mut lines = vec![command.to_owned()];

    lines.push(format!("├── active: {}", display_match_path(active)));
    lines.push(format!("├── executable: {}", yes_no(active.executable)));
    let pkg = package_owner_multi(&active.path);
    lines.push(format!(
        "├── package: {}",
        pkg.as_deref().unwrap_or("unknown")
    ));

    if verbose {
        if let Some(meta) = file_metadata(&active.path) {
            lines.push(format!("├── size: {} bytes", meta.size));
            lines.push(format!("├── owner: {}", meta.owner));
            lines.push(format!("├── perms: {}", meta.perms));
            lines.push(format!("├── mtime: {}", meta.mtime));
        }
    }

    if duplicates.is_empty() {
        lines.push("└── duplicates: none".to_owned());
        return lines.join("\n");
    }

    lines.push("└── duplicates:".to_owned());
    for (index, path_match) in duplicates.iter().enumerate() {
        let prefix = if index + 1 == duplicates.len() {
            "    └──"
        } else {
            "    ├──"
        };
        let detail_prefix = if index + 1 == duplicates.len() {
            "       "
        } else {
            "    │  "
        };

        lines.push(format!("{prefix} {}", display_match_path(path_match)));
        lines.push(format!(
            "{detail_prefix}├── executable: {}",
            yes_no(path_match.executable)
        ));
        lines.push(format!(
            "{detail_prefix}└── package: {}",
            package_owner_multi(&path_match.path)
                .as_deref()
                .unwrap_or("unknown")
        ));
    }

    lines.join("\n")
}

pub fn find_in_path(command: &str, path_env: Option<&OsStr>) -> io::Result<Vec<PathMatch>> {
    let Some(path_env) = path_env else {
        return Ok(Vec::new());
    };

    let mut matches = Vec::new();
    let mut seen = HashSet::new();
    for directory in env::split_paths(path_env) {
        if directory.as_os_str().is_empty() {
            continue;
        }

        let candidate = directory.join(command);
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.file_type().is_file() || metadata.file_type().is_symlink() => {
                let key = dedup_key(&candidate);
                if !seen.insert(key) {
                    continue;
                }

                matches.push(PathMatch {
                    executable: fs::metadata(&candidate)
                        .map(|metadata| metadata.is_file() && is_executable(&metadata))
                        .unwrap_or(false),
                    symlink_chain: resolve_symlink_chain(&candidate),
                    path: candidate,
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }

    Ok(matches)
}

fn dedup_key(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn is_executable(metadata: &fs::Metadata) -> bool {
    metadata.permissions().mode() & 0o111 != 0
}

fn resolve_symlink_chain(path: &Path) -> Vec<PathBuf> {
    let mut chain = Vec::new();
    let mut current = path.to_path_buf();

    for _ in 0..16 {
        let Ok(target) = fs::read_link(&current) else {
            break;
        };

        chain.push(target.clone());
        current = if target.is_absolute() {
            target
        } else {
            current
                .parent()
                .map(|parent| parent.join(&target))
                .unwrap_or(target)
        };
    }

    chain
}

fn display_match_path(path_match: &PathMatch) -> String {
    let mut value = path_match.path.display().to_string();
    for target in path_match.symlink_chain.iter().take(MAX_DISPLAYED_SYMLINKS) {
        value.push_str(" -> ");
        value.push_str(&target.display().to_string());
    }
    if path_match.symlink_chain.len() > MAX_DISPLAYED_SYMLINKS {
        value.push_str(" -> ...");
    }
    value
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

/// Multi-backend package owner lookup. Tries each backend in order of
/// availability: pacman (Arch), dpkg (Debian/Ubuntu), rpm (Fedora/RHEL),
/// apk (Alpine). Returns the first match.
fn package_owner_multi(path: &Path) -> Option<String> {
    if let Some(pkg) = try_pacman(path) {
        return Some(format!("{pkg} (pacman)"));
    }
    if let Some(pkg) = try_dpkg(path) {
        return Some(format!("{pkg} (dpkg)"));
    }
    if let Some(pkg) = try_rpm(path) {
        return Some(format!("{pkg} (rpm)"));
    }
    if let Some(pkg) = try_apk(path) {
        return Some(format!("{pkg} (apk)"));
    }
    None
}

fn try_pacman(path: &Path) -> Option<String> {
    let output = Command::new("pacman")
        .args(["-Qo", "--quiet"])
        .arg(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.trim().to_owned().into()
}

fn try_dpkg(path: &Path) -> Option<String> {
    let output = Command::new("dpkg")
        .args(["-S", "--"])
        .arg(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    // dpkg -S output: "package: /path/to/file" — take first colon-separated
    stdout
        .lines()
        .next()?
        .split(':')
        .next()?
        .trim()
        .to_owned()
        .into()
}

fn try_rpm(path: &Path) -> Option<String> {
    let output = Command::new("rpm")
        .args(["-qf", "--queryformat", "%{NAME}"])
        .arg(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let pkg = stdout.trim();
    if pkg.is_empty() || pkg.contains("not installed") {
        None
    } else {
        pkg.to_owned().into()
    }
}

fn try_apk(path: &Path) -> Option<String> {
    let output = Command::new("apk")
        .args(["info", "--who-owns", "--quiet"])
        .arg(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.trim().to_owned().into()
}

/// File metadata for --verbose output.
struct FileMeta {
    size: u64,
    owner: String,
    perms: String,
    mtime: String,
}

fn file_metadata(path: &Path) -> Option<FileMeta> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::metadata(path).ok()?;
    let perms = format!("{:04o}", meta.permissions().mode() & 0o7777);
    let uid = meta.uid();
    let owner = crate::process::lookup_username(uid);
    let mtime = format_system_time(meta.modified().ok()?);
    Some(FileMeta {
        size: meta.len(),
        owner,
        perms,
        mtime,
    })
}

fn format_system_time(time: std::time::SystemTime) -> String {
    let datetime: chrono::DateTime<chrono::Local> = time.into();
    datetime.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Audit each $PATH component for security-relevant issues:
/// world-writable directories, missing directories, and directories not
/// owned by root.
fn print_path_audit(path_env: &OsStr) {
    println!();
    println!("PATH audit:");
    for directory in env::split_paths(path_env) {
        let dir_str = directory.display().to_string();
        if dir_str.is_empty() {
            continue;
        }
        match fs::metadata(&directory) {
            Ok(meta) => {
                use std::os::unix::fs::MetadataExt;
                let mode = meta.permissions().mode();
                let world_writable = mode & 0o002 != 0;
                let uid = meta.uid();
                let owner = crate::process::lookup_username(uid);
                let mut warnings = Vec::new();
                if world_writable {
                    warnings.push("world-writable".to_owned());
                }
                if uid != 0 {
                    warnings.push(format!("owned by {owner} (not root)"));
                }
                if warnings.is_empty() {
                    println!("  ✓ {dir_str}");
                } else {
                    println!("  ⚠ {dir_str} — {}", warnings.join(", "));
                }
            }
            Err(_) => {
                println!("  ✗ {dir_str} — missing");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    fn make_executable(path: &Path) {
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }

    #[test]
    fn finds_all_path_matches_in_order() {
        let first = TempDir::new().unwrap();
        let second = TempDir::new().unwrap();
        let first_cmd = first.path().join("tool");
        let second_cmd = second.path().join("tool");
        File::create(&first_cmd).unwrap();
        File::create(&second_cmd).unwrap();
        make_executable(&first_cmd);
        make_executable(&second_cmd);

        let path_env = env::join_paths([first.path(), second.path()]).unwrap();
        let matches = find_in_path("tool", Some(path_env.as_os_str())).unwrap();

        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].path, first_cmd);
        assert_eq!(matches[1].path, second_cmd);
        assert!(matches.iter().all(|path_match| path_match.executable));
    }

    #[test]
    fn duplicate_path_directories_do_not_create_duplicate_matches() {
        let directory = TempDir::new().unwrap();
        let command = directory.path().join("tool");
        File::create(&command).unwrap();
        make_executable(&command);

        let path_env = env::join_paths([directory.path(), directory.path()]).unwrap();
        let matches = find_in_path("tool", Some(path_env.as_os_str())).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].path, command);
    }

    #[test]
    fn equivalent_path_directories_keep_first_display_path() {
        let root = TempDir::new().unwrap();
        let real_directory = root.path().join("real");
        let linked_directory = root.path().join("linked");
        fs::create_dir(&real_directory).unwrap();
        symlink(&real_directory, &linked_directory).unwrap();

        let command = real_directory.join("tool");
        File::create(&command).unwrap();
        make_executable(&command);

        let path_env = env::join_paths([&linked_directory, &real_directory]).unwrap();
        let matches = find_in_path("tool", Some(path_env.as_os_str())).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].path, linked_directory.join("tool"));
    }

    #[test]
    fn report_uses_duplicates_none_for_single_match() {
        let matches = vec![PathMatch {
            path: PathBuf::from("/usr/bin/tool"),
            executable: true,
            symlink_chain: Vec::new(),
        }];

        assert_eq!(
            format_path_report("tool", &matches, false),
            "tool\n├── active: /usr/bin/tool\n├── executable: yes\n├── package: unknown\n└── duplicates: none"
        );
    }

    #[test]
    fn report_lists_only_non_active_duplicates() {
        let matches = vec![
            PathMatch {
                path: PathBuf::from("/usr/bin/tool"),
                executable: true,
                symlink_chain: Vec::new(),
            },
            PathMatch {
                path: PathBuf::from("/home/rezky/.local/bin/tool"),
                executable: true,
                symlink_chain: Vec::new(),
            },
        ];

        assert_eq!(
            format_path_report("tool", &matches, false),
            "tool\n├── active: /usr/bin/tool\n├── executable: yes\n├── package: unknown\n└── duplicates:\n    └── /home/rezky/.local/bin/tool\n       ├── executable: yes\n       └── package: unknown"
        );
    }

    #[test]
    fn resolves_symlink_chain() {
        let directory = TempDir::new().unwrap();
        let target = directory.path().join("tool-real");
        let link = directory.path().join("tool");
        File::create(&target).unwrap();
        make_executable(&target);
        symlink("tool-real", &link).unwrap();

        let path_env = env::join_paths([directory.path()]).unwrap();
        let matches = find_in_path("tool", Some(path_env.as_os_str())).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].symlink_chain, vec![PathBuf::from("tool-real")]);
        assert!(matches[0].executable);
    }
}
