// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use std::cmp::Reverse;
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const IGNORED_DIRECTORIES: &[&str] = &[".git", "target", "node_modules", ".cache"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecentFile {
    pub path: PathBuf,
    pub modified: SystemTime,
    pub changed: SystemTime,
    pub size: u64,
    pub uid: u32,
    pub perms: u32,
}

pub fn run(
    path: &Path,
    limit: usize,
    since: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let since = since.map(parse_duration).transpose()?;
    let files = select_recent_files(scan_recent_files(path)?, limit, since, SystemTime::now());

    if files.is_empty() {
        println!("no modified files found");
        return Ok(());
    }

    let now = SystemTime::now();
    let rows: Vec<(String, String, String)> = files
        .iter()
        .map(|file| {
            let owner = crate::process::lookup_username(file.uid);
            (
                display_relative_path(path, &file.path),
                rough_age(now, file.modified),
                format!(
                    "{} {} {:04o}",
                    human_size(file.size),
                    owner,
                    file.perms & 0o7777
                ),
            )
        })
        .collect();
    let width = rows
        .iter()
        .map(|(path, _, _)| path.chars().count())
        .max()
        .unwrap_or(0);

    println!("modified files:");
    for (index, (path, age, meta)) in rows.iter().enumerate() {
        let prefix = if index + 1 == rows.len() {
            "└──"
        } else {
            "├──"
        };
        println!("{prefix} {path:<width$}  {age}  {meta}");
    }

    Ok(())
}

pub fn parse_duration(input: &str) -> Result<Duration, String> {
    if input.len() < 2 {
        return Err(format!("invalid duration: {input}"));
    }

    let (amount, unit) = input.split_at(input.len() - 1);
    let amount: u64 = amount
        .parse()
        .map_err(|_| format!("invalid duration: {input}"))?;

    match unit {
        "m" => Ok(Duration::from_secs(amount * 60)),
        "h" => Ok(Duration::from_secs(amount * 60 * 60)),
        "d" => Ok(Duration::from_secs(amount * 24 * 60 * 60)),
        _ => Err(format!("invalid duration: {input}")),
    }
}

pub fn sort_newest_first(files: &mut [RecentFile]) {
    files.sort_by_key(|file| Reverse(file.modified));
}

fn select_recent_files(
    mut files: Vec<RecentFile>,
    limit: usize,
    since: Option<Duration>,
    now: SystemTime,
) -> Vec<RecentFile> {
    sort_newest_first(&mut files);

    if let Some(since) = since {
        files.retain(|file| {
            now.duration_since(file.modified)
                .map(|age| age <= since)
                .unwrap_or(true)
        });
    }

    files.truncate(limit);
    files
}

fn scan_recent_files(path: &Path) -> io::Result<Vec<RecentFile>> {
    let mut files = Vec::new();
    scan_path(path, &mut files, true)?;
    Ok(files)
}

fn scan_path(path: &Path, files: &mut Vec<RecentFile>, is_root: bool) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if is_skippable_error(&error) && !is_root => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return Ok(()),
        Err(error) => return Err(error),
    };

    if metadata.is_file() {
        if let Ok(modified) = metadata.modified() {
            let changed = SystemTime::UNIX_EPOCH + Duration::from_secs(metadata.ctime() as u64);
            files.push(RecentFile {
                path: path.to_path_buf(),
                modified,
                changed,
                size: metadata.len(),
                uid: metadata.uid(),
                perms: metadata.permissions().mode(),
            });
        }
        return Ok(());
    }

    if !metadata.is_dir() {
        return Ok(());
    }

    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) if is_skippable_error(&error) => return Ok(()),
        Err(error) => return Err(error),
    };

    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let entry_path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };

        if file_type.is_dir() {
            if should_ignore_directory(&entry_path) {
                continue;
            }
            scan_path(&entry_path, files, false)?;
        } else if file_type.is_file() {
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            let Ok(modified) = metadata.modified() else {
                continue;
            };
            let changed = SystemTime::UNIX_EPOCH + Duration::from_secs(metadata.ctime() as u64);
            files.push(RecentFile {
                path: entry_path,
                modified,
                changed,
                size: metadata.len(),
                uid: metadata.uid(),
                perms: metadata.permissions().mode(),
            });
        }
    }

    Ok(())
}

fn is_skippable_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
    )
}

fn should_ignore_directory(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| IGNORED_DIRECTORIES.contains(&name))
        .unwrap_or(false)
}

fn display_relative_path(base: &Path, path: &Path) -> String {
    path.strip_prefix(base)
        .ok()
        .filter(|relative| !relative.as_os_str().is_empty())
        .unwrap_or(path)
        .display()
        .to_string()
}

fn rough_age(now: SystemTime, modified: SystemTime) -> String {
    let age = now.duration_since(modified).unwrap_or(Duration::ZERO);
    let seconds = age.as_secs();

    if seconds < 60 {
        format!("{seconds}s ago")
    } else if seconds < 60 * 60 {
        format!("{}m ago", seconds / 60)
    } else if seconds < 24 * 60 * 60 {
        format!("{}h ago", seconds / (60 * 60))
    } else {
        format!("{}d ago", seconds / (24 * 60 * 60))
    }
}

fn human_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1}GB", bytes as f64 / 1024.0 / 1024.0 / 1024.0)
    } else if bytes >= 1024 * 1024 {
        format!("{:.1}MB", bytes as f64 / 1024.0 / 1024.0)
    } else if bytes >= 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes}B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use tempfile::TempDir;

    #[test]
    fn parses_minutes_hours_and_days() {
        assert_eq!(parse_duration("10m").unwrap(), Duration::from_secs(600));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7_200));
        assert_eq!(parse_duration("1d").unwrap(), Duration::from_secs(86_400));
    }

    #[test]
    fn rejects_invalid_duration() {
        assert!(parse_duration("soon").is_err());
        assert!(parse_duration("10x").is_err());
        assert!(parse_duration("m").is_err());
    }

    #[test]
    fn sorts_newest_first() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let mut files = vec![
            RecentFile {
                path: PathBuf::from("old"),
                modified: now - Duration::from_secs(20),
                changed: now - Duration::from_secs(20),
                size: 100,
                uid: 1000,
                perms: 0o644,
            },
            RecentFile {
                path: PathBuf::from("new"),
                modified: now,
                changed: now,
                size: 100,
                uid: 1000,
                perms: 0o644,
            },
            RecentFile {
                path: PathBuf::from("middle"),
                modified: now - Duration::from_secs(10),
                changed: now - Duration::from_secs(10),
                size: 100,
                uid: 1000,
                perms: 0o644,
            },
        ];

        sort_newest_first(&mut files);

        assert_eq!(files[0].path, PathBuf::from("new"));
        assert_eq!(files[1].path, PathBuf::from("middle"));
        assert_eq!(files[2].path, PathBuf::from("old"));
    }

    #[test]
    fn limit_zero_selects_no_files() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let files = vec![RecentFile {
            path: PathBuf::from("file"),
            modified: now,
            changed: now,
            size: 100,
            uid: 1000,
            perms: 0o644,
        }];

        assert!(select_recent_files(files, 0, None, now).is_empty());
    }

    #[test]
    fn invalid_since_fails_before_scanning() {
        let directory = TempDir::new().unwrap();

        assert!(run(directory.path(), 20, Some("bad")).is_err());
    }

    #[test]
    fn scan_skips_ignored_directories() {
        let directory = TempDir::new().unwrap();
        File::create(directory.path().join("visible")).unwrap();

        for ignored in IGNORED_DIRECTORIES {
            let ignored_directory = directory.path().join(ignored);
            fs::create_dir(&ignored_directory).unwrap();
            File::create(ignored_directory.join("hidden")).unwrap();
        }

        let files = scan_recent_files(directory.path()).unwrap();

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, directory.path().join("visible"));
    }
}
