// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use crate::holds::{self, Evidence, Holder, ScanStats};
use crate::touch::{self, EvidenceSource, TouchInfo};
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    Port(u16),
    Path(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhyError(String);

impl fmt::Display for WhyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for WhyError {}

pub fn run(target: &str) -> Result<(), Box<dyn Error>> {
    let target = parse_target(target)?;
    let output = match target {
        Target::Port(port) => explain_port(port)?,
        Target::Path(path) => explain_path(&path)?,
    };
    println!("{output}");
    Ok(())
}

fn parse_target(input: &str) -> Result<Target, WhyError> {
    if input.chars().all(|character| character.is_ascii_digit()) {
        let port = input
            .parse::<u32>()
            .map_err(|_| WhyError(format!("invalid port: {input}")))?;
        if !(1..=u32::from(u16::MAX)).contains(&port) {
            return Err(WhyError(format!("invalid port: {input}")));
        }
        return Ok(Target::Port(port as u16));
    }

    Ok(Target::Path(PathBuf::from(input)))
}

fn explain_port(port: u16) -> Result<String, WhyError> {
    let (holders, stats) =
        holds::scan_port_holders(port).map_err(|error| WhyError(error.to_string()))?;

    if holders.is_empty() {
        if stats.has_unreadable() {
            return Ok(format_no_visible_port_reason(port));
        }
        return Ok(format!("No reason found for port {port}."));
    }

    Ok(format_port_holder_reason(port, &holders, &stats))
}

fn explain_path(path: &Path) -> Result<String, WhyError> {
    validate_path(path)?;
    let display = path.display().to_string();
    let (holders, stats) =
        holds::scan_path_holders(path).map_err(|error| WhyError(error.to_string()))?;

    if !holders.is_empty() {
        return Ok(format_path_holder_reason(&display, &holders, &stats));
    }

    let info = touch::inspect_path(path).map_err(|error| WhyError(error.to_string()))?;
    Ok(format_path_touch_reason(&info))
}

fn validate_path(path: &Path) -> Result<(), WhyError> {
    fs::metadata(path).map(|_| ()).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            WhyError(format!("path not found: {}", path.display()))
        } else {
            WhyError(format!("{}: {error}", path.display()))
        }
    })
}

fn format_port_holder_reason(port: u16, holders: &[Holder], stats: &ScanStats) -> String {
    let mut lines = vec![
        format!(":{port}"),
        "├── reason: port is open because a process owns this socket".to_owned(),
    ];
    append_holder_summaries(&mut lines, holders, true);
    lines.push("└── evidence: socket inode matched from /proc".to_owned());
    lines.push(String::new());
    lines.push(format!(
        "{} {}",
        holders.len(),
        plural(holders.len(), "reason", "reasons")
    ));
    append_incomplete_note(&mut lines, stats);
    lines.join("\n")
}

fn format_no_visible_port_reason(port: u16) -> String {
    [
        format!(":{port}"),
        "├── reason: no visible holder found".to_owned(),
        "└── evidence: process details may be incomplete".to_owned(),
        String::new(),
        "note: some processes were not readable; try sudo for complete explanation".to_owned(),
    ]
    .join("\n")
}

fn format_path_holder_reason(path: &str, holders: &[Holder], stats: &ScanStats) -> String {
    let mut lines = vec![
        path.to_owned(),
        "├── reason: path is open because a process references it".to_owned(),
    ];
    append_holder_summaries(&mut lines, holders, false);
    lines.push(format!(
        "└── evidence: {}",
        summarize_path_evidence(holders)
    ));
    lines.push(String::new());
    lines.push(format!(
        "{} {}",
        holders.len(),
        plural(holders.len(), "reason", "reasons")
    ));
    append_incomplete_note(&mut lines, stats);
    lines.join("\n")
}

fn format_path_touch_reason(info: &TouchInfo) -> String {
    let mut lines = vec![info.path.display().to_string()];
    let reason = match info.source {
        EvidenceSource::Metadata => "path exists and has modification evidence",
        EvidenceSource::Audit | EvidenceSource::Journal => "path has recent modification evidence",
    };

    lines.push(format!("├── reason: {reason}"));
    lines.push(format!(
        "├── modified: {}",
        touch::format_system_time(info.modified)
    ));
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

fn append_holder_summaries(lines: &mut Vec<String>, holders: &[Holder], show_cwd: bool) {
    for holder in holders {
        lines.push(format!(
            "├── holder: {} pid={} user={}",
            holder.name, holder.pid, holder.user
        ));

        if show_cwd && let Some(cwd) = &holder.cwd {
            lines.push(format!("│   └── cwd {}", cwd.display()));
        }

        if !show_cwd {
            for (index, evidence) in holder.evidence.iter().enumerate() {
                let branch = if index + 1 == holder.evidence.len() {
                    "└──"
                } else {
                    "├──"
                };
                lines.push(format!("│   {branch} {}", evidence.label()));
            }
        }
    }
}

fn summarize_path_evidence(holders: &[Holder]) -> &'static str {
    let has_fd = holders.iter().any(|holder| {
        holder
            .evidence
            .iter()
            .any(|evidence| matches!(evidence, Evidence::Fd(_)))
    });
    let has_mmap = holders.iter().any(|holder| {
        holder
            .evidence
            .iter()
            .any(|evidence| matches!(evidence, Evidence::Mmap))
    });

    match (has_fd, has_mmap) {
        (true, true) => "/proc/<pid>/fd link or maps entry matched this path",
        (true, false) => "/proc/<pid>/fd link matched this path",
        (false, true) => "/proc/<pid>/maps entry matched this path",
        (false, false) => "procfs matched this path",
    }
}

fn append_incomplete_note(lines: &mut Vec<String>, stats: &ScanStats) {
    if stats.has_unreadable() {
        lines.push(String::new());
        lines.push(
            "note: some processes were not readable; try sudo for complete explanation".to_owned(),
        );
    }
}

fn plural<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::touch::ProcessEvidence;
    use std::os::unix::fs::symlink;
    use std::time::{Duration, UNIX_EPOCH};
    use tempfile::TempDir;

    fn holder(pid: u32, name: &str, evidence: Vec<Evidence>) -> Holder {
        Holder {
            pid,
            name: name.to_owned(),
            user: "rezky".to_owned(),
            cwd: Some(PathBuf::from("/home/rezky/project")),
            evidence,
        }
    }

    fn quiet_stats() -> ScanStats {
        ScanStats::default()
    }

    #[test]
    fn target_detection_valid_port() {
        assert_eq!(parse_target("53").unwrap(), Target::Port(53));
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
        assert_eq!(
            parse_target("abc").unwrap(),
            Target::Path(PathBuf::from("abc"))
        );
    }

    #[test]
    fn renders_port_reason_with_holder() {
        let output =
            format_port_holder_reason(3000, &[holder(1234, "node", vec![])], &quiet_stats());

        assert!(output.contains(":3000"));
        assert!(output.contains("reason: port is open because a process owns this socket"));
        assert!(output.contains("holder: node pid=1234 user=rezky"));
        assert!(output.contains("cwd /home/rezky/project"));
        assert!(output.contains("evidence: socket inode matched from /proc"));
        assert!(output.contains("1 reason"));
    }

    #[test]
    fn renders_port_no_visible_holder_with_unreadable_note() {
        let output = format_no_visible_port_reason(53);

        assert!(output.contains(":53"));
        assert!(output.contains("reason: no visible holder found"));
        assert!(output.contains("process details may be incomplete"));
        assert!(output.contains("try sudo for complete explanation"));
    }

    #[test]
    fn renders_no_port_reason() {
        assert_eq!(
            format!("No reason found for port {}.", 3000),
            "No reason found for port 3000."
        );
    }

    #[test]
    fn renders_path_reason_with_holder_evidence() {
        let output = format_path_holder_reason(
            "/tmp/example",
            &[holder(1234, "nano", vec![Evidence::Fd(12)])],
            &quiet_stats(),
        );

        assert!(output.contains("reason: path is open because a process references it"));
        assert!(output.contains("holder: nano pid=1234 user=rezky"));
        assert!(output.contains("fd 12"));
        assert!(output.contains("evidence: /proc/<pid>/fd link matched this path"));
        assert!(output.contains("1 reason"));
    }

    #[test]
    fn renders_path_metadata_fallback() {
        let output = format_path_touch_reason(&TouchInfo {
            path: PathBuf::from("/tmp/example"),
            modified: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            source: EvidenceSource::Metadata,
            actor: "unknown".to_owned(),
            process: None,
            meta: None,
        });

        assert!(output.contains("reason: path exists and has modification evidence"));
        assert!(output.contains("source: filesystem metadata"));
        assert!(output.contains("actor: unknown"));
        assert!(output.contains("not who changed it"));
        assert!(!output.contains("try sudo for complete explanation"));
    }

    #[test]
    fn renders_path_journal_evidence() {
        let output = format_path_touch_reason(&TouchInfo {
            path: PathBuf::from("/tmp/example"),
            modified: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            source: EvidenceSource::Journal,
            actor: "rezky".to_owned(),
            process: Some(ProcessEvidence {
                name: "sudo".to_owned(),
                pid: Some(230261),
            }),
            meta: None,
        });

        assert!(output.contains("reason: path has recent modification evidence"));
        assert!(output.contains("source: journal evidence"));
        assert!(output.contains("process: sudo pid=230261"));
        assert!(output.contains("best-effort"));
    }

    #[test]
    fn missing_path_error_is_clean() {
        let directory = TempDir::new().unwrap();
        let missing = directory.path().join("missing");

        assert_eq!(
            explain_path(&missing).unwrap_err().to_string(),
            format!("path not found: {}", missing.display())
        );
    }

    #[test]
    fn broken_symlink_error_is_clean() {
        let directory = TempDir::new().unwrap();
        let link = directory.path().join("broken");
        symlink(directory.path().join("missing"), &link).unwrap();

        assert_eq!(
            explain_path(&link).unwrap_err().to_string(),
            format!("path not found: {}", link.display())
        );
    }

    #[test]
    fn path_with_spaces_works() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("file with spaces");
        fs::write(&path, "hello").unwrap();

        let output = explain_path(&path).unwrap();

        assert!(output.contains(&path.display().to_string()));
    }

    #[test]
    fn wording_does_not_overclaim() {
        let output = format_path_touch_reason(&TouchInfo {
            path: PathBuf::from("/tmp/example"),
            modified: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            source: EvidenceSource::Metadata,
            actor: "unknown".to_owned(),
            process: None,
            meta: None,
        });

        assert!(!output.contains("definitely"));
        assert!(!output.contains("malicious"));
    }

    #[test]
    fn permission_note_is_not_added_to_metadata_explanation() {
        let output = format_path_touch_reason(&TouchInfo {
            path: PathBuf::from("/tmp/example"),
            modified: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            source: EvidenceSource::Metadata,
            actor: "unknown".to_owned(),
            process: None,
            meta: None,
        });

        assert!(!output.contains("try sudo for complete explanation"));
    }

    #[test]
    fn permission_note_is_added_once_for_holder_explanation() {
        let stats = ScanStats {
            unreadable_processes: 1,
            unreadable_fds: 2,
            unreadable_maps: 3,
        };
        let output = format_path_holder_reason(
            "/tmp/example",
            &[holder(1234, "nano", vec![Evidence::Fd(12)])],
            &stats,
        );

        assert_eq!(
            output
                .matches(
                    "note: some processes were not readable; try sudo for complete explanation"
                )
                .count(),
            1
        );
    }

    #[test]
    fn stable_summary_count_for_multiple_holders() {
        let output = format_path_holder_reason(
            "/tmp/example",
            &[
                holder(1111, "nano", vec![Evidence::Fd(4)]),
                holder(2222, "vim", vec![Evidence::Mmap]),
            ],
            &quiet_stats(),
        );

        assert!(output.contains("2 reasons"));
        assert!(output.contains("/proc/<pid>/fd link or maps entry matched this path"));
    }
}
