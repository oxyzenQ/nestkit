// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use crate::holds::{self, Evidence, Holder, ScanStats};
#[cfg(test)]
use crate::touch::EvidenceSource;
use crate::touch::{self, TouchInfo};
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

    // Cross-reference: for each holder, also read its systemd unit (via cgroup)
    // and cmdline to synthesize a richer explanation.
    let enriched: Vec<EnrichedHolder> = holders
        .iter()
        .map(|h| EnrichedHolder {
            holder: h.clone(),
            systemd_unit: crate::process::read_systemd_unit(Path::new("/proc"), h.pid),
            cmdline: crate::process::read_cmdline(Path::new("/proc"), h.pid),
        })
        .collect();

    Ok(format_port_synthesis(port, &enriched, &stats))
}

fn explain_path(path: &Path) -> Result<String, WhyError> {
    validate_path(path)?;
    let display = path.display().to_string();

    // Always run BOTH holds and touch — the audit log might tell you who
    // wrote a file 5 minutes ago even though no FD is currently open.
    let (holders, stats) =
        holds::scan_path_holders(path).map_err(|error| WhyError(error.to_string()))?;
    let touch_info = touch::inspect_path(path).ok();

    if holders.is_empty() && touch_info.is_none() {
        return Ok(format!("No reason found for '{display}'."));
    }

    // Enrich holders with systemd unit + cmdline
    let enriched: Vec<EnrichedHolder> = holders
        .iter()
        .map(|h| EnrichedHolder {
            holder: h.clone(),
            systemd_unit: crate::process::read_systemd_unit(Path::new("/proc"), h.pid),
            cmdline: crate::process::read_cmdline(Path::new("/proc"), h.pid),
        })
        .collect();

    Ok(format_path_synthesis(
        &display,
        &enriched,
        touch_info.as_ref(),
        &stats,
    ))
}

/// A holder enriched with systemd unit and cmdline for cross-referencing.
struct EnrichedHolder {
    holder: Holder,
    systemd_unit: Option<String>,
    cmdline: Option<String>,
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

#[cfg(test)]
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

/// Synthesized port explanation: cross-references holder PID + systemd unit
/// (from cgroup) + cmdline to give a one-line "most likely explanation".
fn format_port_synthesis(port: u16, enriched: &[EnrichedHolder], stats: &ScanStats) -> String {
    let mut lines = vec![format!(":{port}")];

    // Synthesis line — the "dragon hunts the meal" one-liner
    let synthesis = synthesize_port_explanation(enriched);
    lines.push(format!("├── reason: {synthesis}"));

    // Per-holder detail with systemd unit + cmdline
    for e in enriched {
        let mut holder_line = format!(
            "├── holder: {} pid={} user={}",
            e.holder.name, e.holder.pid, e.holder.user
        );
        if let Some(ref unit) = e.systemd_unit {
            holder_line.push_str(&format!(" unit={unit}"));
        }
        lines.push(holder_line);
        if let Some(ref cmd) = e.cmdline {
            if !cmd.is_empty() && cmd.as_str() != e.holder.name {
                lines.push(format!("│   ├── cmd: {cmd}"));
            }
        }
        if let Some(ref cwd) = e.holder.cwd {
            lines.push(format!("│   └── cwd {}", cwd.display()));
        }
    }

    lines.push("└── evidence: socket inode matched from /proc/<pid>/fd".to_owned());
    lines.push(String::new());
    lines.push(format!(
        "{} {}",
        enriched.len(),
        plural(enriched.len(), "reason", "reasons")
    ));
    append_incomplete_note(&mut lines, stats);
    lines.join("\n")
}

fn synthesize_port_explanation(enriched: &[EnrichedHolder]) -> String {
    if enriched.is_empty() {
        return "no visible holder found".to_owned();
    }
    if enriched.len() == 1 {
        let e = &enriched[0];
        let mut parts = vec![format!("{} (pid={})", e.holder.name, e.holder.pid)];
        if let Some(ref unit) = e.systemd_unit {
            parts.push(format!("owned by {unit}"));
        }
        parts.push("owns this socket".to_owned());
        return parts.join(" ");
    }
    // Multiple holders — summarize
    let names: Vec<&str> = enriched.iter().map(|e| e.holder.name.as_str()).collect();
    let unique: Vec<&str> = {
        let mut seen = std::collections::HashSet::new();
        names.iter().copied().filter(|n| seen.insert(*n)).collect()
    };
    if unique.len() == 1 {
        format!(
            "{} processes named '{}' share this socket",
            enriched.len(),
            unique[0]
        )
    } else {
        format!(
            "{} processes ({}) share this socket",
            enriched.len(),
            unique.join(", ")
        )
    }
}

/// Synthesized path explanation: cross-references holds + touch metadata +
/// audit/journal evidence + systemd unit of holders.
fn format_path_synthesis(
    path: &str,
    enriched: &[EnrichedHolder],
    touch_info: Option<&TouchInfo>,
    stats: &ScanStats,
) -> String {
    let mut lines = vec![path.to_owned()];

    // Synthesis line
    let synthesis = synthesize_path_explanation(enriched, touch_info);
    lines.push(format!("├── reason: {synthesis}"));

    // Holders section (if any)
    if !enriched.is_empty() {
        lines.push(format!("├── holders ({}):", enriched.len()));
        for e in enriched {
            let mut holder_line = format!(
                "│   ├── {} pid={} user={}",
                e.holder.name, e.holder.pid, e.holder.user
            );
            if let Some(ref unit) = e.systemd_unit {
                holder_line.push_str(&format!(" unit={unit}"));
            }
            lines.push(holder_line);
            // Evidence
            for ev in &e.holder.evidence {
                lines.push(format!("│   │   ├── {}", ev.label()));
            }
        }
    }

    // Touch/metadata section (if available)
    if let Some(info) = touch_info {
        lines.push("├── metadata:".to_owned());
        if let Some(ref meta) = info.meta {
            lines.push(format!("│   ├── type: {}", meta.file_type));
            lines.push(format!("│   ├── size: {} bytes", meta.size));
            lines.push(format!("│   ├── perms: {}", meta.perms_octal));
            lines.push(format!(
                "│   ├── modified: {}",
                touch::format_system_time(meta.modified)
            ));
            lines.push(format!(
                "│   └── changed:  {}",
                touch::format_system_time(meta.changed)
            ));
        } else {
            lines.push(format!(
                "│   └── modified: {}",
                touch::format_system_time(info.modified)
            ));
        }
        if info.source != touch::EvidenceSource::Metadata {
            lines.push(format!(
                "├── actor: {} ({})",
                info.actor,
                info.source.label()
            ));
            if let Some(proc) = &info.process {
                lines.push(format!("│   └── process: {}", proc.label()));
            }
        }
    }

    lines.push(format!(
        "└── evidence: {}",
        if enriched.is_empty() {
            "filesystem metadata"
        } else {
            summarize_path_evidence(
                &enriched
                    .iter()
                    .map(|e| e.holder.clone())
                    .collect::<Vec<_>>(),
            )
        }
    ));
    lines.push(String::new());
    let reason_count = enriched.len() + if touch_info.is_some() { 1 } else { 0 };
    lines.push(format!(
        "{} {}",
        reason_count,
        plural(reason_count, "reason", "reasons")
    ));
    append_incomplete_note(&mut lines, stats);
    lines.join("\n")
}

fn synthesize_path_explanation(
    enriched: &[EnrichedHolder],
    touch_info: Option<&TouchInfo>,
) -> String {
    match (enriched.is_empty(), touch_info) {
        (false, Some(info)) => {
            // Both holders and touch — combine
            let holder_names: Vec<&str> = enriched.iter().map(|e| e.holder.name.as_str()).collect();
            let unique: Vec<&str> = {
                let mut seen = std::collections::HashSet::new();
                holder_names
                    .iter()
                    .copied()
                    .filter(|n| seen.insert(*n))
                    .collect()
            };
            let actor = if info.actor != "unknown" {
                format!("last modified by {}", info.actor)
            } else {
                "modification time on record".to_owned()
            };
            if unique.len() == 1 {
                format!(
                    "currently held by {} (pid={}), {}",
                    enriched[0].holder.name, enriched[0].holder.pid, actor
                )
            } else {
                format!(
                    "{} processes ({}) hold this path, {}",
                    enriched.len(),
                    unique.join(", "),
                    actor
                )
            }
        }
        (false, None) => {
            let holder_names: Vec<&str> = enriched.iter().map(|e| e.holder.name.as_str()).collect();
            let unique: Vec<&str> = {
                let mut seen = std::collections::HashSet::new();
                holder_names
                    .iter()
                    .copied()
                    .filter(|n| seen.insert(*n))
                    .collect()
            };
            if unique.len() == 1 {
                format!(
                    "currently held by {} (pid={})",
                    enriched[0].holder.name, enriched[0].holder.pid
                )
            } else {
                format!(
                    "{} processes ({}) hold this path",
                    enriched.len(),
                    unique.join(", ")
                )
            }
        }
        (true, Some(info)) => {
            if info.actor != "unknown" {
                format!("last modified by {} ({})", info.actor, info.source.label())
            } else {
                "path exists with filesystem metadata only".to_owned()
            }
        }
        (true, None) => "no evidence found".to_owned(),
    }
}

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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
            .any(|evidence| matches!(evidence, Evidence::Fd(_, _)))
    });
    let has_mmap = holders.iter().any(|holder| {
        holder
            .evidence
            .iter()
            .any(|evidence| matches!(evidence, Evidence::Mmap(_)))
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
    use crate::touch::{EvidenceSource, ProcessEvidence};
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
            &[holder(
                1234,
                "nano",
                vec![Evidence::Fd(12, holds::FdMode::Read)],
            )],
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
            &[holder(
                1234,
                "nano",
                vec![Evidence::Fd(12, holds::FdMode::Read)],
            )],
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
                holder(1111, "nano", vec![Evidence::Fd(4, holds::FdMode::Read)]),
                holder(
                    2222,
                    "vim",
                    vec![Evidence::Mmap(holds::MmapPerms {
                        read: true,
                        write: false,
                        execute: false,
                        private: true,
                    })],
                ),
            ],
            &quiet_stats(),
        );

        assert!(output.contains("2 reasons"));
        assert!(output.contains("/proc/<pid>/fd link or maps entry matched this path"));
    }
}
