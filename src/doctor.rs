// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use std::error::Error;
use std::fs;
use std::io::{self, BufRead};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckStatus {
    Ok,
    Warn,
    Fail,
}

impl CheckStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CheckResult {
    status: CheckStatus,
    check: &'static str,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Summary {
    ok: usize,
    warn: usize,
    fail: usize,
}

pub fn run(git_hash: &str) -> Result<(), Box<dyn Error>> {
    let checks = collect_checks(git_hash);
    let summary = summarize(&checks);
    println!("{}", format_report(&checks, summary, git_hash));
    // Non-zero exit on FAIL so CI / automation can gate on doctor.
    if summary.fail > 0 {
        return Err("doctor checks failed".into());
    }
    Ok(())
}

fn collect_checks(git_hash: &str) -> Vec<CheckResult> {
    vec![
        check_os(),
        check_kernel_distro(),
        check_container(),
        check_procfs(Path::new("/proc")),
        check_visible_pids(Path::new("/proc")),
        check_proc_access(Path::new("/proc/1/comm")),
        check_proc_net(Path::new("/proc/net")),
        check_holders(Path::new("/proc/self/fd")),
        check_audit_log(Path::new("/var/log/audit/audit.log")),
        check_journalctl("journalctl"),
        check_systemctl("systemctl"),
        check_build_metadata(git_hash),
    ]
}

fn check_kernel_distro() -> CheckResult {
    let kernel = run_uname_r().unwrap_or_else(|| "unknown".to_owned());
    let distro = read_distro().unwrap_or_else(|| "unknown".to_owned());
    CheckResult {
        status: CheckStatus::Ok,
        check: "kernel",
        message: format!("{kernel} | {distro}"),
    }
}

fn run_uname_r() -> Option<String> {
    let out = Command::new("uname").arg("-r").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if s.is_empty() { None } else { Some(s) }
}

fn read_distro() -> Option<String> {
    let content = fs::read_to_string("/etc/os-release").ok()?;
    let mut name = None;
    let mut version = None;
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("PRETTY_NAME=") {
            return Some(v.trim_matches('"').to_owned());
        }
        if let Some(v) = line.strip_prefix("NAME=") {
            name = Some(v.trim_matches('"').to_owned());
        }
        if let Some(v) = line.strip_prefix("VERSION=") {
            version = Some(v.trim_matches('"').to_owned());
        }
    }
    match (name, version) {
        (Some(n), Some(v)) => Some(format!("{n} {v}")),
        (Some(n), None) => Some(n),
        _ => None,
    }
}

fn check_container() -> CheckResult {
    let mut evidence = Vec::new();
    // /.dockerenv is the classic Docker marker
    if Path::new("/.dockerenv").exists() {
        evidence.push("/.dockerenv".to_owned());
    }
    // /run/.containerenv is the podman marker
    if Path::new("/run/.containerenv").exists() {
        evidence.push("/run/.containerenv".to_owned());
    }
    // /proc/1/cgroup containing /docker/ or /kubepods/ indicates a container
    if let Ok(cg) = fs::read_to_string("/proc/1/cgroup") {
        if cg.contains("/docker/") || cg.contains("/kubepods/") || cg.contains("/lxc/") {
            evidence.push("cgroup indicates container".to_owned());
        }
    }
    // /proc/1/sched shows the init process name; in containers it's not "systemd" or "init"
    if let Ok(sched) = fs::read_to_string("/proc/1/sched") {
        let first_line = sched.lines().next().unwrap_or("");
        // In a real host, PID 1 is usually systemd/init. In a container it's
        // typically the entrypoint binary.
        if !first_line.contains("systemd")
            && !first_line.contains("init")
            && !first_line.contains("/sbin/init")
            && !first_line.is_empty()
        {
            // Only flag if other evidence also present, to avoid false positives
            // on minimal hosts
            if !evidence.is_empty() {
                evidence.push(format!("pid 1: {first_line}"));
            }
        }
    }

    if evidence.is_empty() {
        CheckResult {
            status: CheckStatus::Ok,
            check: "container",
            message: "bare-metal or VM (no container markers found)".to_owned(),
        }
    } else {
        CheckResult {
            status: CheckStatus::Warn,
            check: "container",
            message: format!("running inside container ({})", evidence.join(", ")),
        }
    }
}

fn format_report(checks: &[CheckResult], summary: Summary, git_hash: &str) -> String {
    let build = build_label(git_hash);
    let mut lines = vec![
        "Doctor report:".to_owned(),
        mode_label(effective_uid()),
        "STATUS  CHECK                 MESSAGE".to_owned(),
    ];

    for check in checks {
        lines.push(format_check_row(check));
    }

    lines.push(String::new());
    lines.push(format_summary(summary));
    lines.push(format!("Build: {build}"));
    lines.join("\n")
}

fn format_check_row(check: &CheckResult) -> String {
    format!(
        "{:<6}  {:<20} {}",
        check.status.label(),
        check.check,
        check.message
    )
}

fn summarize(checks: &[CheckResult]) -> Summary {
    let mut summary = Summary {
        ok: 0,
        warn: 0,
        fail: 0,
    };

    for check in checks {
        match check.status {
            CheckStatus::Ok => summary.ok += 1,
            CheckStatus::Warn => summary.warn += 1,
            CheckStatus::Fail => summary.fail += 1,
        }
    }

    summary
}

fn format_summary(summary: Summary) -> String {
    format!(
        "Summary: ok={} warn={} fail={}",
        summary.ok, summary.warn, summary.fail
    )
}

fn mode_label(uid: Option<u32>) -> String {
    if uid == Some(0) {
        "Mode: privileged".to_owned()
    } else {
        "Mode: unprivileged (partial results expected)".to_owned()
    }
}

fn effective_uid() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        let Some(rest) = line.strip_prefix("Uid:") else {
            continue;
        };
        let mut fields = rest.split_whitespace();
        fields.next();
        return fields.next()?.parse::<u32>().ok();
    }
    None
}

fn build_label(git_hash: &str) -> String {
    format!(
        "zejtron v{} ({})",
        env!("CARGO_PKG_VERSION"),
        short_hash(git_hash)
    )
}

fn short_hash(hash: &str) -> &str {
    let hash = hash.trim();
    if hash.is_empty() {
        "unknown"
    } else {
        hash.get(0..7).unwrap_or(hash)
    }
}

fn check_os() -> CheckResult {
    if std::env::consts::OS == "linux" {
        return CheckResult {
            status: CheckStatus::Ok,
            check: "os",
            message: "linux".to_owned(),
        };
    }

    CheckResult {
        status: CheckStatus::Fail,
        check: "os",
        message: format!("unsupported OS: {}", std::env::consts::OS),
    }
}

fn check_procfs(proc_path: &Path) -> CheckResult {
    match fs::metadata(proc_path) {
        Ok(metadata) if metadata.is_dir() => CheckResult {
            status: CheckStatus::Ok,
            check: "procfs",
            message: format!("{} present", proc_path.display()),
        },
        Ok(_) => CheckResult {
            status: CheckStatus::Fail,
            check: "procfs",
            message: format!("{} is not a directory", proc_path.display()),
        },
        Err(error) => CheckResult {
            status: CheckStatus::Fail,
            check: "procfs",
            message: format!("{} not accessible: {error}", proc_path.display()),
        },
    }
}

fn check_visible_pids(proc_path: &Path) -> CheckResult {
    match count_visible_pids(proc_path) {
        Ok(0) => CheckResult {
            status: CheckStatus::Fail,
            check: "pids",
            message: "no visible processes".to_owned(),
        },
        Ok(count) if count < 3 => CheckResult {
            status: CheckStatus::Warn,
            check: "pids",
            message: format!("{count} processes visible; procfs may be restricted"),
        },
        Ok(count) => CheckResult {
            status: CheckStatus::Ok,
            check: "pids",
            message: format!("{count} processes visible"),
        },
        Err(error) => CheckResult {
            status: CheckStatus::Fail,
            check: "pids",
            message: format!("cannot scan {}: {error}", proc_path.display()),
        },
    }
}

fn count_visible_pids(proc_path: &Path) -> io::Result<usize> {
    let mut count = 0;
    for entry in fs::read_dir(proc_path)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.chars().all(|character| character.is_ascii_digit()))
        {
            count += 1;
        }
    }
    Ok(count)
}

fn check_proc_access(comm_path: &Path) -> CheckResult {
    match fs::read_to_string(comm_path) {
        Ok(_) => CheckResult {
            status: CheckStatus::Ok,
            check: "proc_access",
            message: format!("can read {}", comm_path.display()),
        },
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => CheckResult {
            status: CheckStatus::Warn,
            check: "proc_access",
            message: format!("permission denied reading {}", comm_path.display()),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => CheckResult {
            status: CheckStatus::Warn,
            check: "proc_access",
            message: format!("{} not found", comm_path.display()),
        },
        Err(error) => CheckResult {
            status: CheckStatus::Warn,
            check: "proc_access",
            message: format!("error reading {}: {error}", comm_path.display()),
        },
    }
}

fn check_proc_net(proc_net: &Path) -> CheckResult {
    let files = ["tcp", "udp", "tcp6", "udp6"];
    let mut parsed = 0usize;
    let mut unavailable = 0usize;

    for file in files {
        match count_proc_net_sockets(&proc_net.join(file)) {
            Ok(count) => parsed += count,
            Err(_) => unavailable += 1,
        }
    }

    if parsed > 0 && unavailable == 0 {
        return CheckResult {
            status: CheckStatus::Ok,
            check: "proc_net",
            message: format!("{parsed} sockets parsed"),
        };
    }

    if parsed > 0 {
        return CheckResult {
            status: CheckStatus::Warn,
            check: "proc_net",
            message: format!("{parsed} sockets parsed; {unavailable} proc-net files unavailable"),
        };
    }

    CheckResult {
        status: CheckStatus::Fail,
        check: "proc_net",
        message: "no /proc/net socket files could be parsed".to_owned(),
    }
}

fn count_proc_net_sockets(path: &Path) -> io::Result<usize> {
    let file = fs::File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut count = 0usize;

    for (index, line) in reader.lines().enumerate() {
        let line = line?;
        if index == 0 {
            continue;
        }
        if proc_net_line_has_socket(&line) {
            count += 1;
        }
    }

    Ok(count)
}

fn proc_net_line_has_socket(line: &str) -> bool {
    let columns: Vec<&str> = line.split_whitespace().collect();
    if columns.len() < 10 {
        return false;
    }
    let Some(local) = columns.get(1) else {
        return false;
    };
    let Some((_, port_hex)) = local.split_once(':') else {
        return false;
    };
    u16::from_str_radix(port_hex, 16).is_ok() && columns[9].parse::<u64>().is_ok()
}

fn check_holders(fd_path: &Path) -> CheckResult {
    match fs::read_dir(fd_path) {
        Ok(_) => CheckResult {
            status: CheckStatus::Ok,
            check: "holders",
            message: "current process fd directory readable".to_owned(),
        },
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => CheckResult {
            status: CheckStatus::Warn,
            check: "holders",
            message: "fd scanning appears restricted; sudo may reveal more holder details"
                .to_owned(),
        },
        Err(error) => CheckResult {
            status: CheckStatus::Warn,
            check: "holders",
            message: format!("fd scan smoke failed: {error}"),
        },
    }
}

fn check_audit_log(path: &Path) -> CheckResult {
    match fs::metadata(path) {
        Ok(_) => match fs::File::open(path) {
            Ok(_) => CheckResult {
                status: CheckStatus::Ok,
                check: "audit_log",
                message: "audit log readable".to_owned(),
            },
            Err(error) => CheckResult {
                status: CheckStatus::Warn,
                check: "audit_log",
                message: format!("audit log unavailable: {error}"),
            },
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => CheckResult {
            status: CheckStatus::Warn,
            check: "audit_log",
            message: "audit log unavailable: not found".to_owned(),
        },
        Err(error) => CheckResult {
            status: CheckStatus::Warn,
            check: "audit_log",
            message: format!("audit log unavailable: {error}"),
        },
    }
}

fn check_journalctl(command: &str) -> CheckResult {
    check_command_version(
        "journalctl",
        command,
        &["--version"],
        "available",
        "unavailable or not usable",
    )
}

fn check_systemctl(command: &str) -> CheckResult {
    check_command_version(
        "systemctl",
        command,
        &[
            "list-units",
            "--type=service",
            "--no-legend",
            "--no-pager",
            "--plain",
        ],
        "available and systemd is usable",
        "unavailable or not usable",
    )
}

fn check_command_version(
    check: &'static str,
    command: &str,
    args: &[&str],
    ok_message: &str,
    warn_message: &str,
) -> CheckResult {
    match Command::new(command).args(args).output() {
        Ok(output) if output.status.success() => CheckResult {
            status: CheckStatus::Ok,
            check,
            message: ok_message.to_owned(),
        },
        Ok(output) => {
            let detail = first_output_line(&output.stderr, &output.stdout)
                .unwrap_or_else(|| "command returned non-zero".to_owned());
            CheckResult {
                status: CheckStatus::Warn,
                check,
                message: format!("{warn_message}: {detail}"),
            }
        }
        Err(error) => CheckResult {
            status: CheckStatus::Warn,
            check,
            message: format!("{warn_message}: {error}"),
        },
    }
}

fn first_output_line(stderr: &[u8], stdout: &[u8]) -> Option<String> {
    let stderr = String::from_utf8_lossy(stderr);
    let stdout = String::from_utf8_lossy(stdout);
    stderr
        .lines()
        .chain(stdout.lines())
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_owned)
}

fn check_build_metadata(git_hash: &str) -> CheckResult {
    CheckResult {
        status: CheckStatus::Ok,
        check: "build_meta",
        message: build_label(git_hash),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn result(status: CheckStatus, check: &'static str, message: &str) -> CheckResult {
        CheckResult {
            status,
            check,
            message: message.to_owned(),
        }
    }

    #[test]
    fn summary_count_formatting() {
        let checks = [
            result(CheckStatus::Ok, "one", "ok"),
            result(CheckStatus::Warn, "two", "warn"),
            result(CheckStatus::Fail, "three", "fail"),
        ];

        assert_eq!(
            format_summary(summarize(&checks)),
            "Summary: ok=1 warn=1 fail=1"
        );
    }

    #[test]
    fn status_row_formatting() {
        assert_eq!(
            format_check_row(&result(CheckStatus::Warn, "journalctl", "missing")),
            "WARN    journalctl           missing"
        );
    }

    #[test]
    fn mode_labels_are_stable() {
        assert_eq!(mode_label(Some(0)), "Mode: privileged");
        assert_eq!(
            mode_label(Some(1000)),
            "Mode: unprivileged (partial results expected)"
        );
        assert_eq!(
            mode_label(None),
            "Mode: unprivileged (partial results expected)"
        );
    }

    #[test]
    fn missing_systemctl_is_warn_not_fail() {
        let check = check_systemctl("zejtron-missing-systemctl-test-command");

        assert_eq!(check.status, CheckStatus::Warn);
        assert_eq!(check.check, "systemctl");
    }

    #[test]
    fn missing_journalctl_is_warn_not_fail() {
        let check = check_journalctl("zejtron-missing-journalctl-test-command");

        assert_eq!(check.status, CheckStatus::Warn);
        assert_eq!(check.check, "journalctl");
    }

    #[test]
    fn procfs_missing_is_fail() {
        let directory = TempDir::new().unwrap();
        let check = check_procfs(&directory.path().join("missing-proc"));

        assert_eq!(check.status, CheckStatus::Fail);
        assert_eq!(check.check, "procfs");
    }

    #[test]
    fn proc_net_parse_count_formatting() {
        let directory = TempDir::new().unwrap();
        fs::write(
            directory.path().join("tcp"),
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 46743 2 0000000000000000 100 0 0 10 0\n",
        )
        .unwrap();

        let check = check_proc_net(directory.path());

        assert_eq!(check.status, CheckStatus::Warn);
        assert_eq!(check.check, "proc_net");
        assert!(check.message.contains("1 sockets parsed"));
    }

    #[test]
    fn build_metadata_row() {
        let check = check_build_metadata("abcdef123");

        assert_eq!(check.status, CheckStatus::Ok);
        assert_eq!(check.check, "build_meta");
        assert!(check.message.contains("zejtron v"));
        assert!(check.message.contains("(abcdef1)"));
    }

    #[test]
    fn stable_output_shape() {
        let checks = [result(CheckStatus::Ok, "os", "linux")];
        let output = format_report(&checks, summarize(&checks), "abcdef123");

        assert!(output.starts_with("Doctor report:\nMode: "));
        assert!(output.contains("STATUS  CHECK                 MESSAGE"));
        assert!(output.contains("OK      os                   linux"));
        assert!(output.contains("Summary: ok=1 warn=0 fail=0"));
        assert!(output.contains("Build: zejtron v"));
    }
}
