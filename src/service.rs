// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use std::error::Error;
use std::fmt;
use std::io;
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceUnit {
    pub name: String,
    pub load: String,
    pub active: String,
    pub sub: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceFlags {
    pub unit: Option<String>,
    pub system: bool,
    pub user: bool,
    pub failed: bool,
    pub all: bool,
    pub filter: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceScope {
    System,
    User,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ServiceOptions {
    scope: ServiceScope,
    failed: bool,
    all: bool,
    filter: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceError(String);

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for ServiceError {}

pub fn run(flags: ServiceFlags) -> Result<(), Box<dyn Error>> {
    // Parse options once. The unit field is consumed by parse_options via Clone.
    let unit_name = flags.unit.clone();
    let options = parse_options(flags)?;

    // If a unit name is given, show detail mode (systemctl show <unit>).
    if let Some(unit) = unit_name.as_deref() {
        let detail = query_unit_detail(&options, unit)?;
        let output = format_unit_detail(&detail);
        println!("{output}");
        return Ok(());
    }

    let output = if options.failed {
        let failed = filter_services(
            query_services(&options, QueryMode::Failed)?,
            &options.filter,
        );
        format_failed_report(&failed, options.filter.as_deref())
    } else if options.all {
        let services = filter_services(query_services(&options, QueryMode::All)?, &options.filter);
        format_all_report(&services, options.filter.as_deref())
    } else {
        let running = filter_running_services(query_services(&options, QueryMode::Default)?);
        let running = filter_services(running, &options.filter);
        let failed = filter_services(
            query_services(&options, QueryMode::Failed)?,
            &options.filter,
        );
        format_default_report(&running, &failed, options.filter.as_deref())
    };
    println!("{output}");
    Ok(())
}

/// Detailed unit info gathered from `systemctl show <unit>`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnitDetail {
    pub name: String,
    pub description: String,
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub main_pid: Option<u32>,
    pub exec_start: String,
    pub fragment_path: String,
    pub active_enter_timestamp: String,
    pub n_restarts: Option<u64>,
    pub memory_current: Option<u64>,
    pub cpu_usage_nsec: Option<u64>,
    pub tasks_current: Option<u64>,
    pub wants: Vec<String>,
    pub requires: Vec<String>,
    pub wanted_by: Vec<String>,
}

fn query_unit_detail(options: &ServiceOptions, unit: &str) -> Result<UnitDetail, ServiceError> {
    let mut cmd = Command::new("systemctl");
    if options.scope == ServiceScope::User {
        cmd.arg("--user");
    }
    cmd.args(["show", unit]);
    let output = cmd.output().map_err(|e| ServiceError(e.to_string()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ServiceError(stderr.trim().to_owned()));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_unit_show(&stdout, unit))
}

fn parse_unit_show(show_output: &str, unit: &str) -> UnitDetail {
    let mut detail = UnitDetail {
        name: unit.to_owned(),
        ..Default::default()
    };
    for line in show_output.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "Description" => detail.description = value.to_owned(),
            "LoadState" => detail.load_state = value.to_owned(),
            "ActiveState" => detail.active_state = value.to_owned(),
            "SubState" => detail.sub_state = value.to_owned(),
            "MainPID" => detail.main_pid = value.parse().ok(),
            "ExecStart" => detail.exec_start = value.to_owned(),
            "FragmentPath" => detail.fragment_path = value.to_owned(),
            "ActiveEnterTimestamp" => detail.active_enter_timestamp = value.to_owned(),
            "NRestarts" => detail.n_restarts = value.parse().ok(),
            "MemoryCurrent" => {
                if value != "[not set]" && value != "0" {
                    detail.memory_current = value.parse().ok();
                }
            }
            "CPUUsageNSec" => {
                if value != "[not set]" {
                    detail.cpu_usage_nsec = value.parse().ok();
                }
            }
            "TasksCurrent" => {
                if value != "[not set]" && value != "18446744073709551615" {
                    detail.tasks_current = value.parse().ok();
                }
            }
            "Wants" => {
                detail.wants = value.split_whitespace().map(str::to_owned).collect();
            }
            "Requires" => {
                detail.requires = value.split_whitespace().map(str::to_owned).collect();
            }
            "WantedBy" => {
                detail.wanted_by = value.split_whitespace().map(str::to_owned).collect();
            }
            _ => {}
        }
    }
    detail
}

fn format_unit_detail(detail: &UnitDetail) -> String {
    let mut lines = vec![detail.name.clone()];
    if !detail.description.is_empty() {
        lines.push(format!("├── description: {}", detail.description));
    }
    lines.push(format!(
        "├── state: load={} active={} sub={}",
        detail.load_state, detail.active_state, detail.sub_state
    ));
    if let Some(pid) = detail.main_pid {
        if pid > 0 {
            lines.push(format!("├── main-pid: {pid}"));
        }
    }
    if !detail.exec_start.is_empty() {
        lines.push(format!("├── exec-start: {}", detail.exec_start));
    }
    if !detail.fragment_path.is_empty() {
        lines.push(format!("├── fragment: {}", detail.fragment_path));
    }
    if !detail.active_enter_timestamp.is_empty() {
        lines.push(format!(
            "├── active-since: {}",
            detail.active_enter_timestamp
        ));
    }
    if let Some(restarts) = detail.n_restarts {
        if restarts > 0 {
            lines.push(format!("├── restarts: {restarts}"));
        }
    }
    if let Some(mem) = detail.memory_current {
        lines.push(format!("├── memory: {}", human_bytes(mem)));
    }
    if let Some(cpu_ns) = detail.cpu_usage_nsec {
        let cpu_secs = cpu_ns as f64 / 1_000_000_000.0;
        lines.push(format!("├── cpu-time: {cpu_secs:.2}s"));
    }
    if let Some(tasks) = detail.tasks_current {
        lines.push(format!("├── tasks: {tasks}"));
    }
    if !detail.wants.is_empty() {
        lines.push(format!("├── wants: {}", detail.wants.join(", ")));
    }
    if !detail.requires.is_empty() {
        lines.push(format!("├── requires: {}", detail.requires.join(", ")));
    }
    if !detail.wanted_by.is_empty() {
        lines.push(format!("└── wanted-by: {}", detail.wanted_by.join(", ")));
    } else if lines.last().map(|l| l.starts_with("├──")).unwrap_or(false) {
        // Fix the last ├── to └──
        if let Some(last) = lines.last_mut() {
            *last = last.replacen("├──", "└──", 1);
        }
    }
    lines.join("\n")
}

fn human_bytes(b: u64) -> String {
    if b >= 1024 * 1024 * 1024 {
        format!("{:.2}GB", b as f64 / 1024.0 / 1024.0 / 1024.0)
    } else if b >= 1024 * 1024 {
        format!("{:.1}MB", b as f64 / 1024.0 / 1024.0)
    } else if b >= 1024 {
        format!("{:.1}KB", b as f64 / 1024.0)
    } else {
        format!("{b}B")
    }
}

fn parse_options(flags: ServiceFlags) -> Result<ServiceOptions, ServiceError> {
    if flags.system && flags.user {
        return Err(ServiceError(
            "--system cannot be used with --user".to_owned(),
        ));
    }

    Ok(ServiceOptions {
        scope: if flags.user {
            ServiceScope::User
        } else {
            ServiceScope::System
        },
        failed: flags.failed,
        all: flags.all,
        filter: flags.filter,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueryMode {
    Default,
    Failed,
    All,
}

fn query_services(
    options: &ServiceOptions,
    mode: QueryMode,
) -> Result<Vec<ServiceUnit>, Box<dyn Error>> {
    let mut command = Command::new("systemctl");
    if options.scope == ServiceScope::User {
        command.arg("--user");
    }

    match mode {
        QueryMode::Default => {
            command.args([
                "list-units",
                "--type=service",
                "--no-legend",
                "--no-pager",
                "--plain",
            ]);
        }
        QueryMode::Failed => {
            command.args([
                "--failed",
                "--type=service",
                "--no-legend",
                "--no-pager",
                "--plain",
            ]);
        }
        QueryMode::All => {
            command.args([
                "list-units",
                "--type=service",
                "--all",
                "--no-legend",
                "--no-pager",
                "--plain",
            ]);
        }
    }

    let output = match command.output() {
        Ok(output) => output,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(Box::new(ServiceError(
                "systemctl not found. Zejtron service requires systemd/systemctl.".to_owned(),
            )));
        }
        Err(error) => return Err(Box::new(error)),
    };

    if !output.status.success() {
        return Err(Box::new(ServiceError(format_systemctl_error(
            &String::from_utf8_lossy(&output.stderr),
            &String::from_utf8_lossy(&output.stdout),
        ))));
    }

    Ok(parse_systemctl_units(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

fn format_systemctl_error(stderr: &str, stdout: &str) -> String {
    let message = stderr
        .lines()
        .chain(stdout.lines())
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("systemctl command failed");
    format!("systemctl failed: {message}")
}

pub fn parse_systemctl_units(output: &str) -> Vec<ServiceUnit> {
    output.lines().filter_map(parse_systemctl_line).collect()
}

pub fn parse_systemctl_line(line: &str) -> Option<ServiceUnit> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    let mut columns = line.split_whitespace();
    let name = columns.next()?.trim_start_matches('●');
    let load = columns.next()?;
    let active = columns.next()?;
    let sub = columns.next()?;
    let description = columns.collect::<Vec<_>>().join(" ");

    if !name.ends_with(".service") {
        return None;
    }

    Some(ServiceUnit {
        name: name.to_owned(),
        load: load.to_owned(),
        active: active.to_owned(),
        sub: sub.to_owned(),
        description: description.to_owned(),
    })
}

pub fn filter_services(services: Vec<ServiceUnit>, filter: &Option<String>) -> Vec<ServiceUnit> {
    let Some(filter) = filter.as_deref().filter(|value| !value.is_empty()) else {
        return services;
    };
    let filter = filter.to_lowercase();
    services
        .into_iter()
        .filter(|unit| unit.name.to_lowercase().contains(&filter))
        .collect()
}

pub fn filter_running_services(services: Vec<ServiceUnit>) -> Vec<ServiceUnit> {
    services
        .into_iter()
        .filter(|unit| unit.active == "active" && unit.sub == "running")
        .collect()
}

pub fn format_default_report(
    running: &[ServiceUnit],
    failed: &[ServiceUnit],
    filter: Option<&str>,
) -> String {
    if running.is_empty()
        && failed.is_empty()
        && let Some(filter) = filter
    {
        return format!("No services matched '{filter}'.");
    }

    let mut lines = vec!["services".to_owned()];
    lines.push("├── running".to_owned());
    append_unit_tree(&mut lines, running, "│   ", UnitRender::Sub);
    lines.push("└── failed".to_owned());
    append_unit_tree(&mut lines, failed, "    ", UnitRender::Sub);
    lines.push(String::new());
    lines.push(format!(
        "{} {} · {} {}",
        running.len(),
        plural(running.len(), "running", "running"),
        failed.len(),
        plural(failed.len(), "failed", "failed")
    ));
    lines.join("\n")
}

pub fn format_failed_report(failed: &[ServiceUnit], filter: Option<&str>) -> String {
    if failed.is_empty() {
        return if let Some(filter) = filter {
            format!("No services matched '{filter}'.")
        } else {
            "No failed services.".to_owned()
        };
    }

    let mut lines = vec!["failed services".to_owned()];
    append_unit_tree(&mut lines, failed, "", UnitRender::Sub);
    lines.push(String::new());
    lines.push(format!(
        "{} {}",
        failed.len(),
        plural(failed.len(), "failed", "failed")
    ));
    lines.join("\n")
}

pub fn format_all_report(services: &[ServiceUnit], filter: Option<&str>) -> String {
    if services.is_empty() {
        return if let Some(filter) = filter {
            format!("No services matched '{filter}'.")
        } else {
            "No services found.".to_owned()
        };
    }

    let mut lines = vec!["services".to_owned()];
    append_unit_tree(&mut lines, services, "", UnitRender::ActiveSub);
    lines.push(String::new());
    lines.push(format!(
        "{} {}",
        services.len(),
        plural(services.len(), "service", "services")
    ));
    lines.join("\n")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnitRender {
    Sub,
    ActiveSub,
}

fn append_unit_tree(
    lines: &mut Vec<String>,
    units: &[ServiceUnit],
    indent: &str,
    render: UnitRender,
) {
    if units.is_empty() {
        lines.push(format!("{indent}└── none"));
        return;
    }

    for (index, unit) in units.iter().enumerate() {
        let branch = if index + 1 == units.len() {
            "└──"
        } else {
            "├──"
        };
        lines.push(format!("{indent}{branch} {}", format_unit(unit, render)));
    }
}

fn format_unit(unit: &ServiceUnit, render: UnitRender) -> String {
    match render {
        UnitRender::Sub => format!("{} {}", unit.name, unit.sub),
        UnitRender::ActiveSub => format!("{} {}/{}", unit.name, unit.active, unit.sub),
    }
}

fn plural<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(name: &str, active: &str, sub: &str) -> ServiceUnit {
        ServiceUnit {
            name: name.to_owned(),
            load: "loaded".to_owned(),
            active: active.to_owned(),
            sub: sub.to_owned(),
            description: String::new(),
        }
    }

    #[test]
    fn parses_normal_systemctl_line() {
        let line = "NetworkManager.service loaded active running Network Manager";
        let unit = parse_systemctl_line(line).unwrap();

        assert_eq!(unit.name, "NetworkManager.service");
        assert_eq!(unit.load, "loaded");
        assert_eq!(unit.active, "active");
        assert_eq!(unit.sub, "running");
        assert_eq!(unit.description, "Network Manager");
    }

    #[test]
    fn parses_description_with_spaces() {
        let line = "unbound.service loaded active running Validating recursive DNS resolver";
        let unit = parse_systemctl_line(line).unwrap();

        assert_eq!(unit.description, "Validating recursive DNS resolver");
    }

    #[test]
    fn skips_malformed_empty_and_non_service_lines() {
        let output = "\nmalformed\nbasic.target loaded active active Basic System\nsshd.service loaded active running OpenSSH server\n";
        let units = parse_systemctl_units(output);

        assert_eq!(units.len(), 1);
        assert_eq!(units[0].name, "sshd.service");
        assert_eq!(units[0].description, "OpenSSH server");
    }

    #[test]
    fn filter_is_case_insensitive_by_unit_name() {
        let services = vec![
            unit("NetworkManager.service", "active", "running"),
            unit("unbound.service", "active", "running"),
        ];

        let filtered = filter_services(services, &Some("network".to_owned()));

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "NetworkManager.service");
    }

    #[test]
    fn default_renderer_shows_running_and_failed() {
        let running = vec![
            unit("NetworkManager.service", "active", "running"),
            unit("unbound.service", "active", "running"),
        ];
        let failed = vec![unit("bad.service", "failed", "failed")];

        let report = format_default_report(&running, &failed, None);

        assert!(report.contains("├── running"));
        assert!(report.contains("NetworkManager.service running"));
        assert!(report.contains("└── failed"));
        assert!(report.contains("bad.service failed"));
        assert!(report.contains("2 running · 1 failed"));
    }

    #[test]
    fn default_filter_excludes_active_exited_services() {
        let services = vec![
            unit("NetworkManager.service", "active", "running"),
            unit("systemd-random-seed.service", "active", "exited"),
            unit("dead.service", "inactive", "dead"),
        ];

        let running = filter_running_services(services);

        assert_eq!(
            running,
            vec![unit("NetworkManager.service", "active", "running")]
        );
    }

    #[test]
    fn filter_applies_after_default_mode_selection() {
        let services = vec![
            unit("systemd-journald.service", "active", "running"),
            unit("systemd-random-seed.service", "active", "exited"),
        ];
        let running = filter_running_services(services);
        let filtered = filter_services(running, &Some("systemd".to_owned()));
        let report = format_default_report(&filtered, &[], Some("systemd"));

        assert!(report.contains("systemd-journald.service running"));
        assert!(!report.contains("systemd-random-seed.service"));
        assert!(report.contains("1 running · 0 failed"));
    }

    #[test]
    fn failed_only_renderer_handles_none() {
        assert_eq!(format_failed_report(&[], None), "No failed services.");
    }

    #[test]
    fn all_renderer_uses_active_sub_format_and_summary() {
        let services = vec![
            unit("one.service", "active", "running"),
            unit("two.service", "inactive", "dead"),
            unit("oneshot.service", "active", "exited"),
        ];

        let report = format_all_report(&services, None);

        assert!(report.contains("one.service active/running"));
        assert!(report.contains("two.service inactive/dead"));
        assert!(report.contains("oneshot.service active/exited"));
        assert!(report.contains("3 services"));
    }

    #[test]
    fn all_filter_can_show_exited_units() {
        let services = vec![
            unit("systemd-journald.service", "active", "running"),
            unit("systemd-random-seed.service", "active", "exited"),
        ];
        let filtered = filter_services(services, &Some("random".to_owned()));

        let report = format_all_report(&filtered, Some("random"));

        assert!(report.contains("systemd-random-seed.service active/exited"));
        assert!(report.contains("1 service"));
    }

    #[test]
    fn system_and_user_conflict() {
        let error = parse_options(ServiceFlags {
            system: true,
            user: true,
            failed: false,
            all: false,
            filter: None,
            unit: None,
        })
        .unwrap_err();

        assert_eq!(error.to_string(), "--system cannot be used with --user");
    }

    #[test]
    fn systemctl_missing_error_format_is_stable() {
        let error = ServiceError(
            "systemctl not found. Zejtron service requires systemd/systemctl.".to_owned(),
        );

        assert_eq!(
            error.to_string(),
            "systemctl not found. Zejtron service requires systemd/systemctl."
        );
    }

    #[test]
    fn systemctl_unusable_error_format_is_stable() {
        assert_eq!(
            format_systemctl_error(
                "System has not been booted with systemd as init system (PID 1).",
                ""
            ),
            "systemctl failed: System has not been booted with systemd as init system (PID 1)."
        );
        assert_eq!(
            format_systemctl_error("", "Failed to connect to bus: No medium found"),
            "systemctl failed: Failed to connect to bus: No medium found"
        );
    }

    #[test]
    fn filter_no_match_message_is_clean() {
        assert_eq!(
            format_default_report(&[], &[], Some("unbound")),
            "No services matched 'unbound'."
        );
    }

    #[test]
    fn parse_unit_show_extracts_fields() {
        let show_output = "Id=nginx.service\n\
Description=The NGINX HTTP and reverse proxy server\n\
LoadState=loaded\n\
ActiveState=active\n\
SubState=running\n\
MainPID=1234\n\
ExecStart={ path=/usr/sbin/nginx ; argv[]=nginx -g 'daemon off;' }\n\
FragmentPath=/usr/lib/systemd/system/nginx.service\n\
ActiveEnterTimestamp=Mon 2026-01-15 14:23:01 UTC\n\
NRestarts=3\n\
MemoryCurrent=8388608\n\
CPUUsageNSec=5000000000\n\
TasksCurrent=5\n\
Wants=network.target\n\
Requires=\n\
WantedBy=multi-user.target\n";
        let detail = parse_unit_show(show_output, "nginx.service");
        assert_eq!(detail.name, "nginx.service");
        assert_eq!(
            detail.description,
            "The NGINX HTTP and reverse proxy server"
        );
        assert_eq!(detail.load_state, "loaded");
        assert_eq!(detail.active_state, "active");
        assert_eq!(detail.sub_state, "running");
        assert_eq!(detail.main_pid, Some(1234));
        assert!(detail.exec_start.contains("nginx"));
        assert_eq!(
            detail.fragment_path,
            "/usr/lib/systemd/system/nginx.service"
        );
        assert_eq!(detail.n_restarts, Some(3));
        assert_eq!(detail.memory_current, Some(8388608));
        assert_eq!(detail.cpu_usage_nsec, Some(5_000_000_000));
        assert_eq!(detail.tasks_current, Some(5));
        assert_eq!(detail.wants, vec!["network.target"]);
        assert_eq!(detail.wanted_by, vec!["multi-user.target"]);
    }

    #[test]
    fn format_unit_detail_renders_all_fields() {
        let detail = UnitDetail {
            name: "nginx.service".to_owned(),
            description: "NGINX server".to_owned(),
            load_state: "loaded".to_owned(),
            active_state: "active".to_owned(),
            sub_state: "running".to_owned(),
            main_pid: Some(1234),
            exec_start: "nginx -g 'daemon off;'".to_owned(),
            fragment_path: "/usr/lib/systemd/system/nginx.service".to_owned(),
            active_enter_timestamp: "Mon 2026-01-15 14:23:01 UTC".to_owned(),
            n_restarts: Some(3),
            memory_current: Some(8388608),
            cpu_usage_nsec: Some(5_000_000_000),
            tasks_current: Some(5),
            wants: vec!["network.target".to_owned()],
            requires: vec![],
            wanted_by: vec!["multi-user.target".to_owned()],
        };
        let out = format_unit_detail(&detail);
        assert!(out.contains("nginx.service"));
        assert!(out.contains("description: NGINX server"));
        assert!(out.contains("state: load=loaded active=active sub=running"));
        assert!(out.contains("main-pid: 1234"));
        assert!(out.contains("exec-start: nginx"));
        assert!(out.contains("fragment: /usr/lib/systemd/system/nginx.service"));
        assert!(out.contains("restarts: 3"));
        assert!(out.contains("memory: 8.0MB"));
        assert!(out.contains("cpu-time: 5.00s"));
        assert!(out.contains("tasks: 5"));
        assert!(out.contains("wants: network.target"));
        assert!(out.contains("wanted-by: multi-user.target"));
    }
}
