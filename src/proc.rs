// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

pub const DEFAULT_INTERVAL_SECONDS: u64 = 6;
pub const MIN_INTERVAL_SECONDS: u64 = 3;
pub const MAX_INTERVAL_SECONDS: u64 = 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Process {
    pub name: String,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub cmdline: Option<String>,
    pub state: String,
    pub vm_rss_kb: u64,
    pub vm_size_kb: u64,
    pub threads: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanReport {
    pub processes: Vec<Process>,
    pub unreadable_statuses: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessForest {
    pub processes: BTreeMap<u32, Process>,
    pub roots: Vec<u32>,
    pub children: BTreeMap<u32, Vec<u32>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetUser {
    pub name: String,
    pub uid: u32,
}

impl TargetUser {
    pub fn label(&self) -> String {
        let uid_label = format!("uid={}", self.uid);
        if self.name == uid_label {
            uid_label
        } else {
            format!("{} {}", self.name, uid_label)
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ProcFlags {
    pub me: bool,
    pub live: bool,
    pub watch: bool,
    pub interval: Option<u64>,
    pub depth: Option<usize>,
    pub find: Option<String>,
    pub no_pid: bool,
    pub no_color: bool,
    pub verbose: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ViewOptions {
    max_depth: Option<usize>,
    find: Option<String>,
    verbose: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcError(String);

impl fmt::Display for ProcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for ProcError {}

pub fn run(user_or_uid: Option<&str>, flags: ProcFlags) -> Result<(), Box<dyn Error>> {
    run_inner(user_or_uid, flags).map_err(|error| ProcError(error).into())
}

fn run_inner(user_or_uid: Option<&str>, flags: ProcFlags) -> Result<(), String> {
    let live = is_live_mode(flags.live, flags.watch);
    let interval_seconds = validate_interval(live, flags.interval)?;
    let find = validate_find(flags.find)?;
    let target = resolve_target(flags.me, user_or_uid)?;
    let view = ViewOptions {
        max_depth: flags.depth,
        find,
        verbose: flags.verbose,
    };

    if live {
        run_live(target, interval_seconds, !flags.no_pid, view)
    } else {
        print!("{}", render_snapshot(&target, !flags.no_pid, &view, None)?);
        Ok(())
    }
}

pub fn validate_interval(live: bool, interval: Option<u64>) -> Result<u64, String> {
    match (live, interval) {
        (false, Some(_)) => Err("--interval requires --live".to_owned()),
        (false, None) => Ok(DEFAULT_INTERVAL_SECONDS),
        (true, Some(seconds))
            if !(MIN_INTERVAL_SECONDS..=MAX_INTERVAL_SECONDS).contains(&seconds) =>
        {
            Err(format!(
                "--interval must be between {MIN_INTERVAL_SECONDS} and {MAX_INTERVAL_SECONDS} seconds"
            ))
        }
        (true, Some(seconds)) => Ok(seconds),
        (true, None) => Ok(DEFAULT_INTERVAL_SECONDS),
    }
}

pub fn is_live_mode(live: bool, watch: bool) -> bool {
    live || watch
}

fn validate_find(find: Option<String>) -> Result<Option<String>, String> {
    match find {
        Some(pattern) if pattern.trim().is_empty() => {
            Err("--find requires a non-empty pattern".to_owned())
        }
        Some(pattern) => Ok(Some(pattern)),
        None => Ok(None),
    }
}

pub fn resolve_target(me: bool, user_or_uid: Option<&str>) -> Result<TargetUser, String> {
    match (me, user_or_uid) {
        (true, None) => current_user(),
        (false, Some(value)) => resolve_user_or_uid(value),
        (true, Some(_)) => Err("use either --me or USER_OR_UID, not both".to_owned()),
        (false, None) => Err("expected USER_OR_UID or --me".to_owned()),
    }
}

pub fn resolve_user_or_uid(input: &str) -> Result<TargetUser, String> {
    if input.is_empty() {
        return Err("empty user or UID".to_owned());
    }

    if input.chars().all(|character| character.is_ascii_digit()) {
        let uid = input
            .parse::<u32>()
            .map_err(|_| format!("invalid UID: {input}"))?;
        let name = username_for_uid(uid).unwrap_or_else(|| format!("uid={uid}"));
        return Ok(TargetUser { name, uid });
    }

    passwd_entries()
        .ok()
        .and_then(|entries| {
            entries
                .into_iter()
                .find(|entry| entry.name == input)
                .map(|entry| TargetUser {
                    name: entry.name,
                    uid: entry.uid,
                })
        })
        .ok_or_else(|| format!("unknown user: {input}"))
}

pub fn current_user() -> Result<TargetUser, String> {
    let uid = current_uid().ok_or_else(|| "failed to resolve current UID".to_owned())?;
    let name = username_for_uid(uid).unwrap_or_else(|| format!("uid={uid}"));
    Ok(TargetUser { name, uid })
}

fn current_uid() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    parse_status_value(&status, "Uid")?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn username_for_uid(uid: u32) -> Option<String> {
    passwd_entries()
        .ok()?
        .into_iter()
        .find(|entry| entry.uid == uid)
        .map(|entry| entry.name)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PasswdEntry {
    name: String,
    uid: u32,
}

fn passwd_entries() -> io::Result<Vec<PasswdEntry>> {
    parse_passwd_entries(&fs::read_to_string("/etc/passwd")?)
}

fn parse_passwd_entries(contents: &str) -> io::Result<Vec<PasswdEntry>> {
    let mut entries = Vec::new();
    for line in contents.lines() {
        let mut fields = line.split(':');
        let Some(name) = fields.next().filter(|name| !name.is_empty()) else {
            continue;
        };
        fields.next();
        let Some(uid) = fields.next().and_then(|uid| uid.parse::<u32>().ok()) else {
            continue;
        };
        entries.push(PasswdEntry {
            name: name.to_owned(),
            uid,
        });
    }
    Ok(entries)
}

fn run_live(
    target: TargetUser,
    interval_seconds: u64,
    show_pid: bool,
    view: ViewOptions,
) -> Result<(), String> {
    let running = Arc::new(AtomicBool::new(true));
    let handler_running = Arc::clone(&running);
    ctrlc::set_handler(move || {
        handler_running.store(false, Ordering::SeqCst);
    })
    .map_err(|error| format!("failed to install Ctrl+C handler: {error}"))?;

    let interval = Duration::from_secs(interval_seconds);
    while running.load(Ordering::SeqCst) {
        print!("\x1b[2J\x1b[H");
        print!(
            "{}",
            render_snapshot(&target, show_pid, &view, Some(interval_seconds))?
        );
        io::stdout()
            .flush()
            .map_err(|error| format!("failed to flush stdout: {error}"))?;

        let started = Instant::now();
        while running.load(Ordering::SeqCst) && started.elapsed() < interval {
            let remaining = interval.saturating_sub(started.elapsed());
            thread::sleep(remaining.min(Duration::from_millis(200)));
        }
    }

    println!();
    Ok(())
}

fn render_snapshot(
    target: &TargetUser,
    show_pid: bool,
    view: &ViewOptions,
    live_interval_seconds: Option<u64>,
) -> Result<String, String> {
    let report = scan_processes_for_uid(target.uid)?;
    Ok(render_report(
        target,
        report,
        show_pid,
        view,
        live_interval_seconds,
    ))
}

fn render_report(
    target: &TargetUser,
    report: ScanReport,
    show_pid: bool,
    view: &ViewOptions,
    live_interval_seconds: Option<u64>,
) -> String {
    let mut forest = build_forest(report.processes);

    if let Some(pattern) = &view.find {
        let matches = matching_process_ids(&forest, pattern);
        if matches.is_empty() {
            let mut output = format!("No processes matched '{pattern}'.\n");
            if let Some(interval_seconds) = live_interval_seconds {
                output.push('\n');
                output.push_str(&render_live_footer(interval_seconds));
                output.push('\n');
            }
            return output;
        }
        forest = prune_for_matches(&forest, &matches);
    }

    forest = limit_depth(&forest, view.max_depth);

    let mut output = render_forest(target, &forest, show_pid, view.verbose);
    output.push('\n');

    if report.unreadable_statuses > 0 {
        output.push_str(render_unreadable_note());
        output.push('\n');
    }

    output.push_str(&render_summary(&forest));
    output.push('\n');

    if let Some(interval_seconds) = live_interval_seconds {
        output.push_str(&render_live_footer(interval_seconds));
        output.push('\n');
    }

    output
}

pub fn scan_processes_for_uid(target_uid: u32) -> Result<ScanReport, String> {
    scan_processes_for_uid_at(Path::new("/proc"), target_uid)
}

fn scan_processes_for_uid_at(proc_root: &Path, target_uid: u32) -> Result<ScanReport, String> {
    let mut processes = Vec::new();
    let mut unreadable_statuses = 0;
    let entries = fs::read_dir(proc_root)
        .map_err(|error| format!("failed to read {}: {error}", proc_root.display()))?;

    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };

        let status_path = entry.path().join("status");
        let contents = match fs::read_to_string(status_path) {
            Ok(contents) => contents,
            Err(error) => {
                if error.kind() != io::ErrorKind::NotFound {
                    unreadable_statuses += 1;
                }
                continue;
            }
        };

        let Ok(mut process) = parse_status(&contents) else {
            continue;
        };

        if process.pid == pid && process.uid == target_uid {
            // Enrich with cmdline (from /proc/<pid>/cmdline) and state char
            // (from /proc/<pid>/stat field 3).
            process.cmdline = crate::process::read_cmdline(proc_root, pid);
            process.state = read_state_char(&entry.path()).unwrap_or_else(|| "?".to_owned());
            processes.push(process);
        }
    }

    processes.sort_by_key(|process| process.pid);
    Ok(ScanReport {
        processes,
        unreadable_statuses,
    })
}

pub fn parse_status(contents: &str) -> Result<Process, String> {
    let name = parse_status_value(contents, "Name");
    let pid = parse_status_number(contents, "Pid")?.ok_or_else(|| "missing Pid".to_owned())?;
    let ppid = parse_status_number(contents, "PPid")?.ok_or_else(|| "missing PPid".to_owned())?;
    let uid = parse_status_value(contents, "Uid")
        .and_then(|value| value.split_whitespace().next().map(str::to_owned))
        .ok_or_else(|| "missing Uid".to_owned())?
        .parse::<u32>()
        .map_err(|_| "invalid real UID".to_owned())?;

    // State — read from /proc/<pid>/stat (status has no state char). The
    // caller passes the status contents only, so we read stat separately in
    // scan_processes_for_uid_at. Here we default to "?" and let the scanner
    // fill it in.
    let vm_rss_kb = parse_status_u64(contents, "VmRSS").unwrap_or(0);
    let vm_size_kb = parse_status_u64(contents, "VmSize").unwrap_or(0);
    let threads = parse_status_u64(contents, "Threads").unwrap_or(1);

    Ok(Process {
        name: name.ok_or_else(|| "missing Name".to_owned())?,
        pid,
        ppid,
        uid,
        cmdline: None,         // filled in by scanner after parse_status
        state: "?".to_owned(), // filled in by scanner from /proc/<pid>/stat
        vm_rss_kb,
        vm_size_kb,
        threads,
    })
}

fn parse_status_value(status: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}:");
    status
        .lines()
        .find_map(|line| line.strip_prefix(&prefix).map(str::trim))
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn parse_status_number(contents: &str, key: &str) -> Result<Option<u32>, String> {
    let Some(value) = parse_status_value(contents, key) else {
        return Ok(None);
    };
    value
        .parse::<u32>()
        .map(Some)
        .map_err(|_| format!("invalid {key}"))
}

/// Like parse_status_number but returns u64 (for memory/threads fields).
fn parse_status_u64(contents: &str, key: &str) -> Option<u64> {
    let value = parse_status_value(contents, key)?;
    // VmRSS: 1234 kB — take first whitespace-separated token
    value
        .split_whitespace()
        .next()
        .and_then(|n| n.parse::<u64>().ok())
}

/// Read the state character from /proc/<pid>/stat field 3.
/// The comm field (field 2) can contain spaces and parens, so we find the
/// LAST ')' and take the char right after it.
fn read_state_char(proc_dir: &std::path::Path) -> Option<String> {
    let stat = fs::read_to_string(proc_dir.join("stat")).ok()?;
    let close_paren = stat.rfind(')')?;
    let after = &stat[close_paren + 1..];
    let state_char = after.trim_start().chars().next()?;
    let label = match state_char {
        'R' => "R",
        'S' => "S",
        'D' => "D",
        'Z' => "Z",
        'T' => "T",
        't' => "t",
        _ => "?",
    };
    Some(label.to_owned())
}

pub fn build_forest(processes: Vec<Process>) -> ProcessForest {
    let processes: BTreeMap<u32, Process> = processes
        .into_iter()
        .map(|process| (process.pid, process))
        .collect();
    let process_ids: BTreeSet<u32> = processes.keys().copied().collect();
    let mut roots = Vec::new();
    let mut children: BTreeMap<u32, Vec<u32>> = BTreeMap::new();

    for process in processes.values() {
        if process.ppid != process.pid && process_ids.contains(&process.ppid) {
            children.entry(process.ppid).or_default().push(process.pid);
        } else {
            roots.push(process.pid);
        }
    }

    for child_ids in children.values_mut() {
        child_ids.sort_unstable();
    }
    roots.sort_unstable();

    ProcessForest {
        processes,
        roots,
        children,
    }
}

pub fn matching_process_ids(forest: &ProcessForest, pattern: &str) -> BTreeSet<u32> {
    let pattern = pattern.to_lowercase();
    forest
        .processes
        .values()
        .filter(|process| process.name.to_lowercase().contains(&pattern))
        .map(|process| process.pid)
        .collect()
}

pub fn prune_for_matches(forest: &ProcessForest, matches: &BTreeSet<u32>) -> ProcessForest {
    let mut included = BTreeSet::new();

    for pid in matches {
        include_ancestors(forest, *pid, &mut included);
        include_descendants(forest, *pid, &mut included);
    }

    forest_from_ids(forest, &included)
}

pub fn limit_depth(forest: &ProcessForest, max_depth: Option<usize>) -> ProcessForest {
    let Some(max_depth) = max_depth else {
        return forest.clone();
    };

    if max_depth == 0 {
        return build_forest(Vec::new());
    }

    let mut included = BTreeSet::new();
    for root in &forest.roots {
        include_to_depth(forest, *root, 1, max_depth, &mut included);
    }

    forest_from_ids(forest, &included)
}

fn include_ancestors(forest: &ProcessForest, pid: u32, included: &mut BTreeSet<u32>) {
    let mut current_pid = pid;
    while let Some(process) = forest.processes.get(&current_pid) {
        included.insert(process.pid);
        if process.ppid == process.pid || !forest.processes.contains_key(&process.ppid) {
            break;
        }
        current_pid = process.ppid;
    }
}

fn include_descendants(forest: &ProcessForest, pid: u32, included: &mut BTreeSet<u32>) {
    included.insert(pid);

    if let Some(children) = forest.children.get(&pid) {
        for child in children {
            include_descendants(forest, *child, included);
        }
    }
}

fn include_to_depth(
    forest: &ProcessForest,
    pid: u32,
    depth: usize,
    max_depth: usize,
    included: &mut BTreeSet<u32>,
) {
    if depth > max_depth || !included.insert(pid) {
        return;
    }

    if let Some(children) = forest.children.get(&pid) {
        for child in children {
            include_to_depth(forest, *child, depth + 1, max_depth, included);
        }
    }
}

fn forest_from_ids(forest: &ProcessForest, included: &BTreeSet<u32>) -> ProcessForest {
    build_forest(
        included
            .iter()
            .filter_map(|pid| forest.processes.get(pid).cloned())
            .collect(),
    )
}

pub fn render_forest(
    target: &TargetUser,
    forest: &ProcessForest,
    show_pid: bool,
    verbose: bool,
) -> String {
    let mut output = format!("{}\n", target.label());

    for (index, pid) in forest.roots.iter().enumerate() {
        render_process(
            &mut output,
            forest,
            *pid,
            "",
            index + 1 == forest.roots.len(),
            show_pid,
            verbose,
        );
    }

    output
}

pub fn render_summary(forest: &ProcessForest) -> String {
    format!(
        "{} roots · {} processes",
        forest.roots.len(),
        forest.processes.len()
    )
}

fn render_unreadable_note() -> &'static str {
    "note: some processes were not readable; try sudo for a complete tree"
}

fn render_live_footer(interval_seconds: u64) -> String {
    format!("live mode · refresh {interval_seconds}s · press Ctrl+C to quit")
}

fn render_process(
    output: &mut String,
    forest: &ProcessForest,
    pid: u32,
    prefix: &str,
    is_last: bool,
    show_pid: bool,
    verbose: bool,
) {
    let Some(process) = forest.processes.get(&pid) else {
        return;
    };

    let branch = if is_last { "└── " } else { "├── " };
    output.push_str(&format!("{prefix}{branch}{}", process.name));

    if show_pid {
        output.push_str(&format!(" pid={}", process.pid));
    }
    // Always show state — it's a single char and very high signal (Z = zombie!)
    output.push_str(&format!(" state={}", process.state));

    if verbose {
        // Show memory (RSS) and thread count
        if process.vm_rss_kb > 0 {
            output.push_str(&format!(" rss={}", human_kb(process.vm_rss_kb)));
        }
        if process.threads > 1 {
            output.push_str(&format!(" threads={}", process.threads));
        }
        // Show cmdline if it differs from name (kernel threads have no cmdline)
        if let Some(ref cmd) = process.cmdline {
            if !cmd.is_empty() && cmd.as_str() != process.name {
                output.push_str(&format!(" cmd={}", quote_if_needed(cmd)));
            }
        }
    }

    output.push('\n');

    let next_prefix = if is_last {
        format!("{prefix}    ")
    } else {
        format!("{prefix}│   ")
    };

    let Some(children) = forest.children.get(&pid) else {
        return;
    };

    for (index, child_pid) in children.iter().enumerate() {
        render_process(
            output,
            forest,
            *child_pid,
            &next_prefix,
            index + 1 == children.len(),
            show_pid,
            verbose,
        );
    }
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
    use tempfile::TempDir;

    fn target() -> TargetUser {
        TargetUser {
            name: "rezky".to_owned(),
            uid: 1000,
        }
    }

    fn process(name: &str, pid: u32, ppid: u32) -> Process {
        Process {
            name: name.to_owned(),
            pid,
            ppid,
            uid: 1000,
            cmdline: None,
            state: "?".to_owned(),
            vm_rss_kb: 0,
            vm_size_kb: 0,
            threads: 1,
        }
    }

    fn report() -> ScanReport {
        ScanReport {
            processes: vec![
                process("bash", 20, 1),
                process("python3", 30, 20),
                process("codex", 40, 30),
                process("worker", 50, 40),
            ],
            unreadable_statuses: 0,
        }
    }

    fn view(max_depth: Option<usize>, find: Option<&str>) -> ViewOptions {
        ViewOptions {
            max_depth,
            find: find.map(str::to_owned),
            verbose: false,
        }
    }

    #[test]
    fn accepts_default_interval_for_live_mode() {
        assert_eq!(validate_interval(true, None), Ok(DEFAULT_INTERVAL_SECONDS));
    }

    #[test]
    fn accepts_interval_bounds_for_live_mode() {
        assert_eq!(validate_interval(true, Some(MIN_INTERVAL_SECONDS)), Ok(3));
        assert_eq!(validate_interval(true, Some(MAX_INTERVAL_SECONDS)), Ok(60));
    }

    #[test]
    fn rejects_interval_outside_bounds() {
        assert_eq!(
            validate_interval(true, Some(2)),
            Err("--interval must be between 3 and 60 seconds".to_owned())
        );
        assert_eq!(
            validate_interval(true, Some(61)),
            Err("--interval must be between 3 and 60 seconds".to_owned())
        );
    }

    #[test]
    fn rejects_interval_without_live_mode() {
        assert_eq!(
            validate_interval(false, Some(6)),
            Err("--interval requires --live".to_owned())
        );
    }

    #[test]
    fn watch_behaves_like_live_for_interval_validation() {
        assert!(is_live_mode(false, true));
        assert_eq!(validate_interval(is_live_mode(false, true), Some(3)), Ok(3));
    }

    #[test]
    fn resolves_numeric_uid_target() {
        assert_eq!(
            resolve_user_or_uid("4294967295").unwrap(),
            TargetUser {
                name: "uid=4294967295".to_owned(),
                uid: u32::MAX,
            }
        );
    }

    #[test]
    fn resolves_me_to_current_user() {
        let user = resolve_target(true, None).unwrap();
        assert_eq!(user.uid, current_uid().unwrap());
    }

    #[test]
    fn rejects_missing_target() {
        assert_eq!(
            resolve_target(false, None),
            Err("expected USER_OR_UID or --me".to_owned())
        );
    }

    #[test]
    fn rejects_me_with_explicit_target() {
        assert_eq!(
            resolve_target(true, Some("root")),
            Err("use either --me or USER_OR_UID, not both".to_owned())
        );
    }

    #[test]
    fn parses_passwd_entries() {
        assert_eq!(
            parse_passwd_entries(
                "root:x:0:0:root:/root:/bin/bash\nrezky:x:1000:1000::/home/rezky:/bin/zsh\n"
            )
            .unwrap(),
            vec![
                PasswdEntry {
                    name: "root".to_owned(),
                    uid: 0,
                },
                PasswdEntry {
                    name: "rezky".to_owned(),
                    uid: 1000,
                },
            ]
        );
    }

    #[test]
    fn parses_linux_status_fields() {
        let contents = "\
Name:\tbash
Umask:\t0022
State:\tS (sleeping)
Pid:\t1234
PPid:\t1000
Uid:\t1000\t1000\t1000\t1000
";

        assert_eq!(
            parse_status(contents).unwrap(),
            Process {
                name: "bash".to_owned(),
                pid: 1234,
                ppid: 1000,
                uid: 1000,
                cmdline: None,
                state: "?".to_owned(),
                vm_rss_kb: 0,
                vm_size_kb: 0,
                threads: 1,
            }
        );
    }

    #[test]
    fn rejects_status_without_required_fields() {
        assert_eq!(
            parse_status("Name:\tbash\nPid:\t1234\n").unwrap_err(),
            "missing PPid"
        );
    }

    #[test]
    fn tracks_unreadable_statuses_without_real_proc() {
        let proc_root = TempDir::new().unwrap();
        let readable_pid = proc_root.path().join("1234");
        let unreadable_pid = proc_root.path().join("5678");
        fs::create_dir_all(&readable_pid).unwrap();
        fs::create_dir_all(unreadable_pid.join("status")).unwrap();
        fs::write(
            readable_pid.join("status"),
            "Name:\tbash\nPid:\t1234\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\n",
        )
        .unwrap();

        let report = scan_processes_for_uid_at(proc_root.path(), 1000).unwrap();

        assert_eq!(report.processes.len(), 1);
        assert_eq!(report.unreadable_statuses, 1);
    }

    #[test]
    fn treats_process_as_root_when_parent_is_not_in_filtered_set() {
        let forest = build_forest(vec![
            process("bash", 20, 1),
            process("python3", 30, 20),
            process("cargo", 25, 20),
        ]);

        assert_eq!(forest.roots, vec![20]);
        assert_eq!(forest.children.get(&20), Some(&vec![25, 30]));
    }

    #[test]
    fn treats_self_parent_as_root() {
        let forest = build_forest(vec![process("initlike", 1, 1)]);

        assert_eq!(forest.roots, vec![1]);
        assert!(forest.children.is_empty());
    }

    #[test]
    fn finds_process_names_case_insensitively() {
        let forest = build_forest(vec![
            process("bash", 20, 1),
            process("Codex", 30, 20),
            process("cargo", 40, 20),
        ]);

        assert_eq!(matching_process_ids(&forest, "codex"), BTreeSet::from([30]));
    }

    #[test]
    fn pruning_keeps_ancestors_and_descendants_of_matches() {
        let forest = build_forest(vec![
            process("bash", 20, 1),
            process("python3", 30, 20),
            process("codex", 40, 30),
            process("worker", 50, 40),
        ]);
        let pruned = prune_for_matches(&forest, &BTreeSet::from([40]));

        assert_eq!(pruned.roots, vec![20]);
        assert!(pruned.processes.contains_key(&20));
        assert!(pruned.processes.contains_key(&30));
        assert!(pruned.processes.contains_key(&40));
        assert!(pruned.processes.contains_key(&50));
    }

    #[test]
    fn limits_depth_zero_to_no_processes() {
        let forest = build_forest(vec![process("bash", 20, 1)]);
        let limited = limit_depth(&forest, Some(0));

        assert!(limited.roots.is_empty());
        assert!(limited.processes.is_empty());
    }

    #[test]
    fn limits_depth_two_to_roots_and_direct_children() {
        let forest = build_forest(vec![
            process("bash", 20, 1),
            process("python3", 30, 20),
            process("worker", 40, 30),
        ]);
        let limited = limit_depth(&forest, Some(2));

        assert_eq!(limited.roots, vec![20]);
        assert_eq!(limited.processes.len(), 2);
        assert!(limited.processes.contains_key(&20));
        assert!(limited.processes.contains_key(&30));
        assert!(!limited.processes.contains_key(&40));
    }

    #[test]
    fn renders_tree_with_pid() {
        let output = render_forest(
            &target(),
            &build_forest(vec![
                process("bash", 20, 1),
                process("python3", 30, 20),
                process("cargo", 25, 20),
            ]),
            true,
            false,
        );

        // state=? because test Process defaults to "?"
        assert!(output.contains("bash pid=20 state=?"));
        assert!(output.contains("cargo pid=25 state=?"));
        assert!(output.contains("python3 pid=30 state=?"));
    }

    #[test]
    fn renders_tree_without_pid() {
        let output = render_forest(
            &target(),
            &build_forest(vec![process("bash", 20, 1), process("python3", 30, 20)]),
            false,
            false,
        );

        assert!(output.contains("bash state=?"));
        assert!(output.contains("python3 state=?"));
        assert!(!output.contains(" pid="));
    }

    #[test]
    fn renders_stable_summary() {
        let forest = build_forest(vec![
            process("bash", 20, 1),
            process("python3", 30, 20),
            process("cargo", 25, 20),
        ]);

        assert_eq!(render_summary(&forest), "1 roots · 3 processes");
    }

    #[test]
    fn depth_zero_renders_header_and_summary_only() {
        let output = render_report(&target(), report(), true, &view(Some(0), None), None);

        assert_eq!(output, "rezky uid=1000\n\n0 roots · 0 processes\n");
    }

    #[test]
    fn depth_combines_with_no_pid() {
        let output = render_report(&target(), report(), false, &view(Some(2), None), None);

        // state=? always shown now (even without --verbose)
        assert_eq!(
            output,
            "rezky uid=1000\n└── bash state=?\n    └── python3 state=?\n\n1 roots · 2 processes\n"
        );
        assert!(!output.contains(" pid="));
    }

    #[test]
    fn find_no_match_returns_clean_message() {
        let output = render_report(
            &target(),
            report(),
            true,
            &view(None, Some("missing")),
            None,
        );

        assert_eq!(output, "No processes matched 'missing'.\n");
    }
}
