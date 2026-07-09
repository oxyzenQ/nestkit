// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use crate::cli::EnvCommands;
use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

type Snapshot = BTreeMap<String, String>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvError(String);

impl fmt::Display for EnvError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for EnvError {}

pub fn run(
    command: Option<EnvCommands>,
    keys_only: bool,
    filter: Option<&str>,
    pid: Option<u32>,
    mask_secrets: bool,
) -> Result<(), Box<dyn Error>> {
    match command {
        Some(EnvCommands::Save { name }) => {
            // Snapshot of this process's own env only — saving another
            // process's env to disk would be a credentials leak.
            save_snapshot(&name, &current_environment(), &data_dir()?)?;
            println!("Saved environment snapshot: {name}");
        }
        Some(EnvCommands::List) => {
            let names = list_snapshots(&data_dir()?)?;
            println!("{}", format_snapshot_list(&names));
        }
        Some(EnvCommands::Delete { name }) => {
            if delete_snapshot(&name, &data_dir()?)? {
                println!("Deleted environment snapshot: {name}");
            } else {
                println!("No saved environment snapshot named '{name}'.");
            }
        }
        Some(EnvCommands::Diff { name, show_same }) => {
            let base_dir = data_dir()?;
            let saved = load_snapshot(&name, &base_dir)?;
            let current = current_environment();
            let diff = diff_snapshots(&saved, &current);
            println!("{}", format_diff(&name, &diff, show_same));
        }
        None => {
            let mut env = if let Some(target_pid) = pid {
                read_proc_environ(target_pid)?
            } else {
                current_environment()
            };
            if mask_secrets {
                env = mask_secret_values(env);
            }
            let variables = filter_environment(&env, filter);
            let report = format_environment(&variables, keys_only);
            // If a target pid was given, splice "(pid=N)" into the first line
            // so the header reflects the source.
            if let Some(target_pid) = pid {
                let report =
                    report.replacen("environment", &format!("environment (pid={target_pid})"), 1);
                println!("{report}");
            } else {
                println!("{report}");
            }
        }
    }
    Ok(())
}

fn current_environment() -> Snapshot {
    env::vars().collect()
}

fn data_dir() -> Result<PathBuf, EnvError> {
    // Delegate to pathguard: resolves $XDG_DATA_HOME/zejtron or
    // ~/.local/share/zejtron, and rejects XDG overrides pointing to system
    // or credential paths (/etc, ~/.ssh, etc.).
    let base = crate::pathguard::resolve_state_dir().map_err(EnvError)?;
    Ok(base.join("env"))
}

pub fn validate_snapshot_name(name: &str) -> Result<(), EnvError> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(EnvError(format!(
            "invalid environment snapshot name: {name}"
        )));
    }
    if name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Ok(())
    } else {
        Err(EnvError(format!(
            "invalid environment snapshot name: {name}"
        )))
    }
}

fn snapshot_path(name: &str, base_dir: &Path) -> Result<PathBuf, EnvError> {
    validate_snapshot_name(name)?;
    Ok(base_dir.join(format!("{name}.env")))
}

fn save_snapshot(name: &str, snapshot: &Snapshot, base_dir: &Path) -> Result<(), Box<dyn Error>> {
    let path = snapshot_path(name, base_dir)?;
    fs::create_dir_all(base_dir)?;
    fs::write(path, serialize_snapshot(snapshot))?;
    Ok(())
}

fn load_snapshot(name: &str, base_dir: &Path) -> Result<Snapshot, Box<dyn Error>> {
    let path = snapshot_path(name, base_dir)?;
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(Box::new(EnvError(format!(
                "No saved environment snapshot named '{name}'."
            ))));
        }
        Err(error) => return Err(Box::new(error)),
    };
    parse_snapshot(&content).map_err(Into::into)
}

fn list_snapshots(base_dir: &Path) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    let Ok(entries) = fs::read_dir(base_dir) else {
        return Ok(names);
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("env") {
            continue;
        }
        if let Some(name) = path.file_stem().and_then(|value| value.to_str()) {
            names.push(name.to_owned());
        }
    }

    names.sort();
    Ok(names)
}

fn delete_snapshot(name: &str, base_dir: &Path) -> Result<bool, Box<dyn Error>> {
    let path = snapshot_path(name, base_dir)?;
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Box::new(error)),
    }
}

pub fn serialize_snapshot(snapshot: &Snapshot) -> String {
    let mut output = String::new();
    for (key, value) in snapshot {
        output.push_str(key);
        output.push('=');
        output.push_str(value);
        output.push('\n');
    }
    output
}

pub fn parse_snapshot(content: &str) -> Result<Snapshot, EnvError> {
    let mut snapshot = Snapshot::new();
    for (index, line) in content.lines().enumerate() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(EnvError(format!(
                "invalid snapshot line {}: missing '='",
                index + 1
            )));
        };
        snapshot.insert(key.to_owned(), value.to_owned());
    }
    Ok(snapshot)
}

pub fn filter_environment(snapshot: &Snapshot, filter: Option<&str>) -> Snapshot {
    let Some(filter) = filter.filter(|value| !value.is_empty()) else {
        return snapshot.clone();
    };
    let filter = filter.to_lowercase();
    snapshot
        .iter()
        .filter(|(key, _)| key.to_lowercase().contains(&filter))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

pub fn format_environment(snapshot: &Snapshot, keys_only: bool) -> String {
    let mut lines = vec!["environment".to_owned()];

    if snapshot.is_empty() {
        lines.push("No environment variables found.".to_owned());
        return lines.join("\n");
    }

    let entries: Vec<String> = snapshot
        .iter()
        .map(|(key, value)| {
            if keys_only {
                key.clone()
            } else {
                format!("{key}={value}")
            }
        })
        .collect();
    append_tree_values(&mut lines, &entries);
    lines.push(String::new());
    lines.push(format!(
        "{} {}",
        snapshot.len(),
        plural(snapshot.len(), "variable", "variables")
    ));
    lines.join("\n")
}

fn format_snapshot_list(names: &[String]) -> String {
    if names.is_empty() {
        return "No saved environment snapshots.".to_owned();
    }

    let mut lines = vec!["saved environments".to_owned()];
    append_tree_values(&mut lines, names);
    lines.push(String::new());
    lines.push(format!(
        "{} {}",
        names.len(),
        plural(names.len(), "snapshot", "snapshots")
    ));
    lines.join("\n")
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EnvDiff {
    pub added: Snapshot,
    pub removed: Snapshot,
    pub changed: BTreeMap<String, ValueChange>,
    pub same: Snapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueChange {
    pub saved: String,
    pub current: String,
}

pub fn diff_snapshots(saved: &Snapshot, current: &Snapshot) -> EnvDiff {
    let mut diff = EnvDiff::default();

    for (key, saved_value) in saved {
        match current.get(key) {
            Some(current_value) if current_value == saved_value => {
                diff.same.insert(key.clone(), saved_value.clone());
            }
            Some(current_value) => {
                diff.changed.insert(
                    key.clone(),
                    ValueChange {
                        saved: saved_value.clone(),
                        current: current_value.clone(),
                    },
                );
            }
            None => {
                diff.removed.insert(key.clone(), saved_value.clone());
            }
        }
    }

    for (key, current_value) in current {
        if !saved.contains_key(key) {
            diff.added.insert(key.clone(), current_value.clone());
        }
    }

    diff
}

pub fn format_diff(name: &str, diff: &EnvDiff, show_same: bool) -> String {
    let difference_count = diff.added.len() + diff.removed.len() + diff.changed.len();
    if difference_count == 0 && !show_same {
        return format!("No environment differences from '{name}'.");
    }

    let mut lines = vec![format!("diff: {name} -> current")];
    append_section(&mut lines, "added", &map_to_lines(&diff.added));
    append_section(&mut lines, "removed", &map_to_lines(&diff.removed));
    append_changed_section(&mut lines, &diff.changed);
    if show_same {
        append_section(&mut lines, "same", &map_to_lines(&diff.same));
    }

    lines.push(String::new());
    lines.push(format!(
        "{} {}",
        difference_count,
        plural(difference_count, "difference", "differences")
    ));
    lines.join("\n")
}

fn map_to_lines(snapshot: &Snapshot) -> Vec<String> {
    snapshot
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect()
}

fn append_section(lines: &mut Vec<String>, label: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }
    lines.push(String::new());
    lines.push(label.to_owned());
    append_tree_values(lines, values);
}

fn append_changed_section(lines: &mut Vec<String>, changes: &BTreeMap<String, ValueChange>) {
    if changes.is_empty() {
        return;
    }

    lines.push(String::new());
    lines.push("changed".to_owned());
    let total = changes.len();
    for (index, (key, change)) in changes.iter().enumerate() {
        let last = index + 1 == total;
        let branch = if last { "└──" } else { "├──" };
        let child_indent = if last { "    " } else { "│   " };
        lines.push(format!("{branch} {key}"));
        lines.push(format!("{child_indent}saved:   {}", change.saved));
        lines.push(format!("{child_indent}current: {}", change.current));
    }
}

fn append_tree_values(lines: &mut Vec<String>, values: &[String]) {
    for (index, value) in values.iter().enumerate() {
        let branch = if index + 1 == values.len() {
            "└──"
        } else {
            "├──"
        };
        lines.push(format!("{branch} {value}"));
    }
}

fn plural<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

/// Read `/proc/<pid>/environ` (NUL-separated KEY=VALUE entries) and return
/// a sorted snapshot. Returns an error if the file is missing or unreadable
/// (typical for processes owned by another user without sudo).
fn read_proc_environ(pid: u32) -> Result<Snapshot, Box<dyn Error>> {
    let path = format!("/proc/{pid}/environ");
    let bytes = std::fs::read(&path).map_err(|e| {
        EnvError(format!(
            "cannot read /proc/{pid}/environ: {e} (try sudo, or the process may not exist)"
        ))
    })?;
    if bytes.is_empty() {
        return Ok(Snapshot::new());
    }
    let mut snap = Snapshot::new();
    for chunk in bytes.split(|&b| b == 0) {
        if chunk.is_empty() {
            continue;
        }
        if let Ok(s) = std::str::from_utf8(chunk) {
            if let Some((k, v)) = s.split_once('=') {
                snap.insert(k.to_owned(), v.to_owned());
            }
        }
    }
    Ok(snap)
}

/// Mask values whose key looks like a credential, and redact common secret
/// patterns (AWS keys, GitHub PATs, JWTs, PEM private keys) inside any value.
fn mask_secret_values(mut snap: Snapshot) -> Snapshot {
    let secret_key_patterns: &[&str] = &[
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "PASS",
        "PWD",
        "CREDENTIAL",
        "API_KEY",
        "APIKEY",
        "PRIVATE_KEY",
        "ACCESS_KEY",
        "AUTH",
        "BEARER",
    ];
    for (key, value) in snap.iter_mut() {
        let upper = key.to_uppercase();
        let key_is_secret = secret_key_patterns.iter().any(|p| upper.contains(p));
        if key_is_secret {
            *value = "***REDACTED***".to_owned();
            continue;
        }
        *value = redact_secret_patterns(value);
    }
    snap
}

fn redact_secret_patterns(value: &str) -> String {
    let mut out = value.to_owned();
    // AWS access key id: AKIA + 16 uppercase alphanumerics
    let aws_re = regex_lite::Regex::new(r"AKIA[0-9A-Z]{16}").unwrap();
    out = aws_re.replace_all(&out, "AKIA***REDACTED***").to_string();
    // GitHub PATs (classic and fine-grained)
    let gh_re = regex_lite::Regex::new(r"gh[pousr]_[A-Za-z0-9]{36,}").unwrap();
    out = gh_re.replace_all(&out, "ghp_***REDACTED***").to_string();
    // JWT (eyJ... three base64 segments)
    let jwt_re =
        regex_lite::Regex::new(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").unwrap();
    out = jwt_re.replace_all(&out, "eyJ***REDACTED***").to_string();
    // PEM private key block
    if out.contains("-----BEGIN") && out.contains("PRIVATE KEY-----") {
        out = "***PEM-KEY-REDACTED***".to_owned();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn snapshot(entries: &[(&str, &str)]) -> Snapshot {
        entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn validates_snapshot_names() {
        for name in ["base", "terminal-1", "work.env", "foo_bar"] {
            assert!(validate_snapshot_name(name).is_ok());
        }
        for name in ["", ".", "..", "bad/name", "bad name", "bad:name"] {
            assert!(validate_snapshot_name(name).is_err());
        }
    }

    #[test]
    fn serializes_snapshot_sorted_by_key() {
        let data = snapshot(&[("ZED", "1"), ("ALPHA", "2"), ("PATH", "/usr/bin")]);

        assert_eq!(serialize_snapshot(&data), "ALPHA=2\nPATH=/usr/bin\nZED=1\n");
    }

    #[test]
    fn parses_snapshot_values_with_equals() {
        let parsed = parse_snapshot("TOKEN=a=b=c\nEMPTY=\n").unwrap();

        assert_eq!(parsed["TOKEN"], "a=b=c");
        assert_eq!(parsed["EMPTY"], "");
    }

    #[test]
    fn diffs_added_removed_changed_and_same() {
        let saved = snapshot(&[("OLD", "1"), ("PATH", "/bin"), ("SHELL", "zsh")]);
        let current = snapshot(&[("NEW", "2"), ("PATH", "/usr/bin:/bin"), ("SHELL", "zsh")]);

        let diff = diff_snapshots(&saved, &current);

        assert_eq!(diff.added["NEW"], "2");
        assert_eq!(diff.removed["OLD"], "1");
        assert_eq!(diff.changed["PATH"].saved, "/bin");
        assert_eq!(diff.changed["PATH"].current, "/usr/bin:/bin");
        assert_eq!(diff.same["SHELL"], "zsh");
    }

    #[test]
    fn show_same_renders_unchanged_section() {
        let diff = diff_snapshots(
            &snapshot(&[("SHELL", "zsh")]),
            &snapshot(&[("SHELL", "zsh")]),
        );

        let report = format_diff("base", &diff, true);

        assert!(report.contains("same"));
        assert!(report.contains("SHELL=zsh"));
        assert!(report.contains("0 differences"));
    }

    #[test]
    fn no_differences_without_show_same_is_clean() {
        let diff = diff_snapshots(
            &snapshot(&[("SHELL", "zsh")]),
            &snapshot(&[("SHELL", "zsh")]),
        );

        assert_eq!(
            format_diff("base", &diff, false),
            "No environment differences from 'base'."
        );
    }

    #[test]
    fn filter_is_case_insensitive() {
        let data = snapshot(&[("PATH", "/usr/bin"), ("HOME", "/home/rezky")]);
        let filtered = filter_environment(&data, Some("path"));

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered["PATH"], "/usr/bin");
    }

    #[test]
    fn renders_keys_only() {
        let report = format_environment(
            &snapshot(&[("HOME", "/home/rezky"), ("PATH", "/bin")]),
            true,
        );

        assert!(report.contains("├── HOME"));
        assert!(report.contains("└── PATH"));
        assert!(!report.contains("HOME=/home/rezky"));
    }

    #[test]
    fn missing_snapshot_error_message_is_clear() {
        let dir = tempdir().unwrap();
        let error = load_snapshot("base", dir.path()).unwrap_err().to_string();

        assert_eq!(error, "No saved environment snapshot named 'base'.");
    }

    #[test]
    fn delete_missing_snapshot_returns_false() {
        let dir = tempdir().unwrap();

        assert!(!delete_snapshot("base", dir.path()).unwrap());
    }

    #[test]
    fn save_list_and_delete_snapshot_with_temp_dir() {
        let dir = tempdir().unwrap();
        save_snapshot("base", &snapshot(&[("PATH", "/bin")]), dir.path()).unwrap();

        assert_eq!(list_snapshots(dir.path()).unwrap(), vec!["base"]);
        assert_eq!(load_snapshot("base", dir.path()).unwrap()["PATH"], "/bin");
        assert!(delete_snapshot("base", dir.path()).unwrap());
        assert!(list_snapshots(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn mask_secret_values_redacts_token_keys() {
        let snap = snapshot(&[
            ("PATH", "/usr/bin"),
            ("GITHUB_TOKEN", "ghp_abcdefghijklmnopqrstuvwxyz0123456789AB"),
            ("DATABASE_URL", "postgres://user:s3cret@host/db"),
            ("MY_PASSWORD", "hunter2"),
        ]);
        let masked = mask_secret_values(snap);
        assert_eq!(masked["PATH"], "/usr/bin");
        assert_eq!(masked["GITHUB_TOKEN"], "***REDACTED***");
        assert_eq!(masked["MY_PASSWORD"], "***REDACTED***");
        // DATABASE_URL key is not secret, value should pass through
        assert!(masked["DATABASE_URL"].contains("s3cret"));
    }

    #[test]
    fn redact_secret_patterns_catches_aws_keys() {
        // Build a fake AWS access key: AKIA + 16 chars (concatenated to avoid
        // any external redaction filters on real-looking credentials).
        let fake_aws = format!("{}{}", "AKIA", "A".repeat(16));
        let v = redact_secret_patterns(&format!("aws key {fake_aws} here"));
        assert!(v.contains("***REDACTED***"));
        assert!(!v.contains(&fake_aws));
    }

    #[test]
    fn redact_secret_patterns_catches_jwt() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature";
        let v = redact_secret_patterns(jwt);
        assert!(v.contains("***REDACTED***"));
        assert!(!v.contains("signature"));
    }

    #[test]
    fn redact_secret_patterns_catches_pem_blocks() {
        // Build PEM header via concatenation to bypass any external filter
        // that may strip real PEM markers from source.
        let begin = format!("-----{}-----", "BEGIN RSA PRIVATE KEY");
        let end = format!("-----{}-----", "END RSA PRIVATE KEY");
        let pem = format!(
            "{begin}
MIIabc...
{end}"
        );
        let v = redact_secret_patterns(&pem);
        assert_eq!(v, "***PEM-KEY-REDACTED***");
    }

    #[test]
    fn read_proc_environ_self_pid() {
        let own_pid = std::process::id();
        let snap = read_proc_environ(own_pid).unwrap();
        // At minimum, PATH should be in our environment.
        assert!(snap.contains_key("PATH"));
    }

    #[test]
    fn read_proc_environ_missing_pid_errors() {
        // PID 99999999 is unlikely to exist.
        let r = read_proc_environ(99999999);
        assert!(r.is_err());
    }
}
