// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use std::env;
use std::error::Error;
use std::fs;

const SAFE_ENV_KEYS: &[&str] = &[
    "HISTFILE",
    "SHELL",
    "STARSHIP_SHELL",
    "TERM",
    "XDG_CONFIG_HOME",
    "ZDOTDIR",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentProcess {
    pub name: String,
    pub pid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigStatus {
    Readable,
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigEntry {
    pub display_path: String,
    pub status: ConfigStatus,
}

/// Describes where config paths were resolved from.
/// "parent" means the parent process name was used;
/// "login" means $SHELL was used as fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSource {
    Parent(String),
    Login(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellReport {
    pub parent: Option<ParentProcess>,
    pub login_shell: Option<String>,
    pub terminal: Option<String>,
    pub env_vars: Vec<(String, String)>,
    pub configs: Vec<ConfigEntry>,
    pub config_source: Option<ConfigSource>,
    pub ancestor_chain: Vec<AncestorEntry>,
}

/// One entry in the ancestor process chain (from current process to PID 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AncestorEntry {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub cmdline: Option<String>,
}

pub fn run() -> Result<(), Box<dyn Error>> {
    let report = collect_report();
    println!("{}", render_report(&report));
    Ok(())
}

fn collect_report() -> ShellReport {
    let parent = read_parent_process();
    let login_shell = env::var("SHELL").ok();
    let terminal = env::var("TERM").ok();
    let env_vars = filter_shell_env();
    let home = env::var("HOME").ok();
    let zdotdir = env::var("ZDOTDIR").ok();
    let xdg_config_home = env::var("XDG_CONFIG_HOME").ok();

    let detected_shell = parent.as_ref().and_then(|p| classify_shell(&p.name));

    let login_name = login_shell
        .as_deref()
        .and_then(|path| shell_name_from_path(path))
        .and_then(|name| classify_shell(name));

    let config_shell = detected_shell.or(login_name);
    let config_source = match (detected_shell, login_name) {
        (Some(shell), _) => Some(ConfigSource::Parent(shell.to_owned())),
        (None, Some(shell)) => Some(ConfigSource::Login(shell.to_owned())),
        (None, None) => None,
    };

    let configs = match (&home, &zdotdir, &xdg_config_home, config_shell) {
        (Some(home), zdotdir, xdg_config_home, Some(shell)) => {
            config_paths(shell, home, zdotdir.as_deref(), xdg_config_home.as_deref())
        }
        (None, _, _, _) => {
            vec![ConfigEntry {
                display_path: "HOME is not set; cannot resolve config paths".to_owned(),
                status: ConfigStatus::Missing,
            }]
        }
        _ => vec![],
    };

    ShellReport {
        parent,
        login_shell,
        terminal,
        env_vars,
        configs,
        config_source,
        ancestor_chain: read_ancestor_chain(),
    }
}

/// Walk the full ancestor chain from the current process to PID 1.
fn read_ancestor_chain() -> Vec<AncestorEntry> {
    let own_pid = std::process::id();
    let chain = crate::process::parent_chain(std::path::Path::new("/proc"), own_pid);
    chain
        .into_iter()
        .map(|ctx| AncestorEntry {
            pid: ctx.pid,
            ppid: ctx.ppid,
            name: ctx.name,
            cmdline: ctx.cmdline,
        })
        .collect()
}

fn read_parent_process() -> Option<ParentProcess> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let ppid = parse_ppid(&status)?;
    let name = read_proc_comm(ppid).unwrap_or_else(|| format!("pid={ppid}"));
    Some(ParentProcess { name, pid: ppid })
}

fn parse_ppid(status: &str) -> Option<u32> {
    status.lines().find_map(|line| {
        let rest = line.strip_prefix("PPid:")?;
        let trimmed = rest.trim();
        trimmed.parse::<u32>().ok()
    })
}

fn read_proc_comm(pid: u32) -> Option<String> {
    let path = format!("/proc/{pid}/comm");
    let content = fs::read_to_string(path).ok()?;
    Some(content.trim().to_owned())
}

pub fn classify_shell(name: &str) -> Option<&'static str> {
    let lower = name.to_lowercase();
    let bare = lower.strip_suffix(".exe").unwrap_or(&lower);

    if bare == "zsh" || bare == "-zsh" {
        return Some("zsh");
    }
    if bare == "bash" || bare == "-bash" {
        return Some("bash");
    }
    if bare == "fish" || bare == "-fish" {
        return Some("fish");
    }
    if bare == "dash" || bare == "-dash" {
        return Some("dash");
    }
    if bare == "nu" || bare == "-nu" {
        return Some("nu");
    }
    if bare == "sh" || bare == "-sh" {
        return Some("sh");
    }
    None
}

pub fn shell_name_from_path(path: &str) -> Option<&str> {
    let trimmed = path.trim();
    let filename = trimmed.rsplit('/').next().filter(|s| !s.is_empty())?;
    Some(filename)
}

pub fn config_paths(
    shell: &str,
    home: &str,
    zdotdir: Option<&str>,
    xdg_config_home: Option<&str>,
) -> Vec<ConfigEntry> {
    match shell {
        "zsh" => config_paths_zsh(home, zdotdir),
        "bash" => config_paths_bash(home),
        "fish" => config_paths_fish(home, xdg_config_home),
        "dash" | "sh" => config_paths_sh(home),
        _ => vec![],
    }
}

fn config_paths_zsh(home: &str, zdotdir: Option<&str>) -> Vec<ConfigEntry> {
    let base = zdotdir.unwrap_or(home);
    let files = [".zshenv", ".zprofile", ".zshrc", ".zlogin", ".zlogout"];
    files
        .iter()
        .map(|file| config_entry(base, file, home))
        .collect()
}

fn config_paths_bash(home: &str) -> Vec<ConfigEntry> {
    let files = [
        ".bash_profile",
        ".bash_login",
        ".profile",
        ".bashrc",
        ".bash_logout",
    ];
    files
        .iter()
        .map(|file| config_entry(home, file, home))
        .collect()
}

fn config_paths_fish(home: &str, xdg_config_home: Option<&str>) -> Vec<ConfigEntry> {
    let config_dir = xdg_config_home
        .map(|d| d.to_owned())
        .unwrap_or_else(|| format!("{home}/.config"));
    let path = format!("{config_dir}/fish/config.fish");
    vec![config_entry_from_path(&path, home)]
}

fn config_paths_sh(home: &str) -> Vec<ConfigEntry> {
    vec![config_entry(home, ".profile", home)]
}

fn config_entry(base: &str, filename: &str, home: &str) -> ConfigEntry {
    let full = format!("{base}/{filename}");
    let display_path = expand_home(&full, home);
    let status = check_file_status(&full);
    ConfigEntry {
        display_path,
        status,
    }
}

fn config_entry_from_path(path: &str, home: &str) -> ConfigEntry {
    let display_path = expand_home(path, home);
    ConfigEntry {
        display_path,
        status: check_file_status(path),
    }
}

fn expand_home(path: &str, home: &str) -> String {
    if let Some(rest) = path.strip_prefix(home) {
        if rest.starts_with('/') {
            return format!("~{rest}");
        }
    }
    path.to_owned()
}

fn check_file_status(path: &str) -> ConfigStatus {
    match fs::metadata(path) {
        Ok(_) => {
            if fs::read_to_string(path).is_ok() {
                ConfigStatus::Readable
            } else {
                ConfigStatus::Missing
            }
        }
        Err(_) => ConfigStatus::Missing,
    }
}

pub fn filter_shell_env() -> Vec<(String, String)> {
    let mut vars = Vec::new();
    for key in SAFE_ENV_KEYS {
        if let Ok(value) = env::var(key) {
            vars.push((String::from(*key), value));
        }
    }
    vars.sort_by(|a, b| a.0.cmp(&b.0));
    vars
}

pub fn render_report(report: &ShellReport) -> String {
    let mut lines = vec!["shell".to_owned()];

    render_invocation_section(&mut lines, report);
    render_terminal_section(&mut lines, report);
    render_env_section(&mut lines, report);
    render_configs_section(&mut lines, report);
    render_ancestor_chain_section(&mut lines, report);

    lines.join("\n")
}

fn render_ancestor_chain_section(lines: &mut Vec<String>, report: &ShellReport) {
    if report.ancestor_chain.is_empty() {
        return;
    }
    lines.push(String::new());
    lines.push("└── ancestor-chain (to PID 1)".to_owned());
    for (i, entry) in report.ancestor_chain.iter().enumerate() {
        let is_last = i + 1 == report.ancestor_chain.len();
        let branch = if is_last { "└──" } else { "├──" };
        let mut line = format!("    {branch} {} pid={}", entry.name, entry.pid);
        if entry.pid != 1 {
            line.push_str(&format!(" (ppid={})", entry.ppid));
        }
        if let Some(ref cmd) = entry.cmdline {
            if !cmd.is_empty() && cmd.as_str() != entry.name {
                // Truncate long cmdlines for readability
                let truncated = if cmd.len() > 80 {
                    format!("{}...", &cmd[..77])
                } else {
                    cmd.clone()
                };
                line.push_str(&format!(" cmd={truncated}"));
            }
        }
        lines.push(line);
    }
}

fn render_invocation_section(lines: &mut Vec<String>, report: &ShellReport) {
    let has_parent = report.parent.is_some();
    let has_login = report.login_shell.is_some();

    if !has_parent && !has_login {
        return;
    }

    lines.push(String::new());
    lines.push("├── invocation".to_owned());

    match (&report.parent, &report.login_shell) {
        (Some(parent), Some(login)) => {
            lines.push(format!(
                "│   ├── parent: {} pid={}",
                parent.name, parent.pid
            ));
            lines.push(format!("│   └── login: {login}"));
        }
        (Some(parent), None) => {
            lines.push(format!(
                "│   └── parent: {} pid={}",
                parent.name, parent.pid
            ));
        }
        (None, Some(login)) => {
            lines.push(format!("│   └── login: {login}"));
        }
        (None, None) => {}
    }
}

fn render_terminal_section(lines: &mut Vec<String>, report: &ShellReport) {
    let Some(term) = &report.terminal else {
        return;
    };
    let has_configs = !report.configs.is_empty();
    let branch = if has_configs { "├" } else { "└" };
    lines.push(format!("{branch}── terminal"));
    if has_configs {
        lines.push(format!("│   └── TERM={term}"));
    } else {
        lines.push(format!("    └── TERM={term}"));
    }
}

fn render_env_section(lines: &mut Vec<String>, report: &ShellReport) {
    if report.env_vars.is_empty() {
        return;
    }
    let has_configs = !report.configs.is_empty();
    let branch = if has_configs { "├" } else { "└" };
    lines.push(format!("{branch}── environment"));

    for (index, (key, value)) in report.env_vars.iter().enumerate() {
        let is_last = index + 1 == report.env_vars.len();
        let indent = if has_configs { "│" } else { " " };
        let leaf = if is_last { "└" } else { "├" };
        lines.push(format!("{indent}   {leaf}── {key}={value}"));
    }
}

fn render_configs_section(lines: &mut Vec<String>, report: &ShellReport) {
    if report.configs.is_empty() {
        return;
    }
    let source_label = match &report.config_source {
        Some(ConfigSource::Parent(shell)) => format!("configs ({shell}, via parent process)"),
        Some(ConfigSource::Login(shell)) => format!("configs ({shell}, via $SHELL)"),
        None => "configs".to_owned(),
    };
    lines.push(format!("└── {source_label}"));

    for (index, entry) in report.configs.iter().enumerate() {
        let is_last = index + 1 == report.configs.len();
        let branch = if is_last { "└──" } else { "├──" };
        let status_label = match entry.status {
            ConfigStatus::Readable => "readable",
            ConfigStatus::Missing => "missing",
        };
        lines.push(format!(
            "    {branch} {} {status_label}",
            entry.display_path
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_cmdline_bytes(bytes: &[u8]) -> Vec<String> {
        let mut args = Vec::new();
        let mut current = Vec::new();
        for &byte in bytes {
            if byte == 0 {
                if !current.is_empty() {
                    args.push(String::from_utf8_lossy(&current).to_string());
                    current.clear();
                }
            } else {
                current.push(byte);
            }
        }
        if !current.is_empty() {
            args.push(String::from_utf8_lossy(&current).to_string());
        }
        args
    }

    #[test]
    fn classifies_known_shells() {
        assert_eq!(classify_shell("zsh"), Some("zsh"));
        assert_eq!(classify_shell("bash"), Some("bash"));
        assert_eq!(classify_shell("fish"), Some("fish"));
        assert_eq!(classify_shell("dash"), Some("dash"));
        assert_eq!(classify_shell("sh"), Some("sh"));
        assert_eq!(classify_shell("nu"), Some("nu"));
    }

    #[test]
    fn classifies_login_shell_prefix() {
        assert_eq!(classify_shell("-zsh"), Some("zsh"));
        assert_eq!(classify_shell("-bash"), Some("bash"));
        assert_eq!(classify_shell("-fish"), Some("fish"));
        assert_eq!(classify_shell("-sh"), Some("sh"));
    }

    #[test]
    fn classifies_unknown_as_none() {
        assert_eq!(classify_shell("python3"), None);
        assert_eq!(classify_shell("vim"), None);
        assert_eq!(classify_shell(""), None);
    }

    #[test]
    fn classifies_case_insensitive() {
        assert_eq!(classify_shell("ZSH"), Some("zsh"));
        assert_eq!(classify_shell("BASH"), Some("bash"));
        assert_eq!(classify_shell("Fish"), Some("fish"));
    }

    #[test]
    fn extracts_shell_name_from_path() {
        assert_eq!(shell_name_from_path("/bin/zsh"), Some("zsh"));
        assert_eq!(shell_name_from_path("/usr/bin/bash"), Some("bash"));
        assert_eq!(shell_name_from_path("/bin/fish"), Some("fish"));
        assert_eq!(shell_name_from_path("/usr/local/bin/dash"), Some("dash"));
    }

    #[test]
    fn extracts_shell_name_from_trailing_slash() {
        assert_eq!(shell_name_from_path("/bin/"), None);
        assert_eq!(shell_name_from_path("/"), None);
    }

    #[test]
    fn extracts_shell_name_from_bare_filename() {
        assert_eq!(shell_name_from_path("sh"), Some("sh"));
        assert_eq!(shell_name_from_path("bash"), Some("bash"));
    }

    #[test]
    fn parses_cmdline_with_nul_separators() {
        let bytes: &[u8] = b"bash\0--login\0-i\0";
        let args = parse_cmdline_bytes(bytes);
        assert_eq!(args, vec!["bash", "--login", "-i"]);
    }

    #[test]
    fn parses_cmdline_empty() {
        let args = parse_cmdline_bytes(b"");
        assert!(args.is_empty());
    }

    #[test]
    fn parses_cmdline_single_arg() {
        let args = parse_cmdline_bytes(b"zsh");
        assert_eq!(args, vec!["zsh"]);
    }

    #[test]
    fn parses_cmdline_trailing_nul() {
        let args = parse_cmdline_bytes(b"bash\0");
        assert_eq!(args, vec!["bash"]);
    }

    #[test]
    fn parses_cmdline_multiple_nuls_between() {
        let args = parse_cmdline_bytes(b"sh\0\0--help\0");
        assert_eq!(args, vec!["sh", "--help"]);
    }

    #[test]
    fn renders_parent_metadata_with_fixtures() {
        let report = ShellReport {
            parent: Some(ParentProcess {
                name: "bash".to_owned(),
                pid: 1700,
            }),
            login_shell: Some("/bin/zsh".to_owned()),
            terminal: Some("xterm-256color".to_owned()),
            env_vars: vec![
                ("SHELL".to_owned(), "/bin/zsh".to_owned()),
                ("TERM".to_owned(), "xterm-256color".to_owned()),
            ],
            configs: vec![
                ConfigEntry {
                    display_path: "~/.zshrc".to_owned(),
                    status: ConfigStatus::Readable,
                },
                ConfigEntry {
                    display_path: "~/.zshenv".to_owned(),
                    status: ConfigStatus::Missing,
                },
            ],
            config_source: Some(ConfigSource::Parent("bash".to_owned())),

            ancestor_chain: vec![],
        };

        let output = render_report(&report);

        assert!(output.starts_with("shell"));
        assert!(output.contains("parent: bash pid=1700"));
        assert!(output.contains("login: /bin/zsh"));
        assert!(output.contains("TERM=xterm-256color"));
        assert!(output.contains("SHELL=/bin/zsh"));
        assert!(output.contains("~/.zshrc readable"));
        assert!(output.contains("~/.zshenv missing"));
    }

    #[test]
    fn renders_without_parent() {
        let report = ShellReport {
            parent: None,
            login_shell: Some("/bin/bash".to_owned()),
            terminal: Some("dumb".to_owned()),
            env_vars: vec![("SHELL".to_owned(), "/bin/bash".to_owned())],
            configs: vec![],
            config_source: Some(ConfigSource::Login("bash".to_owned())),
            ancestor_chain: vec![],
        };

        let output = render_report(&report);

        assert!(output.contains("login: /bin/bash"));
        assert!(!output.contains("parent:"));
    }

    #[test]
    fn renders_without_login_shell() {
        let report = ShellReport {
            parent: Some(ParentProcess {
                name: "sh".to_owned(),
                pid: 42,
            }),
            login_shell: None,
            terminal: None,
            env_vars: vec![],
            configs: vec![],
            config_source: Some(ConfigSource::Parent("sh".to_owned())),

            ancestor_chain: vec![],
        };

        let output = render_report(&report);
        assert!(output.contains("parent: sh pid=42"));
        assert!(!output.contains("login:"));
    }

    #[test]
    fn renders_missing_home_configs() {
        let report = ShellReport {
            parent: None,
            login_shell: None,
            terminal: None,
            env_vars: vec![],
            configs: vec![ConfigEntry {
                display_path: "HOME is not set; cannot resolve config paths".to_owned(),
                status: ConfigStatus::Missing,
            }],
            config_source: None,

            ancestor_chain: vec![],
        };

        let output = render_report(&report);
        assert!(output.contains("HOME is not set"));
    }

    #[test]
    fn config_paths_zsh_with_zdotdir() {
        let entries = config_paths_zsh("/home/user", Some("/opt/zdot"));
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[0].display_path, "/opt/zdot/.zshenv");
        assert_eq!(entries[1].display_path, "/opt/zdot/.zprofile");
        assert_eq!(entries[2].display_path, "/opt/zdot/.zshrc");
    }

    #[test]
    fn config_paths_zsh_without_zdotdir() {
        let entries = config_paths_zsh("/home/user", None);
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[0].display_path, "~/.zshenv");
        assert_eq!(entries[4].display_path, "~/.zlogout");
    }

    #[test]
    fn generates_config_paths_bash() {
        let entries = super::config_paths_bash("/home/user");
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[0].display_path, "~/.bash_profile");
        assert_eq!(entries[1].display_path, "~/.bash_login");
        assert_eq!(entries[2].display_path, "~/.profile");
        assert_eq!(entries[3].display_path, "~/.bashrc");
        assert_eq!(entries[4].display_path, "~/.bash_logout");
    }

    #[test]
    fn config_paths_fish_with_xdg() {
        let entries = config_paths_fish("/home/user", Some("/opt/config"));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].display_path, "/opt/config/fish/config.fish");
    }

    #[test]
    fn config_paths_fish_without_xdg() {
        let entries = config_paths_fish("/home/user", None);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].display_path, "~/.config/fish/config.fish");
    }

    #[test]
    fn generates_config_paths_sh() {
        let entries = super::config_paths_sh("/home/user");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].display_path, "~/.profile");
    }

    #[test]
    fn config_paths_unknown_shell() {
        let entries = config_paths("python", "/home/user", None, None);
        assert!(entries.is_empty());
    }

    #[test]
    fn filter_env_returns_only_safe_keys() {
        unsafe {
            env::set_var("ZEJTRON_TEST_SHELL_VAR", "should_not_appear");
            env::remove_var("ZEJTRON_TEST_SHELL_VAR");
        }

        let vars = filter_shell_env();

        for (key, _) in &vars {
            assert!(SAFE_ENV_KEYS.contains(&key.as_str()));
        }
    }

    #[test]
    fn filter_env_returns_sorted_keys() {
        let vars = filter_shell_env();
        for window in vars.windows(2) {
            assert!(window[0].0 <= window[1].0);
        }
    }

    #[test]
    fn filter_env_returns_expected_keys_when_set() {
        unsafe {
            env::set_var("SHELL", "/bin/bash");
            env::set_var("TERM", "xterm");
        }

        let vars = filter_shell_env();

        let has_shell = vars.iter().any(|(k, _)| k == "SHELL");
        let has_term = vars.iter().any(|(k, _)| k == "TERM");
        assert!(has_shell);
        assert!(has_term);
    }

    #[test]
    fn stable_output_shape() {
        let report = ShellReport {
            parent: Some(ParentProcess {
                name: "bash".to_owned(),
                pid: 100,
            }),
            login_shell: Some("/bin/zsh".to_owned()),
            terminal: Some("xterm-256color".to_owned()),
            env_vars: vec![("SHELL".to_owned(), "/bin/zsh".to_owned())],
            configs: vec![ConfigEntry {
                display_path: "~/.zshrc".to_owned(),
                status: ConfigStatus::Readable,
            }],
            config_source: Some(ConfigSource::Parent("bash".to_owned())),

            ancestor_chain: vec![],
        };

        let output = render_report(&report);

        assert!(output.starts_with("shell\n"));
        assert!(output.contains("├── invocation"));
        assert!(output.contains("│   ├── parent:"));
        assert!(output.contains("│   └── login:"));
        assert!(output.contains("├── terminal"));
        assert!(output.contains("├── environment"));
        assert!(output.contains("└── configs"));
    }

    #[test]
    fn no_malformed_tree_prefixes() {
        let report = ShellReport {
            parent: Some(ParentProcess {
                name: "bash".to_owned(),
                pid: 100,
            }),
            login_shell: Some("/bin/zsh".to_owned()),
            terminal: Some("xterm-256color".to_owned()),
            env_vars: vec![
                ("HISTFILE".to_owned(), "/home/u/.zsh_history".to_owned()),
                ("SHELL".to_owned(), "/bin/zsh".to_owned()),
                ("STARSHIP_SHELL".to_owned(), "zsh".to_owned()),
                ("TERM".to_owned(), "xterm-256color".to_owned()),
            ],
            configs: vec![
                ConfigEntry {
                    display_path: "~/.zshrc".to_owned(),
                    status: ConfigStatus::Readable,
                },
                ConfigEntry {
                    display_path: "~/.zshenv".to_owned(),
                    status: ConfigStatus::Missing,
                },
            ],
            config_source: Some(ConfigSource::Parent("bash".to_owned())),

            ancestor_chain: vec![],
        };

        let output = render_report(&report);

        for line in output.lines() {
            assert!(!line.contains("├── └──"), "malformed prefix found: {line}");
            assert!(!line.contains("├── │"), "malformed prefix found: {line}");
            assert!(!line.contains("└── ├──"), "malformed prefix found: {line}");
            assert!(!line.contains("└── │"), "malformed prefix found: {line}");
        }
    }

    #[test]
    fn no_malformed_tree_prefixes_no_configs() {
        let report = ShellReport {
            parent: None,
            login_shell: Some("/bin/bash".to_owned()),
            terminal: Some("dumb".to_owned()),
            env_vars: vec![
                ("SHELL".to_owned(), "/bin/bash".to_owned()),
                ("TERM".to_owned(), "dumb".to_owned()),
            ],
            configs: vec![],
            config_source: None,
            ancestor_chain: vec![],
        };

        let output = render_report(&report);

        for line in output.lines() {
            assert!(!line.contains("├── └──"), "malformed prefix found: {line}");
            assert!(!line.contains("├── │"), "malformed prefix found: {line}");
        }
    }

    #[test]
    fn terminal_section_formatting_with_configs() {
        let report = ShellReport {
            parent: None,
            login_shell: None,
            terminal: Some("xterm-direct".to_owned()),
            env_vars: vec![],
            configs: vec![ConfigEntry {
                display_path: "~/.profile".to_owned(),
                status: ConfigStatus::Missing,
            }],
            config_source: None,

            ancestor_chain: vec![],
        };

        let output = render_report(&report);
        let lines: Vec<&str> = output.lines().collect();

        let term_header = *lines.iter().find(|l| l.contains("terminal")).unwrap();
        let term_child = *lines
            .iter()
            .find(|l| l.contains("TERM=xterm-direct"))
            .unwrap();

        assert_eq!(term_header, "├── terminal");
        assert_eq!(term_child, "│   └── TERM=xterm-direct");
    }

    #[test]
    fn terminal_section_formatting_without_configs() {
        let report = ShellReport {
            parent: None,
            login_shell: None,
            terminal: Some("xterm-direct".to_owned()),
            env_vars: vec![],
            configs: vec![],
            config_source: None,
            ancestor_chain: vec![],
        };

        let output = render_report(&report);
        let lines: Vec<&str> = output.lines().collect();

        let term_header = *lines.iter().find(|l| l.contains("terminal")).unwrap();
        let term_child = *lines
            .iter()
            .find(|l| l.contains("TERM=xterm-direct"))
            .unwrap();

        assert_eq!(term_header, "└── terminal");
        assert_eq!(term_child, "    └── TERM=xterm-direct");
    }

    #[test]
    fn environment_section_formatting_with_configs() {
        let report = ShellReport {
            parent: None,
            login_shell: None,
            terminal: None,
            env_vars: vec![
                ("HISTFILE".to_owned(), "/home/u/.zsh_history".to_owned()),
                ("SHELL".to_owned(), "/bin/zsh".to_owned()),
                ("TERM".to_owned(), "xterm-256color".to_owned()),
            ],
            configs: vec![ConfigEntry {
                display_path: "~/.zshrc".to_owned(),
                status: ConfigStatus::Readable,
            }],
            config_source: None,

            ancestor_chain: vec![],
        };

        let output = render_report(&report);
        let lines: Vec<&str> = output.lines().collect();

        let env_header = *lines.iter().find(|l| l.contains("environment")).unwrap();
        assert_eq!(env_header, "├── environment");

        assert!(lines.contains(&"│   ├── HISTFILE=/home/u/.zsh_history"));
        assert!(lines.contains(&"│   ├── SHELL=/bin/zsh"));
        assert!(lines.contains(&"│   └── TERM=xterm-256color"));
    }

    #[test]
    fn environment_section_formatting_without_configs() {
        let report = ShellReport {
            parent: None,
            login_shell: None,
            terminal: None,
            env_vars: vec![("SHELL".to_owned(), "/bin/bash".to_owned())],
            configs: vec![],
            config_source: None,
            ancestor_chain: vec![],
        };

        let output = render_report(&report);
        let lines: Vec<&str> = output.lines().collect();

        let env_header = *lines.iter().find(|l| l.contains("environment")).unwrap();
        assert_eq!(env_header, "└── environment");

        assert!(lines.contains(&"    └── SHELL=/bin/bash"));
    }

    #[test]
    fn config_label_parent_source() {
        let report = ShellReport {
            parent: None,
            login_shell: None,
            terminal: None,
            env_vars: vec![],
            configs: vec![ConfigEntry {
                display_path: "~/.bashrc".to_owned(),
                status: ConfigStatus::Readable,
            }],
            config_source: Some(ConfigSource::Parent("bash".to_owned())),

            ancestor_chain: vec![],
        };

        let output = render_report(&report);
        assert!(output.contains("└── configs (bash, via parent process)"));
        assert!(!output.contains("via $SHELL"));
    }

    #[test]
    fn config_label_login_source() {
        let report = ShellReport {
            parent: None,
            login_shell: None,
            terminal: None,
            env_vars: vec![],
            configs: vec![ConfigEntry {
                display_path: "~/.zshrc".to_owned(),
                status: ConfigStatus::Readable,
            }],
            config_source: Some(ConfigSource::Login("zsh".to_owned())),

            ancestor_chain: vec![],
        };

        let output = render_report(&report);
        assert!(output.contains("└── configs (zsh, via $SHELL)"));
        assert!(!output.contains("via parent process"));
    }

    #[test]
    fn config_label_no_source() {
        let report = ShellReport {
            parent: None,
            login_shell: None,
            terminal: None,
            env_vars: vec![],
            configs: vec![ConfigEntry {
                display_path: "HOME is not set; cannot resolve config paths".to_owned(),
                status: ConfigStatus::Missing,
            }],
            config_source: None,

            ancestor_chain: vec![],
        };

        let output = render_report(&report);
        assert!(output.contains("└── configs"));
        assert!(!output.contains("via parent process"));
        assert!(!output.contains("via $SHELL"));
    }

    #[test]
    fn full_tree_output_exact_shape() {
        let report = ShellReport {
            parent: Some(ParentProcess {
                name: "bash".to_owned(),
                pid: 1700,
            }),
            login_shell: Some("/bin/zsh".to_owned()),
            terminal: Some("xterm-256color".to_owned()),
            env_vars: vec![
                ("HISTFILE".to_owned(), "/home/u/.zsh_history".to_owned()),
                ("SHELL".to_owned(), "/bin/zsh".to_owned()),
                ("TERM".to_owned(), "xterm-256color".to_owned()),
            ],
            configs: vec![ConfigEntry {
                display_path: "~/.zshrc".to_owned(),
                status: ConfigStatus::Readable,
            }],
            config_source: Some(ConfigSource::Parent("bash".to_owned())),

            ancestor_chain: vec![],
        };

        let output = render_report(&report);
        let expected = [
            "shell",
            "",
            "├── invocation",
            "│   ├── parent: bash pid=1700",
            "│   └── login: /bin/zsh",
            "├── terminal",
            "│   └── TERM=xterm-256color",
            "├── environment",
            "│   ├── HISTFILE=/home/u/.zsh_history",
            "│   ├── SHELL=/bin/zsh",
            "│   └── TERM=xterm-256color",
            "└── configs (bash, via parent process)",
            "    └── ~/.zshrc readable",
        ];
        assert_eq!(output, expected.join("\n"));
    }
}
