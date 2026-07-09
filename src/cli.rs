// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use clap::{CommandFactory, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "zejtron",
    about = "Unified Linux introspection toolkit for paths, ports, processes, files, services, and diagnostics",
    disable_version_flag = true
)]
pub struct Cli {
    #[arg(
        short = 'V',
        long = "version",
        global = true,
        help = "Print version information"
    )]
    pub version: bool,

    #[arg(
        long = "check-update",
        alias = "check-updated",
        global = true,
        help = "Check the latest upstream release"
    )]
    pub check_update: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    #[command(about = "Trace where a command comes from")]
    Path {
        #[arg(value_name = "COMMAND", help = "Command name to find in PATH")]
        command: String,
    },
    #[command(about = "Show recently modified files")]
    Recent {
        #[arg(value_name = "PATH", default_value = ".")]
        path: PathBuf,
        #[arg(
            long,
            value_name = "N",
            default_value_t = 20,
            help = "Maximum files to show"
        )]
        limit: usize,
        #[arg(
            long,
            value_name = "DURATION",
            help = "Only show files modified since this duration"
        )]
        since: Option<String>,
    },
    #[command(about = "Show listening ports and process owners")]
    Port {
        #[arg(value_name = "PORT", help = "Port number to inspect")]
        port: Option<String>,
        #[arg(long, help = "Show TCP sockets")]
        tcp: bool,
        #[arg(long, help = "Show UDP sockets")]
        udp: bool,
        #[arg(long, conflicts_with = "all", help = "Show listening or bound sockets")]
        listen: bool,
        #[arg(long, help = "Show all parsed sockets")]
        all: bool,
        #[arg(long, help = "Use numeric addresses and ports")]
        numeric: bool,
        #[arg(long, help = "Group repeated rendered socket rows")]
        group: bool,
        #[arg(long, help = "Hide process IDs in owner lines")]
        no_pid: bool,
    },
    #[command(about = "Inspect process trees by user or UID")]
    Proc {
        #[arg(
            value_name = "USER_OR_UID",
            help = "Username or numeric UID to inspect"
        )]
        user_or_uid: Option<String>,
        #[arg(
            long,
            conflicts_with = "user_or_uid",
            help = "Show processes owned by the current user"
        )]
        me: bool,
        #[arg(long, help = "Continuously refresh the process tree")]
        live: bool,
        #[arg(long, help = "Alias for --live")]
        watch: bool,
        #[arg(
            long,
            value_name = "SECONDS",
            help = "Live refresh interval in seconds"
        )]
        interval: Option<u64>,
        #[arg(
            long,
            allow_hyphen_values = true,
            value_name = "N",
            help = "Limit rendered tree depth"
        )]
        depth: Option<usize>,
        #[arg(
            long,
            value_name = "PATTERN",
            help = "Show process families matching a case-insensitive name substring"
        )]
        find: Option<String>,
        #[arg(long, help = "Hide pid=<PID> labels")]
        no_pid: bool,
        #[arg(long, help = "Disable ANSI color output")]
        no_color: bool,
    },
    #[command(about = "Show processes holding a file, device, or port")]
    Holds {
        #[arg(
            value_name = "TARGET",
            help = "Filesystem path or port number to inspect"
        )]
        target: String,
    },
    #[command(about = "Inspect last modification evidence for a path (read-only)")]
    Touch {
        #[arg(value_name = "PATH", help = "Path to inspect without modifying it")]
        path: PathBuf,
    },
    #[command(about = "Explain visible evidence for a path or port (read-only)")]
    Why {
        #[arg(
            value_name = "TARGET",
            help = "Filesystem path or port number to explain"
        )]
        target: String,
    },
    #[command(about = "Inspect and compare environment variables")]
    Env {
        #[command(subcommand)]
        command: Option<EnvCommands>,
        #[arg(long, help = "Show variable names only")]
        keys: bool,
        #[arg(long, value_name = "TEXT", help = "Filter variables by key substring")]
        filter: Option<String>,
        #[arg(long, help = "Alias for --keys")]
        no_values: bool,
        #[arg(
            long,
            value_name = "PID",
            help = "Read environment from /proc/<PID>/environ instead of this process"
        )]
        pid: Option<u32>,
        #[arg(
            long,
            help = "Mask common secret patterns (AWS, GitHub, JWT, private keys)"
        )]
        mask_secrets: bool,
    },
    #[command(about = "Inspect systemd services (read-only)")]
    Service {
        #[arg(long, conflicts_with = "user", help = "Inspect system services")]
        system: bool,
        #[arg(long, help = "Inspect user services")]
        user: bool,
        #[arg(long, help = "Show failed services only")]
        failed: bool,
        #[arg(long, help = "Show all service units")]
        all: bool,
        #[arg(long, value_name = "TEXT", help = "Filter services by unit name")]
        filter: Option<String>,
    },
    #[command(about = "Check Zejtron system capability/readiness")]
    Doctor,
    #[command(about = "Inspect current shell context (read-only)")]
    Shell,
    #[command(about = "Inspect network interfaces and routing context (read-only)")]
    Net,
    #[command(about = "Inspect git repository context (read-only)")]
    Git,
}

#[derive(Debug, Subcommand)]
pub enum EnvCommands {
    #[command(about = "Save current environment snapshot")]
    Save {
        #[arg(value_name = "NAME")]
        name: String,
    },
    #[command(about = "List saved environment snapshots")]
    List,
    #[command(about = "Delete saved environment snapshot")]
    Delete {
        #[arg(value_name = "NAME")]
        name: String,
    },
    #[command(about = "Compare saved environment snapshot with current environment")]
    Diff {
        #[arg(value_name = "NAME")]
        name: String,
        #[arg(long, help = "Show unchanged variables")]
        show_same: bool,
    },
}

impl Cli {
    pub fn command() -> clap::Command {
        <Self as CommandFactory>::command()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_shell() {
        let cli = Cli::try_parse_from(["zejtron", "shell"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Shell)));
    }

    #[test]
    fn parses_net() {
        let cli = Cli::try_parse_from(["zejtron", "net"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Net)));
    }

    #[test]
    fn parses_git() {
        let cli = Cli::try_parse_from(["zejtron", "git"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Git)));
    }

    #[test]
    fn parses_proc_me() {
        let cli = Cli::try_parse_from(["zejtron", "proc", "--me"]).unwrap();

        match cli.command {
            Some(Commands::Proc {
                me, user_or_uid, ..
            }) => {
                assert!(me);
                assert_eq!(user_or_uid, None);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_holds_target() {
        let cli = Cli::try_parse_from(["zejtron", "holds", "/tmp/file with spaces"]).unwrap();

        match cli.command {
            Some(Commands::Holds { target }) => {
                assert_eq!(target, "/tmp/file with spaces");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_doctor() {
        let cli = Cli::try_parse_from(["zejtron", "doctor"]).unwrap();

        assert!(matches!(cli.command, Some(Commands::Doctor)));
    }

    #[test]
    fn parses_touch_path() {
        let cli = Cli::try_parse_from(["zejtron", "touch", "/tmp/file with spaces"]).unwrap();

        match cli.command {
            Some(Commands::Touch { path }) => {
                assert_eq!(path, PathBuf::from("/tmp/file with spaces"));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_why_target() {
        let cli = Cli::try_parse_from(["zejtron", "why", "/tmp/file with spaces"]).unwrap();

        match cli.command {
            Some(Commands::Why { target }) => {
                assert_eq!(target, "/tmp/file with spaces");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_proc_watch_alias_and_interval() {
        let cli =
            Cli::try_parse_from(["zejtron", "proc", "--me", "--watch", "--interval", "3"]).unwrap();

        match cli.command {
            Some(Commands::Proc {
                watch, interval, ..
            }) => {
                assert!(watch);
                assert_eq!(interval, Some(3));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_proc_filters_and_no_pid() {
        let cli = Cli::try_parse_from([
            "zejtron", "proc", "rezky", "--depth", "2", "--find", "python", "--no-pid",
        ])
        .unwrap();

        match cli.command {
            Some(Commands::Proc {
                user_or_uid,
                depth,
                find,
                no_pid,
                ..
            }) => {
                assert_eq!(user_or_uid.as_deref(), Some("rezky"));
                assert_eq!(depth, Some(2));
                assert_eq!(find.as_deref(), Some("python"));
                assert!(no_pid);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }
}
