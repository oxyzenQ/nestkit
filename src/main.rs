// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

mod cli;
mod doctor;
mod env;
mod git;
mod holds;
mod net;
mod path;
mod pathguard;
mod port;
mod proc;
mod process;
mod recent;
mod service;
mod shell;
mod touch;
mod update;
mod version;
mod why;

use clap::Parser;

fn main() {
    let cli = cli::Cli::parse();

    if cli.version {
        println!("{}", version::version_text(env!("ZEJTRON_GIT_HASH")));
        return;
    }

    if cli.check_update {
        if let Err(error) = update::check_update(env!("CARGO_PKG_VERSION")) {
            eprintln!("zejtron: update check failed: {error}");
            std::process::exit(1);
        }
        return;
    }

    let result = match cli.command {
        Some(cli::Commands::Path { command }) => path::run(&command),
        Some(cli::Commands::Recent { path, limit, since }) => {
            recent::run(&path, limit, since.as_deref())
        }
        Some(cli::Commands::Port {
            port,
            tcp,
            udp,
            listen,
            all,
            numeric,
            group,
            no_pid,
        }) => port::run(
            port.as_deref(),
            port::PortFlags {
                tcp,
                udp,
                listen,
                all,
                numeric,
                group,
                no_pid,
            },
        ),
        Some(cli::Commands::Proc {
            user_or_uid,
            me,
            live,
            watch,
            interval,
            depth,
            find,
            no_pid,
            no_color,
        }) => proc::run(
            user_or_uid.as_deref(),
            proc::ProcFlags {
                me,
                live,
                watch,
                interval,
                depth,
                find,
                no_pid,
                no_color,
            },
        ),
        Some(cli::Commands::Holds { target }) => holds::run(&target),
        Some(cli::Commands::Touch { path }) => touch::run(&path),
        Some(cli::Commands::Why { target }) => why::run(&target),
        Some(cli::Commands::Env {
            command,
            keys,
            filter,
            no_values,
            pid,
            mask_secrets,
        }) => env::run(
            command,
            keys || no_values,
            filter.as_deref(),
            pid,
            mask_secrets,
        ),
        Some(cli::Commands::Service {
            system,
            user,
            failed,
            all,
            filter,
        }) => service::run(service::ServiceFlags {
            system,
            user,
            failed,
            all,
            filter,
        }),
        Some(cli::Commands::Doctor) => doctor::run(env!("ZEJTRON_GIT_HASH")),
        Some(cli::Commands::Shell) => shell::run(),
        Some(cli::Commands::Net) => net::run(),
        Some(cli::Commands::Git) => git::run(),
        None => {
            let mut cmd = cli::Cli::command();
            cmd.print_help().map(|_| println!()).map_err(Into::into)
        }
    };

    if let Err(error) = result {
        eprintln!("zejtron: {error}");
        std::process::exit(1);
    }
}
