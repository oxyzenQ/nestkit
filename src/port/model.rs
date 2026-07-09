// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use std::path::PathBuf;

pub(crate) type OwnerMap = std::collections::HashMap<u64, Vec<ProcessInfo>>;
pub(crate) type ProcScan = (Vec<SocketEntry>, OwnerMap, ScanStats);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub fn label(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketEntry {
    pub protocol: Protocol,
    pub address: String,
    pub port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub state: Option<String>,
    pub inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub user: String,
    pub cwd: Option<PathBuf>,
    pub cmdline: Option<String>,
    pub fd: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SocketGroup {
    pub(crate) socket: SocketEntry,
    pub(crate) owners: Vec<ProcessInfo>,
    pub(crate) count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GroupKey {
    pub(crate) protocol: Protocol,
    pub(crate) address: String,
    pub(crate) port: u16,
    pub(crate) state: Option<String>,
    pub(crate) owners: Vec<OwnerIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OwnerIdentity {
    pub(crate) pid: u32,
    pub(crate) name: String,
    pub(crate) user: String,
}

impl From<&ProcessInfo> for OwnerIdentity {
    fn from(process: &ProcessInfo) -> Self {
        Self {
            pid: process.pid,
            name: process.name.clone(),
            user: process.user.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortOptions {
    pub port: Option<u16>,
    pub tcp: bool,
    pub udp: bool,
    pub listen: bool,
    pub all: bool,
    pub numeric: bool,
    pub group: bool,
    pub no_pid: bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PortFlags {
    pub tcp: bool,
    pub udp: bool,
    pub listen: bool,
    pub all: bool,
    pub numeric: bool,
    pub group: bool,
    pub no_pid: bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ScanStats {
    pub unreadable_processes: usize,
    pub unreadable_fds: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortError(pub(crate) String);

impl std::fmt::Display for PortError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for PortError {}
