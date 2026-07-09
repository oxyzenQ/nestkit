// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Path security guard for zejtron's own state I/O.
//!
//! ## Scope
//!
//! Zejtron is a Linux introspection tool — by design it reads arbitrary
//! user-specified paths (`zejtron why /etc/shadow`, `zejtron touch ~/.ssh/id_rsa`).
//! Those read-only investigation commands are NOT gated here.
//!
//! This module only protects zejtron's own STATE I/O — currently just the
//! `env save/list/diff/delete` snapshot directory at
//! `$XDG_DATA_HOME/zejtron/env/` (or `~/.local/share/zejtron/env/`).
//!
//! ## Threat model
//!
//! Without this guard, a malicious or careless environment could redirect
//! zejtron's state writes via `XDG_DATA_HOME=/etc` or `XDG_DATA_HOME=~/.ssh`,
//! causing env snapshots to be written into protected directories. While the
//! snapshot contents are plain `KEY=VALUE` user environment strings (not
//! credentials), writing them into system or credential directories violates
//! the principle of least privilege and could mask other attacks.
//!
//! ## Policy
//!
//! The zejtron state directory must resolve to either:
//!   - `$XDG_DATA_HOME/zejtron/` (when XDG_DATA_HOME is set, non-empty, AND
//!     not a system/credential path), OR
//!   - `~/.local/share/zejtron/` (default)
//!
//! Any other location — including system paths (`/etc`, `/usr`, `/var`, etc.)
//! and user credential paths (`~/.ssh`, `~/.gnupg`) — is rejected with a
//! clear error message.

use std::path::{Component, Path, PathBuf};

/// Lexically normalize a path: collapse `.` and `..` components without
/// requiring the file to exist on disk. Does NOT follow symlinks.
fn lexical_normalize(path: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => match out.components().next_back() {
                Some(Component::Normal(_)) => {
                    let _ = out.pop();
                }
                Some(Component::RootDir) | None => {}
                _ => {
                    let _ = out.pop();
                }
            },
            other => out.push(other.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Canonicalize a path for comparison. Tries `std::fs::canonicalize` first
/// (resolves symlinks, requires existence); falls back to lexical
/// normalization for paths that don't exist yet.
fn canonical_for_compare(path: &Path) -> PathBuf {
    if let Ok(c) = std::fs::canonicalize(path) {
        return c;
    }
    lexical_normalize(path).unwrap_or_else(|| path.to_path_buf())
}

/// Return true if the canonical path falls inside a known-dangerous prefix
/// that zejtron's state must NEVER touch — even if an XDG env var points
/// there.
fn is_dangerous(canonical: &Path) -> bool {
    let s = canonical.to_string_lossy();
    let home = std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).to_string_lossy().into_owned())
        .unwrap_or_default();

    // System paths — never valid for zejtron state, even if XDG env vars
    // point here. Zejtron is a user-space tool; its state must live under
    // the user's home or proper XDG dirs, NOT in /etc, /usr, /var, etc.
    let deny_prefixes: &[&str] = &[
        "/etc/", "/usr/", "/var/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/boot/", "/root/",
        "/proc/", "/sys/", "/dev/",
    ];

    for prefix in deny_prefixes {
        if s.starts_with(prefix) {
            return true;
        }
    }

    // User credential stores — never valid for zejtron state
    let user_deny_subdirs: &[&str] = &[".ssh/", ".gnupg/", ".kwallet/", ".local/share/keyrings/"];
    if !home.is_empty() {
        for sub in user_deny_subdirs {
            let full = format!("{home}/{sub}");
            if s.starts_with(&full) {
                return true;
            }
        }
    }

    false
}

/// Resolve the zejtron state directory (`$XDG_DATA_HOME/zejtron` or
/// `~/.local/share/zejtron`), rejecting dangerous XDG overrides.
///
/// Returns the canonicalized, validated directory path, or an error message
/// explaining why the resolved location is unsafe.
pub fn resolve_state_dir() -> Result<PathBuf, String> {
    let candidate: PathBuf =
        if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
            PathBuf::from(&xdg).join("zejtron")
        } else {
            let home = std::env::var_os("HOME")
                .filter(|v| !v.is_empty())
                .ok_or_else(|| "HOME is required when XDG_DATA_HOME is not set".to_string())?;
            PathBuf::from(home).join(".local/share/zejtron")
        };

    let canonical = canonical_for_compare(&candidate);
    if is_dangerous(&canonical) {
        return Err(format!(
            "zejtron state directory resolves to a protected path (blocked by pathguard): {}",
            canonical.display()
        ));
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialize env-mutating tests so they don't interfere with each other or
    /// with other tests that read HOME / XDG_DATA_HOME. cargo test runs tests
    /// in parallel by default; without this lock, mutating env vars from one
    /// test would corrupt another test's view of the environment.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Helper: set HOME and optionally XDG_DATA_HOME for the test, restore on drop.
    fn with_test_env<F: FnOnce()>(home: &str, xdg_data: Option<&str>, f: F) {
        let _guard = ENV_LOCK.lock().unwrap();
        let old_home = std::env::var_os("HOME");
        let old_xdg = std::env::var_os("XDG_DATA_HOME");

        // SAFETY: env mutation is serialized by ENV_LOCK; restored before return.
        unsafe {
            std::env::set_var("HOME", home);
            match xdg_data {
                Some(v) => std::env::set_var("XDG_DATA_HOME", v),
                None => std::env::remove_var("XDG_DATA_HOME"),
            }
        }

        f();

        // SAFETY: same locked context, restoring prior values.
        unsafe {
            match old_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
            match old_xdg {
                Some(v) => std::env::set_var("XDG_DATA_HOME", v),
                None => std::env::remove_var("XDG_DATA_HOME"),
            }
        }
    }

    #[test]
    fn test_lexical_normalize_collapses_dots() {
        let p = Path::new("/home/user/.local/share/zejtron/../other");
        let n = lexical_normalize(p).unwrap();
        assert_eq!(n, PathBuf::from("/home/user/.local/share/other"));
    }

    #[test]
    fn test_default_state_dir_under_home() {
        with_test_env("/home/testuser", None, || {
            let dir = resolve_state_dir().unwrap();
            assert_eq!(dir, PathBuf::from("/home/testuser/.local/share/zejtron"));
        });
    }

    #[test]
    fn test_xdg_data_home_respected_when_safe() {
        with_test_env("/home/testuser", Some("/custom/xdg"), || {
            let dir = resolve_state_dir().unwrap();
            assert_eq!(dir, PathBuf::from("/custom/xdg/zejtron"));
        });
    }

    #[test]
    fn test_xdg_to_etc_is_blocked() {
        with_test_env("/home/testuser", Some("/etc"), || {
            let r = resolve_state_dir();
            assert!(r.is_err(), "XDG_DATA_HOME=/etc must be blocked");
            assert!(r.unwrap_err().contains("pathguard"));
        });
    }

    #[test]
    fn test_xdg_to_user_ssh_is_blocked() {
        with_test_env("/home/testuser", Some("/home/testuser/.ssh"), || {
            let r = resolve_state_dir();
            assert!(r.is_err(), "XDG_DATA_HOME=~/.ssh must be blocked");
        });
    }

    #[test]
    fn test_xdg_to_var_is_blocked() {
        with_test_env("/home/testuser", Some("/var/lib"), || {
            assert!(resolve_state_dir().is_err());
        });
    }

    #[test]
    fn test_xdg_to_proc_sys_dev_blocked() {
        with_test_env("/home/testuser", None, || {
            for p in [
                "/proc", "/sys", "/dev", "/boot", "/root", "/usr", "/bin", "/sbin", "/lib",
            ] {
                // SAFETY: single-threaded test, value restored by with_test_env.
                unsafe {
                    std::env::set_var("XDG_DATA_HOME", p);
                }
                assert!(
                    resolve_state_dir().is_err(),
                    "XDG_DATA_HOME={p} must be blocked"
                );
            }
        });
    }

    #[test]
    fn test_dangerous_paths_detected() {
        with_test_env("/home/testuser", None, || {
            assert!(is_dangerous(Path::new("/etc/passwd")));
            assert!(is_dangerous(Path::new("/etc/zejtron/env/x.env")));
            assert!(is_dangerous(Path::new("/usr/bin/bash")));
            assert!(is_dangerous(Path::new("/var/log/x")));
            assert!(is_dangerous(Path::new("/boot/vmlinuz")));
            assert!(is_dangerous(Path::new("/root/.bashrc")));
            assert!(is_dangerous(Path::new("/proc/self/status")));
            assert!(is_dangerous(Path::new("/sys/kernel")));
            assert!(is_dangerous(Path::new("/dev/null")));
            assert!(is_dangerous(Path::new("/home/testuser/.ssh/id_rsa")));
            assert!(is_dangerous(Path::new("/home/testuser/.gnupg/secring.gpg")));
            // Not dangerous — valid state location
            assert!(!is_dangerous(Path::new(
                "/home/testuser/.local/share/zejtron/env/x.env"
            )));
            assert!(!is_dangerous(Path::new("/custom/xdg/zejtron")));
        });
    }

    #[test]
    fn test_missing_home_without_xdg_errors() {
        let _guard = ENV_LOCK.lock().unwrap();
        let old_home = std::env::var_os("HOME");
        let old_xdg = std::env::var_os("XDG_DATA_HOME");
        // SAFETY: serialized by ENV_LOCK, restored below.
        unsafe {
            std::env::remove_var("HOME");
            std::env::remove_var("XDG_DATA_HOME");
        }

        let r = resolve_state_dir();
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("HOME is required"));

        // SAFETY: serialized by ENV_LOCK, restoring prior values.
        unsafe {
            match old_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
            match old_xdg {
                Some(v) => std::env::set_var("XDG_DATA_HOME", v),
                None => std::env::remove_var("XDG_DATA_HOME"),
            }
        }
    }
}
