// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

/// Dynamic build target label: detects arch + libc env at compile time.
/// Returns e.g. "linux-amd64-gnu" (glibc, dynamic) or "linux-amd64-musl"
/// (static) for x86_64 Linux builds.
fn build_label() -> &'static str {
    if cfg!(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "musl"
    )) {
        "linux-amd64-musl"
    } else if cfg!(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu"
    )) {
        "linux-amd64-gnu"
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "linux-amd64"
    } else if cfg!(all(
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "musl"
    )) {
        "linux-aarch64-musl"
    } else if cfg!(all(
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "gnu"
    )) {
        "linux-aarch64-gnu"
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        "linux-aarch64"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "unknown"
    }
}

pub fn version_text(hash: &str) -> String {
    let hash = if hash.trim().is_empty() {
        "unknown"
    } else {
        hash.trim()
    };
    let target = build_label();

    format!(
        "Version: v{}\n\
         Build: {target} ({hash})\n\
         Copyright: (c) 2026 rezky_nightky (oxyzenQ)\n\
         License: GPL-3.0-only\n\
         Source: https://github.com/oxyzenQ/zejtron",
        env!("CARGO_PKG_VERSION")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_version_with_hash() {
        assert_eq!(
            version_text("abc123"),
            format!(
                "Version: v{}\nBuild: {} (abc123)\nCopyright: (c) 2026 rezky_nightky (oxyzenQ)\nLicense: GPL-3.0-only\nSource: https://github.com/oxyzenQ/zejtron",
                env!("CARGO_PKG_VERSION"),
                build_label()
            )
        );
    }

    #[test]
    fn has_five_lines() {
        assert_eq!(version_text("abc123").lines().count(), 5);
    }

    #[test]
    fn falls_back_to_unknown_for_empty_hash() {
        assert_eq!(
            version_text("  "),
            format!(
                "Version: v{}\nBuild: {} (unknown)\nCopyright: (c) 2026 rezky_nightky (oxyzenQ)\nLicense: GPL-3.0-only\nSource: https://github.com/oxyzenQ/zejtron",
                env!("CARGO_PKG_VERSION"),
                build_label()
            )
        );
    }

    #[test]
    fn build_label_detects_libc_variant() {
        let label = build_label();
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            assert!(
                label.ends_with("-gnu") || label.ends_with("-musl"),
                "build_label must include libc variant (-gnu/-musl), got: {label}"
            );
        }
    }
}
