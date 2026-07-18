// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! Single-line failure diagnostic for every Gitway binary.
//!
//! When a Gitway binary runs and fails in human (non-JSON) mode, one
//! [`emit`] / [`emit_for`] / [`emit_for_with_config_sources`] call writes
//! a logfmt-style record to stderr:
//!
//! ```text
//! gitway diag ts=2026-04-22T18:43:11Z pid=12345 code=4 reason=PERMISSION_DENIED config_source=~/.ssh/config,/etc/ssh/ssh_config argv=["gitway", "git@github.com", "git-upload-pack", "'org/repo.git'"]
//! ```
//!
//! The point is to turn silent `exit 128` failures — the opaque code git
//! reports when `core.sshCommand` fails — into a single grep-able line
//! that carries enough context to triage: ISO 8601 timestamp, PID, argv,
//! exit code, error reason, and (when relevant) the `ssh_config(5)`
//! file(s) that were consulted (NFR-24, M12.8).
//!
//! JSON mode already carries `timestamp` and `command` in its structured
//! `{"error": {...}}` blob, so callers should skip this helper on that
//! path.  Stdout is always left untouched (CLI Standard Rule 1) — the diagnostic
//! writes exclusively to stderr.

use std::path::PathBuf;

use crate::error::AnvilError;
use crate::time::now_iso8601;

/// Emits the single-line diagnostic record with an explicit exit code and
/// a reason string.  Use this from the shim binaries (`gitway-keygen`,
/// `gitway-add`) where the reason codes are selected from a local static
/// table; use [`emit_for`] when an [`AnvilError`] is already in hand.
pub fn emit(code: u32, reason: &str) {
    emit_inner(code, reason, &[]);
}

/// Emits the diagnostic record for an [`AnvilError`], reusing the error's
/// mapped exit code and string error class.
pub fn emit_for(err: &AnvilError) {
    emit_inner(err.exit_code(), err.error_code(), &[]);
}

/// Like [`emit_for`], plus a `config_source=` field listing the
/// `ssh_config(5)` files that were consulted during this invocation.
///
/// `config_sources` should be the deduplicated list of files the
/// resolver attempted to read (typically `~/.ssh/config` and, on Unix,
/// `/etc/ssh/ssh_config`).  An empty slice produces a line identical to
/// [`emit_for`] — no `config_source=` field is emitted.
///
/// This is the M12.8 entry point for NFR-24: callers that successfully
/// or unsuccessfully consulted `ssh_config` should pass that fact down
/// to the diagnostic so triage tooling can attribute behavior to the
/// right file.  The Gitway CLI does this around its top-level
/// [`emit_for`]-equivalent call site (`gitway-cli/src/main.rs`).
pub fn emit_for_with_config_sources(err: &AnvilError, config_sources: &[PathBuf]) {
    emit_inner(err.exit_code(), err.error_code(), config_sources);
}

fn emit_inner(code: u32, reason: &str, config_sources: &[PathBuf]) {
    let argv: Vec<String> = std::env::args().collect();
    let extra = if config_sources.is_empty() {
        String::new()
    } else {
        let joined: Vec<String> = config_sources
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        // Field name is logfmt-style `key=value` like the others.  The
        // value is a comma-separated list of paths; commas in paths are
        // exceedingly rare and not worth quoting for in this MVP.
        format!(" config_source={}", joined.join(","))
    };
    eprintln!(
        "gitway diag ts={ts} pid={pid} code={code} reason={reason}{extra} argv={argv:?}",
        ts = now_iso8601(),
        pid = std::process::id(),
    );
}
