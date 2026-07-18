# CLAUDE.md — Anvil

Anvil is a pure-Rust SSH stack for Git tooling: transport, keys, signing, agent.  Extracted from [Spacecraft-Software/Gitway](https://github.com/Spacecraft-Software/gitway) at commit `28abee6`.  Primary consumer is the Gitway CLI binaries (`gitway`, `gitway-keygen`, `gitway-add`).

See [AGENTS.md](AGENTS.md) for coding conventions, forbidden patterns, dependency policy, and the procedure for adding a new Git hosting provider — this file covers the architecture and build/test workflow only.

## Layout

```
src/
  session.rs           russh-backed transport (retry-wrapped connect)
  auth.rs              key discovery (CLI → ~/.ssh → agent) + agent-auth
  hostkey.rs           pinned fingerprints (GitHub / GitLab / Codeberg)
  cert_authority.rs    @cert-authority / @revoked parser + HashedHost
  relay.rs             bidirectional stdin/stdout/stderr relay
  config.rs            AnvilConfig builder; per-provider constructors
  error.rs             unified error + the canonical exit-code map
  algorithms.rs        KEX/cipher/MAC catalogue + OpenSSH +/-/^/replace + denylist
  retry.rs             RetryPolicy + transient/fatal classifier + jittered backoff
  keygen.rs            Ed25519/ECDSA/RSA keygen in OpenSSH format
  sshsig.rs            SSHSIG sign/verify/check-novalidate/find-principals
  allowed_signers.rs   git allowed_signers parser
  log.rs               tracing-category constants + install_log_bridge()
  diagnostic.rs        single-line stderr failure diagnostic helper
  time.rs              ISO 8601 timestamp helpers (no chrono/time dep)
  agent/
    askpass.rs         $SSH_ASKPASS-driven interactive confirm
    client.rs          blocking SSH-agent client
    daemon.rs          async SSH-agent server (Session trait impl)
  proxy/
    command.rs         ProxyCommand spawn + stdio plumbing
    jump.rs            ProxyJump chains (up to 8 hops, per-hop host-key verify)
    stdio.rs           stdio<->channel adapter
    tokens.rs          %h %p %r %n %% token expansion
  ssh_config/
    lexer.rs           ssh_config(5) tokenizer
    parser.rs          directive parser
    matcher.rs         Host / Match block resolution
    resolver.rs        merged effective config per host
    include.rs         Include directive expansion
tests/
  test_connection.rs       gated real-network tests
  test_clone.rs            end-to-end git clone (network-gated)
  test_proxy_jump.rs       ProxyJump chain integration
  test_hashed_hosts.rs     OpenSSH HashKnownHosts (HMAC-SHA1) fixtures
  test_hostkey_writes.rs   known_hosts write paths
  test_known_hosts_cert.rs @cert-authority / @revoked semantics
  ssh_config_acceptance.rs YAML-driven ssh_config parser matrix
  ssh_config_matrix/       acceptance fixtures
benches/
  throughput.rs            criterion transport throughput
  ssh_config_latency.rs    ssh_config parse/resolve latency
  proxy_chain.rs           ProxyJump chain setup overhead
```

## Build and test

**MSRV:** Rust 1.88.

```sh
cargo build --release
cargo test
cargo test --test test_clone                            # single integration test file
cargo test sshsig::tests::verify_roundtrip              # single unit test by path
GITWAY_INTEGRATION_TESTS=1 cargo test -- --ignored      # gated network tests
cargo bench                                             # criterion benches
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

`perl` is required by `aws-lc-rs` (assembly pre-processing) on every platform; `nasm` is also required on Windows MSVC.  On Linux, `musl-tools` is needed for the static target used in CI release builds.

`nix` is a Unix-only dependency (`cfg(unix)` in Cargo.toml) used by the agent daemon for `setsid(2)`, signal handling, and socket-permission tightening.  When cross-checking against Windows (`cargo check --target x86_64-pc-windows-msvc`), expect the agent daemon's Unix paths to compile out, not fail.

## Key invariants

- **`#![forbid(unsafe_code)]`** — no unsafe in project-owned code.
- **Pinned host keys** — SHA-256 fingerprints for GitHub, GitLab, and Codeberg are embedded in `src/hostkey.rs`.  Update them by fetching the official fingerprint pages and running `cargo test` to verify.
- **stdout stays clean** — diagnostic output goes to stderr.  The library deliberately exposes no stdout-touching APIs; output framing is the consumer's concern.
- **Passphrase zeroization** — any `String` holding a passphrase must be wrapped in `Zeroizing<String>`.
- **Exit codes (when consumed via Gitway's CLI-Standard error mapping):**
  - `0` — success
  - `1` — general / unexpected error
  - `2` — usage error (bad arguments, invalid configuration)
  - `3` — not found (no key, unknown host)
  - `4` — permission denied (auth failed, host key mismatch)

## SSH fingerprint rotation procedure

When a hosting provider rotates its host key:

1. Fetch the new fingerprint from the provider's official documentation page.
2. Update the constant in `src/hostkey.rs`.
3. Run `cargo test` to ensure the embedded tests still pass.
4. Open a PR; the CI pipeline validates all targets.  Downstream consumers (Gitway, etc.) bump their `anvil-ssh` pin on next release.

Provider fingerprint pages:

- GitHub: <https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints>
- GitLab: <https://docs.gitlab.com/ee/user/gitlab_com/#ssh-host-keys-fingerprints>
- Codeberg: <https://codeberg.org/Codeberg/Community/issues/1192>

## Security invariants

- `SSH_ASKPASS` must be an absolute path (enforced in `agent::askpass::try_askpass`).
- World-writable `SSH_ASKPASS` programs are rejected on Unix.
- `from_utf8_lossy` is forbidden on passphrase data; use `from_utf8` and reject non-UTF-8 output.
- The raw stdout buffer from `SSH_ASKPASS` is zeroized on every exit path (success, error, and early return).

## Crypto backend

`russh` is configured with `default-features = false` and the feature set `["aws-lc-rs", "flate2", "rsa"]` (see Cargo.toml).  Do not switch the russh backend to `ring` — `aws-lc-rs` provides post-quantum algorithm support that `ring` lacks, and avoids CMake on non-FIPS builds.  On Windows, `nasm` is required for the build (handled in CI).

The `ssh-key` RustCrypto stack (`ed25519-dalek` 2.x, `rsa` 0.9, `p256`/`p384`/`p521`) is used only for keygen and SSHSIG blob formatting.  `PrivateKey` values never cross the boundary between the two stacks.

## Type rename roadmap

Current: **v1.0.x** (`Cargo.toml`).  The `Gitway*` aliases are *deliberately* retained through the entire 1.x line — see [AGENTS.md](AGENTS.md) §"Type rename roadmap" for the canonical timeline and the reason the original 1.0-removal plan was softened (`gitway-lib` shim compatibility).  Removal is planned for **v2.0.0**.

## Related

- [Spacecraft-Software/Gitway](https://github.com/Spacecraft-Software/gitway) — primary consumer.
- [Gitway PRD v1.0](https://github.com/Spacecraft-Software/gitway/blob/main/Gitway-PRD-v1.0.md) — full v1.0 scope and roadmap.
