# Deployment on the Sigelith server (phase 0)

The prover runs as a systemd service **outside Docker and outside the website's compose
stack**: no network, no privileges, at most one CPU core and only CPU time nobody else wants.
A second, small process (`hourglass_sync.py`, every minute) feeds it seed inputs and stamps
finished records through the public Sigelith API.

| file | role |
| --- | --- |
| `install.sh` | `check`, `install`, `start N`, `upgrade`, `status`, `move-data` — see the script header |
| `hourglass-p0.service` | the prover (`hourglass run`): restart always, `CPUQuota=100%`, `CPUWeight=idle` (with cgroup v2, `Nice` alone does not yield to other groups), `PrivateNetwork=yes`, full hardening (`systemd-analyze security`: 0.8 SAFE) |
| `hourglass_sync.py` | writes `inputs.txt` — the Bitcoin block at depth 3 on which two sources agree, the latest Sigelith checkpoint, and the clock offset to PTB from `chronyc` when chrony follows a PTB server — and stamps `genesis.json` and `segments/<j>.json`, keeping the receipts next to them |
| `hourglass-sync.service`, `.timer` | runs the sync every 60 s (`systemd-analyze security`: 1.5 OK) |
| `dist/hourglass`, `dist/hourglass.sha256` | static Linux build (musl) — built locally, not in git |

On the server: program in `/usr/local/bin/hourglass` and `/usr/local/lib/hourglass/`, data in
`/srv/docker_data/beattime/hourglass` (system user `hourglass`), next to the other persistent
data of the project and inside its nightly backup. The script never deletes data.

## Linux build (Rust 1.87+)

The linker settings live in `prover/.cargo/config.toml`, and cargo reads them from the current
directory — build from `prover/`:

    cd prover
    cargo build --release --target x86_64-unknown-linux-musl
    cp target/x86_64-unknown-linux-musl/release/hourglass ../deploy/dist/hourglass
    cd ../deploy/dist && sha256sum hourglass > hourglass.sha256

`install.sh` refuses a binary whose SHA-256 does not match, e.g. after a transfer that changed
line endings.

## Order on the server (root)

1. `install.sh check` — checksum, self-test, NIST CAVP for both SHA-256 implementations, speed
   and the estimated segment length for n = 30…36. Installs nothing.
2. `install.sh install` — user, files, units; starts only the input sync.
3. `install.sh start N` — **once**: genesis (a 20 s start-up benchmark), prover start, genesis
   stamp. A second run refuses: the clock never starts from zero.
4. `install.sh status` — services, state, latest segments, metrics, journal.

A new prover build: `install.sh upgrade` (stop, replace, start — the state stays and the current
segment records a `restart` gap). A build that changed the label computation cannot slip through
silently: the segment's own proof fails the self-check and the record is not published.

Stop without deleting data: `systemctl disable --now hourglass-p0.service hourglass-sync.timer`.

## Backups and restore

The evidence is `genesis.json` and the segment records and proofs in `segments/` — files are
only ever added, never changed.

**After a restore, do not start the prover from a backed-up state if the public log already
holds newer Hourglass stamps.** An old `state.txt` would recompute segments that are already
stamped, with a different seed — two different roots for the same segment are an incident.
Compare the last record in `segments/` with the last Hourglass stamp in the public log first;
the chain may only continue from the last published record. Until then `hourglass-p0` stays
disabled.

## Metrics (`metrics/metrics-<date>.csv`, every minute)

`utc, j, next_leaf, nodes_per_s, loadavg1, steal_permille, ptb_offset_us` — `steal_permille` is
CPU time the hypervisor took from the virtual machine (from `/proc/stat`, ‰ since the previous
row); `ptb_offset_us` as in the segment record (SPEC.md §8).

## Tested before deployment

In an AlmaLinux 10.2 container with systemd 257 (the server's versions), with a stand-in API
instead of sigelith.org: `check`, `install`, `start 20`; refusals (start before install, second
start, `install` while the prover runs); `kill -9` → resume after 30 s with a `restart` gap;
`upgrade`; stamps with the rate limit; a reboot and a hard kill of the whole system → both
services come back by themselves and resume; `move-data` (refusal without changes when the
target is not reachable, the move, sync into the new directory). Every resulting chain passed
the reference verifier.
