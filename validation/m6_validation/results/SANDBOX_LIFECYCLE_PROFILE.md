# M6 Dynamic Sandbox Lifecycle Profile (diagnostic only)

## Method
- External profiling only (no production code touched): the profiler mirrors
  `SandboxPolicy` exactly and times `create / start / wait / logs / remove` with
  `time.perf_counter()` + container timestamps + the sandbox self-reported
  `duration_ms` from its JSON payload.
- Samples: A_simple (`#!/bin/sh` echo), B_child (`sh -c`), C_longcmd (long argv).
- N=3 per stage; monotonic timing; containers force-removed after each run.

## Results (current environment, same session)
| Stage | A_simple | B_child | C_longcmd |
|---|---|---|---|
| create | 6.24 s | 6.23 s | 6.25 s |
| start | 4.78 s | 4.62 s | 4.65 s |
| wait (exec) | 0.008 s | 0.013 s | 0.016 s |
| logs | 0.01 s | 0.01 s | 0.01 s |
| remove | 3.31 s | 3.26 s | 3.29 s |
| in-container self duration | 20 ms | 76 ms | 38 ms |
| TOTAL | ~14.4 s | ~14.2 s | ~14.2 s |

- Same session, daemon freshly used: TOTAL ~2.9 s/container (create 0.41 / start
  0.26 / wait 0.99 / remove 1.19) -> Docker Desktop API latency degrades 5-7x
  within minutes on this host.
- 3 concurrent dynamic scripts via the real API: sandbox payload
  duration_ms = 30 301 / 32 754 / 33 605 ms -> ~30 s per execution under
  concurrency (2x single-container lifecycle).
- strace overhead: ~0 s steady state (inner work 20-90 ms). First-run artifact
  of 0.98 s disappeared once start() absorbed the exec window.
- DB: create scan = 29.5 ms; full 3-commit cycle = 93 ms.
- Analyzer construction per scan (incl. YARA rule compile x5) = 3.1 ms.
- Fast benign file end-to-end on idle server = 0.33-0.87 s.
- Sequential POST latency = ~0.73 s (storage write + DB insert, variable).

## Bottleneck
A: Docker Desktop container lifecycle (create ~6 s + start ~4.6 s + remove ~3.3 s)
= ~14.4 s per container idle, ~30 s under worker concurrency. Inner execution +
strace + collection + normalization + DB together < 0.2 s (<1.5%).

## Security verification (unchanged)
network_disabled=true | read_only_rootfs=true | cap_drop=ALL |
no-new-privileges=true | user=10001:10001 | mem=256m | nano_cpus=0.5 |
pids=64 | exec timeout=30 s | max_output=1 MiB | max_events=2000 |
strace capture=256 bytes (working tree adds `-s 256`, bounded) | force-remove
cleanup in finally. No relaxation.

## Regression
- M5 unit: 8/8 PASS (working tree, uncommitted team changes present)
- M5 E2E: 14/14 PASS
- Orphan containers: 0 (sandbox-*, profile-*)

## Code changes (by this task)
None in production. Added only:
- validation/m6_validation/profile_sandbox.py
- validation/m6_validation/results/sandbox_profile.json
- this file.

Note: the working tree already contained uncommitted team modifications vs the
baseline commit 84e127e (processor.py no-idle-poll, worker_max_threads 2->4,
worker_poll_interval_s 1.0->0.1, strace -s 256, updated tests). This profile was
measured on that current tree; none of those changes were made by this task.

## Recommendation (NOT implemented)
1. The dominant cost is Docker Desktop/WSL2 container lifecycle (~14-30 s per
   container). Scoped options to evaluate later, preserving hardening:
   a. pre-warmed disposable container pool (same security params);
   b. batch multiple samples per container run;
   c. run the sandbox on a Linux host/runner where create+start is ~0.1-0.5 s;
   d. investigate the 5-7x API latency drift on this machine (WSL2 VM CPU/RAM
      allocation, antivirus exclusions on Docker data dirs).
2. Minor: sequential upload POST ~0.7 s (storage write + DB insert).
