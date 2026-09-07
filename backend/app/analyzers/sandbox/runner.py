"""Sandbox runner - disposable container lifecycle (M3).

Responsible for the full lifecycle:
    CREATE -> SECURE -> EXECUTE (traced) -> COLLECT -> DESTROY
Every execution gets a unique sandbox id; containers are never reused and are
always removed (disposable). The runner applies the centralized SandboxPolicy.

The host only talks to the runner (Python Docker SDK). The sample executes inside
the isolated container; the runner reads a single JSON summary line on stdout.
"""

import json
import logging
import time
import uuid
from dataclasses import dataclass, field

import docker
from docker.errors import DockerException
from docker.types import Mount

from app.analyzers.sandbox.policy import SandboxPolicy

logger = logging.getLogger(__name__)


class SandboxError(RuntimeError):
    pass


@dataclass
class SandboxResult:
    sandbox_id: str
    status: str            # completed / timeout / crashed / failed_to_start / resource_limit
    exit_code: int | None = None
    duration_ms: int = 0
    error: str | None = None
    events: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)


class SandboxRunner:
    def __init__(self, policy: SandboxPolicy | None = None) -> None:
        self.policy = policy or SandboxPolicy.from_settings()
        try:
            self.client = docker.from_env()
        except DockerException as exc:
            raise SandboxError(f"Docker unavailable: {exc}") from exc

    def analyze_file(self, sha256: str, display_name: str) -> SandboxResult:
        sandbox_id = f"sandbox-{uuid.uuid4().hex[:12]}"
        started = time.perf_counter()
        container = None
        try:
            container = self.client.containers.run(
                image=self.policy.image,
                command=[
                    self.policy.input_mount_container,
                    f"{sha256}.bin",
                    display_name or "sample.bin",
                ],
                name=sandbox_id,
                network_disabled=self.policy.network_disabled,
                mem_limit=self.policy.mem_limit,
                nano_cpus=self.policy.nano_cpus,
                pids_limit=self.policy.pids_limit,
                read_only=self.policy.read_only_rootfs,
                tmpfs=self.policy.tmpfs or None,
                cap_drop=list(self.policy.cap_drop) if self.policy.cap_drop else None,
                security_opt=list(self.policy.security_opt),
                user=self.policy.user,
                environment={
                    "SANDBOX_EXEC_TIMEOUT_S": str(self.policy.exec_timeout_s),
                    "SANDBOX_MAX_EVENTS": str(self.policy.max_events),
                    "SANDBOX_STRACE_STRING_SIZE": str(self.policy.strace_string_size),
                },
                mounts=[
                    Mount(
                        self.policy.input_mount_container,
                        self.policy.input_mount_host,
                        type="bind",
                        read_only=True,
                    )
                ],
                detach=True,
            )
            exit_info = container.wait(timeout=self.policy.timeout_s)
            raw = (
                container.logs(stdout=True, stderr=True)
                .decode(errors="replace")
                .strip()
            )
            if len(raw) > self.policy.max_output_bytes:
                raw = raw[-self.policy.max_output_bytes :]
            payload = _json_loads_last(raw)
        except DockerException as exc:
            raise SandboxError(f"Sandbox execution failed: {exc}") from exc
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                    logger.info("sandbox %s destroyed", sandbox_id)
                except DockerException:
                    pass

        result = SandboxResult(
            sandbox_id=sandbox_id,
            status=str(payload.get("status")) or "failed_to_start",
            exit_code=payload.get("exit_code"),
            duration_ms=int((time.perf_counter() - started) * 1000),
            error=payload.get("error"),
            events=payload.get("events") or [],
            summary=payload.get("summary") or {},
        )
        if not payload:
            result.status = "failed_to_start"
            result.error = f"no JSON payload from sandbox (raw: {raw[:300]})"
        return result


def _json_loads_last(raw: str) -> dict:
    if not raw:
        return {}
    for line in reversed(raw.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                return obj
        except ValueError:
            continue
    return {}
