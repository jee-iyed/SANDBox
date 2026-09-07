"""Centralized sandbox security policy (M3).

Single source of truth for the hardening contract applied to every disposable
sandbox container. Built entirely from `settings` (provisional, documented in
DECISIONS.md). The runner reads this policy and applies it via the Docker SDK.

Security model: process every analyzed file as hostile. No --privileged, no host
filesystem/network/PID namespace exposure, no Docker socket, no unnecessary
capabilities, non-root, read-only rootfs, isolated network, bounded resources.
"""

from dataclasses import dataclass, field
from typing import Optional

from app.core.config import settings


@dataclass(frozen=True)
class SandboxPolicy:
    image: str
    # Hardening
    read_only_rootfs: bool = True
    cap_drop: tuple[str, ...] = ("ALL",)
    security_opt: tuple[str, ...] = ("no-new-privileges:true",)
    user: str = "10001:10001"  # sandbox:sandbox (image-defined uid/gid)
    network_disabled: bool = True
    tmpfs: dict[str, str] = field(default_factory=dict)
    # Resources
    mem_limit: str = "256m"
    nano_cpus: int = 500_000_000
    pids_limit: int = 64
    # Timing
    timeout_s: int = 60     # container wait (whole execution window)
    exec_timeout_s: int = 30  # per-process traced execution timeout
    # M5 bounded monitoring (additive hardening on top of the M3 contract)
    max_events: int = 2000        # raw events cap inside the container
    max_output_bytes: int = 1_048_576  # container log read cap (host side)
    strace_string_size: int = 256  # bounded argv/string evidence capture
    # Runtime
    input_mount_host: str = ""
    input_mount_container: str = "/analysis/input"
    work_container: str = "/exec"  # writable EXECUTABLE tmpfs (sample runs here)
    entrypoint: Optional[list[str]] = None

    @classmethod
    def from_settings(cls) -> "SandboxPolicy":
        return cls(
            image=settings.sandbox_image,
            mem_limit=settings.sandbox_mem_limit,
            nano_cpus=settings.sandbox_nano_cpus,
            pids_limit=settings.sandbox_pids_limit,
            timeout_s=settings.sandbox_timeout_s,
            exec_timeout_s=settings.sandbox_exec_timeout_s,
            max_events=settings.dynamic_max_events,
            max_output_bytes=settings.dynamic_max_output_mb * 1024 * 1024,
            tmpfs={
                "/tmp": "size=64m,noexec,nodev,nosuid",
                "/exec": "size=64m,rw,nodev,nosuid",
            },
            input_mount_host=str(settings.uploads_dir),
        )
