"""M3 Dynamic Analysis entrypoint - runs INSIDE the hardened sandbox container.

Container config constraints observed on Docker Desktop (documented in SECURITY):
  - Every tmpfs is forced noexec by Docker Desktop, so samples are NOT copied to
    a tmpfs for execution. Instead the sample is executed directly from the
    read-only bind mount /analysis/input, which is executable (9p/drvfs, noexec
    not applied). Reading is allowed; writing stays impossible (ro rootfs+input).

Lifecycle:
  1. resolve sample at <input_dir>/<sample_name> (ro bind mount)
  2. determine interpreter: run a binfmt shebang script via its interpreter and a
     plain executable via execve - always under `strace -f` (same uid)
  3. enforce a per-process execution timeout via the coreutils `timeout`
  4. parse the strace log into raw behavioral events (process/file/network)
  5. print a single JSON summary line to stdout, consumed by the host runner

Network is disabled in the container, so any connect()/sendto() the sample
attempts FAILS and is recorded as result:"blocked" - we never fabricate a
successful connection.

Args (from the host SandboxRunner):
  argv[1] = input directory (bind mount)
  argv[2] = sample file name ({sha256}.bin)
  argv[3] = display name (informational)
"""

import json
import os
import re
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

INPUT_DIR = Path(sys.argv[1])
SAMPLE_NAME = sys.argv[2] if len(sys.argv) > 2 else None
DISPLAY_NAME = sys.argv[3] if len(sys.argv) > 3 else SAMPLE_NAME
WORK = Path("/tmp")          # writable tmpfs for logs (noexec is fine for files)
TRACE_LOG = WORK / "trace.log"

TRACE_SYSCALLS = (
    "execve,execveat,clone,fork,vfork"
    ",open,openat,creat,unlink,unlinkat,rename"
    ",connect,sendto,recvfrom,socket"
)
EXEC_TIMEOUT_S = int(os.environ.get("SANDBOX_EXEC_TIMEOUT_S", "30"))
MAX_EVENTS = int(os.environ.get("SANDBOX_MAX_EVENTS", "2000"))


class Result:
    def __init__(self):
        self.status = "failed_to_start"
        self.exit_code = None
        self.events = []
        self.error = None
        self.events_truncated = False
        self.started_at = time.perf_counter()

    @property
    def duration_ms(self) -> int:
        return int((time.perf_counter() - self.started_at) * 1000)

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "events": self.events,
            "summary": {
                "process_events": sum(1 for e in self.events if e["kind"] == "process"),
                "filesystem_events": sum(1 for e in self.events if e["kind"] == "filesystem"),
                "network_attempts": sum(1 for e in self.events if e["kind"] == "network"),
                "events_truncated": self.events_truncated,
            },
        }


def emit(result: Result, kind: str, etype: str, **fields) -> None:
    if len(result.events) >= MAX_EVENTS:
        result.events_truncated = True
        return
    result.events.append({"kind": kind, "type": etype, **fields})


def _string_args(text: str, limit: int = 16) -> list[str]:
    """Extract quoted string arguments from a strace syscall line (bounded)."""
    args: list[str] = []
    pos = 0
    while len(args) < limit:
        start = text.find('"', pos)
        if start == -1:
            break
        end = text.find('"', start + 1)
        if end == -1:
            break
        args.append(text[start + 1 : end][:256])
        pos = end + 1
    return args


def _first_string_arg(text: str):
    if '"' not in text:
        return None
    start = text.index('"') + 1
    end = text.index('"', start)
    return text[start:end].replace("\\\\", "\\")


def _net_target(text: str):
    host = None
    port = None
    m = re.search(r'sin_addr=inet_addr\("([^"]+)"\)', text)
    n = re.search(r'sin_port=htons\((\d+)\)', text)
    if m:
        host = m.group(1)
    if n:
        port = int(n.group(1))
    if not host:
        mm = re.search(r'"([\d.]+)"', text)
        if mm:
            host = mm.group(1)
    return host, port


def parse_trace(result: Result, log_text: str) -> None:
    for line in log_text.splitlines():
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        pid_txt, rest = parts
        if not pid_txt.isdigit() or "(" not in rest:
            continue
        syscall = rest.partition("(")[0].strip()
        after = rest.partition("(")[2]
        try:
            if syscall in ("execve", "execveat"):
                args = _string_args(after)
                path = args[0] if args else None
                if path:
                    emit(result, "process", "process_created",
                         pid=pid_txt, name=Path(path).name, command_line=path,
                         argv=args[1:] if len(args) > 1 else [])
            elif syscall in ("clone", "fork", "vfork"):
                pass  # child tracked via its own exec; keep simple
            elif syscall in ("open", "openat", "creat"):
                path = _first_string_arg(after)
                if not path:
                    continue
                is_create = syscall == "creat" or "O_CREAT" in after
                is_write = ("O_WRONLY" in after or "O_RDWR" in after or "O_APPEND" in after)
                if is_create:
                    emit(result, "filesystem", "file_created", pid=pid_txt, path=path)
                elif is_write:
                    emit(result, "filesystem", "file_modified", pid=pid_txt, path=path)
                else:
                    emit(result, "filesystem", "file_accessed", pid=pid_txt, path=path)
            elif syscall in ("unlink", "unlinkat"):
                path = _first_string_arg(after)
                if path:
                    emit(result, "filesystem", "file_deleted", pid=pid_txt, path=path)
            elif syscall in ("connect", "sendto", "getaddrinfo"):
                dest, port = _net_target(after)
                emit(result, "network", "network_attempt", pid=pid_txt,
                     protocol="tcp", destination=dest, port=port, blocked=True)
            elif syscall == "socket":
                emit(result, "network", "network_attempt", pid=pid_txt,
                     protocol="unknown", destination=None, port=None, blocked=True)
        except Exception:
            continue


def build_command(sample: Path):
    """strace -f the sample. If it is a binfmt script (#!...), run via its
    interpreter so it traces even though the input mount is read-only (no chmod)."""
    try:
        head = sample.open("rb").read(2)
        if head == b"#!":
            interp = sample.open("rb").readline().decode(errors="replace").strip()
            interp = interp[2:].split()[0] if len(interp) > 2 else None
            # interpreter must live in rootfs (readable, executable)
            return interp  # run: <interp> <sample>
    except OSError:
        pass
    return None  # run the file directly (execve)


def main() -> None:
    result = Result()
    sample = INPUT_DIR / (SAMPLE_NAME or "")
    if not sample.is_file():
        result.status = "failed_to_start"
        result.error = f"sample not found: {sample}"
        print(json.dumps(result.to_dict()))
        return

    try:
        TRACE_LOG.unlink(missing_ok=True)
    except OSError:
        pass

    interp = build_command(sample)
    if interp:
        target = [interp, str(sample)]
    else:
        target = [str(sample)]

    cmd = [
        "timeout", "-k", "2", str(EXEC_TIMEOUT_S),
        "strace", "-f", "-qq",
        "-e", f"trace={TRACE_SYSCALLS}",
        "-o", str(TRACE_LOG),
    ] + target

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True
        )
    except OSError as exc:
        result.status = "failed_to_start"
        result.error = f"spawn: {exc}"
        print(json.dumps(result.to_dict()))
        return

    try:
        proc.wait(timeout=EXEC_TIMEOUT_S + 5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        result.status = "timeout"
    else:
        rc = proc.returncode
        result.exit_code = rc
        if rc == 124 or rc == 137:
            result.status = "timeout"
        elif rc is not None and rc > 128:
            result.status = "crashed"
        else:
            result.status = "completed"

    if TRACE_LOG.exists():
        try:
            parse_trace(result, TRACE_LOG.read_text(errors="replace"))
        except Exception as exc:
            result.error = (result.error or "") + f" parse_trace:{exc}"

    procs = [e for e in result.events if e["kind"] == "process"]
    if result.status in ("completed", "crashed") and not procs and result.exit_code not in (0, None):
        # exec failed outright - not a runnable binary/script in this container
        result.status = "failed_to_start"
        result.error = (result.error or "") + " no_process_spawned"

    print(json.dumps(result.to_dict()))


if __name__ == "__main__":
    main()
