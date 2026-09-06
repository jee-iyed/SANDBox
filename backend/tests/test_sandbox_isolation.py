import hashlib
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from docker.errors import ContainerError  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.analyzers.sandbox.runner import SandboxError, SandboxRunner  # noqa: E402

runner = SandboxRunner()


def run_custom(entry_args: list[str], py_code: str):
    try:
        logs = runner.client.containers.run(
            image=settings.sandbox_image,
            entrypoint=["python"],
            command=["-c", py_code],
            network_disabled=True,
            mem_limit=settings.sandbox_mem_limit,
            nano_cpus=settings.sandbox_nano_cpus,
            pids_limit=settings.sandbox_pids_limit,
            read_only=True,
            tmpfs={"/tmp": "size=8m,noexec,nodev,nosuid"},
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            remove=True,
        )
        return 0, logs.decode(errors="replace")
    except ContainerError as exc:
        return exc.exit_status, exc.stderr.decode(errors="replace")


code_net = (
    "import socket;"
    "s=socket.socket();s.settimeout(4);"
    "s.connect(('93.184.216.34',53));print('NETWORK_REACHABLE')"
)
exit_code, out = run_custom([], code_net)
assert "NETWORK_REACHABLE" not in out and exit_code != 0, f"net leak! {out}"
print("isolation OK: network unreachable")

code_write = "open('/etc/pwned','w').write('x');print('ROOTFS_WRITABLE')"
exit_code, out = run_custom([], code_write)
assert "ROOTFS_WRITABLE" not in out and exit_code != 0, f"rootfs writable! {out}"
print("isolation OK: rootfs read-only")

data = b"%PDF-1.4\n% sandbox isolation verification\n"
sha = hashlib.sha256(data).hexdigest()
verify_path = settings.storage_dir / "uploads" / f"{sha}.bin"
try:
    verify_path.write_bytes(data)
    try:
        result = runner.analyze_file(sha, "verify.pdf")
    except SandboxError as exc:
        raise SystemExit(f"happy path failed: {exc}")
finally:
    if verify_path.exists():
        os.remove(verify_path)
assert result.status in ("completed", "timeout"), result
assert result.exit_code is None or result.exit_code >= 0, result
assert isinstance(result.events, list), result
assert isinstance(result.summary, dict), result
assert result.sandbox_id.startswith("sandbox-"), result
print(f"isolation OK: analysis roundtrip ({result.duration_ms}ms, {result.status})")

print("SANDBOX ISOLATION TEST PASSED")
