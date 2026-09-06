"""Build the sandbox runner Docker image (M3).

Usage:
    .\\.venv\\Scripts\\python.exe scripts\\build_sandbox_image.py
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "docscan/sandbox-runner:latest"


def main() -> None:
    dockerfile_dir = ROOT / "sandbox_runner"
    print(f"[build] building {IMAGE} from {dockerfile_dir}")
    res = subprocess.run(
        ["docker", "build", "-t", IMAGE, str(dockerfile_dir)],
        cwd=str(ROOT),
    )
    if res.returncode != 0:
        print(f"[build] FAILED rc={res.returncode}")
        sys.exit(res.returncode)
    print("[build] OK")


if __name__ == "__main__":
    main()
