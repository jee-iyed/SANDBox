"""Raw behavioral event definitions produced inside the sandbox (M3).

The in-container entrypoint (sandbox_runner/) traces the sample under `strace -f`
and emits a list of *raw* events. This module defines their shape and the stable
strings they map to. Normalization (raw -> FindingSpec) lives in normalizer.py,
per the single canonical Finding schema.
"""

from __future__ import annotations

from enum import Enum


class ExecutionStatus(str, Enum):
    """Distinct terminal states - failures are NOT collapsed into one value."""

    COMPLETED = "completed"          # process exited on its own (exit_code set)
    TIMEOUT = "timeout"              # killed because exec_timeout_s elapsed
    CRASHED = "crashed"              # terminated by signal
    FAILED_TO_START = "failed_to_start"  # sample could not be launched at all
    RESOURCE_LIMIT = "resource_limit"     # hit a container/pids/mem limit


class RawEventType(str, Enum):
    PROCESS = "process"
    FILESYSTEM = "filesystem"
    NETWORK = "network"


# Finding types produced by the normalizer (stable across scans).
FINDING_PROCESS_CREATION = "process_creation"
FINDING_FILE_CREATION = "file_creation"
FINDING_FILE_MODIFICATION = "file_modification"
FINDING_FILE_DELETION = "file_deletion"
FINDING_NETWORK_ATTEMPT = "network_attempt"
FINDING_EXECUTION_TIMEOUT = "execution_timeout"
FINDING_RESOURCE_LIMIT = "resource_limit"
FINDING_SANDBOX_INFO = "sandbox_info"
FINDING_SANDBOX_ERROR = "sandbox_error"
