"""
Generate LLDB SBAPI scripts with ALF bootstrap headers.

The resulting script can be imported inside LLDB's embedded Python and still
`import alf` successfully.
"""

from __future__ import annotations

from ..server.environment import bootstrap_header
from .templates.fork_server import FORK_SERVER_TEMPLATE
from .templates.stop_hook import STOP_HOOK_TEMPLATE


def wrap_with_bootstrap(script: str, root: str | None = None) -> str:
    """Prepend the ALF sys.path bootstrap header to a script."""
    return bootstrap_header(root=root) + "\n\n" + script


def generate_stop_hook(
    ptr_reg: str = "x0",
    len_reg: str | None = None,
    max_size: int = 4096,
    name: str = "alf_stop_hook",
    telemetry_pipe: str | None = None,
    include_bootstrap: bool = True,
) -> str:
    """
    Generate a high-performance LLDB breakpoint stop-hook for in-process mutation.

    The hook:
      - reads a buffer pointer from `ptr_reg`
      - strips PAC bits
      - reads up to `max_size` bytes (or min(len_reg, max_size))
      - mutates with `alf.mut.apply_random_mutation`
      - writes bytes back and returns False to continue

    Returned script is ready to import via `lldb_script`.
    """
    script = STOP_HOOK_TEMPLATE.format(
        name=name,
        ptr_reg=ptr_reg,
        len_reg=len_reg or "",
        max_size=int(max_size),
        telemetry_pipe=telemetry_pipe or "",
    )
    return wrap_with_bootstrap(script) if include_bootstrap else script


def generate_fork_server(
    name: str = "alf_fork_server",
    telemetry_pipe: str | None = None,
    include_bootstrap: bool = True,
) -> str:
    """
    Generate an LLDB breakpoint callback that acts as a simple fork server.

    Intended for one-shot binaries: installed at entry (e.g., main/harness entry).
    Parent loops: fork -> waitpid(child) -> emit telemetry -> repeat.
    Child returns from callback and runs the target normally.
    """
    script = FORK_SERVER_TEMPLATE.format(
        name=name,
        telemetry_pipe=telemetry_pipe or "",
    )
    return wrap_with_bootstrap(script) if include_bootstrap else script
