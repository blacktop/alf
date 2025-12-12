"""Backend factory for creating LLDB backends.

Provides a unified interface for instantiating different backend types
without requiring knowledge of the specific implementation classes.

Usage:
    from alf.backend.factory import get_backend, BackendType

    # Create a DAP backend (default)
    backend = get_backend("dap", timeout=30.0)

    # Create an SBAPI backend for maximum performance
    backend = get_backend("sbapi", binary="/path/to/binary")

    # Create an LLDB MCP backend
    backend = get_backend("lldb_mcp", host="127.0.0.1", port=59999)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from .base import LLDBBackend

# Supported backend types
BackendType = Literal["dap", "sbapi", "lldb_mcp", "mock"]

# Default backend configuration
DEFAULT_BACKEND: BackendType = "dap"


def get_backend(
    backend_type: BackendType = DEFAULT_BACKEND,
    **kwargs,
) -> LLDBBackend:
    """Create and return an LLDB backend instance.

    Args:
        backend_type: Type of backend to create:
            - "dap": Debug Adapter Protocol backend (default, most compatible)
            - "sbapi": Direct LLDB Python API (fastest, requires lldb module)
            - "lldb_mcp": Native LLDB MCP protocol (requires LLDB MCP server)
            - "mock": Mock backend for testing/verification
        **kwargs: Backend-specific configuration options:

            DAP backend kwargs:
                host: DAP server host (default: "127.0.0.1")
                port: DAP server port (default: 4711)
                timeout: Operation timeout in seconds (default: 30.0)

            SBAPI backend kwargs:
                binary: Path to executable (optional, can set later)
                timeout: Operation timeout in seconds (default: 30.0)

            LLDB MCP backend kwargs:
                host: MCP server host (default: "127.0.0.1")
                port: MCP server port (default: 59999)
                timeout: Operation timeout in seconds (default: 30.0)
            
            Mock backend kwargs:
                scenario: Optional scenario name.

    Returns:
        An LLDBBackend instance ready for use.

    Raises:
        ValueError: If backend_type is not recognized.
        ImportError: If the backend's dependencies are not available.

    Example:
        >>> backend = get_backend("dap", port=4712)
        >>> backend.connect()
        >>> result = backend.launch("/path/to/binary")
    """
    if backend_type == "dap":
        from .dap import DAPBackend

        return DAPBackend(
            host=kwargs.get("host", "127.0.0.1"),
            port=kwargs.get("port", 4711),
            timeout=kwargs.get("timeout", 30.0),
        )

    if backend_type == "sbapi":
        from .sbapi import SBAPIBackend

        return SBAPIBackend(
            binary=kwargs.get("binary"),
            timeout=kwargs.get("timeout", 30.0),
        )

    if backend_type == "lldb_mcp":
        from .lldb_mcp import LLDBMCPBackend

        return LLDBMCPBackend(
            host=kwargs.get("host", "127.0.0.1"),
            port=kwargs.get("port", 59999),
            timeout=kwargs.get("timeout", 30.0),
        )

    if backend_type == "mock":
        from .mock import MockBackend

        return MockBackend(
            timeout=kwargs.get("timeout", 30.0),
            scenario=kwargs.get("scenario", "default"),
        )

    raise ValueError(
        f"Unknown backend type: {backend_type!r}. "
        f"Supported types: 'dap', 'sbapi', 'lldb_mcp', 'mock'"
    )


def list_backends() -> list[dict[str, str]]:
    """List available backends with their descriptions.

    Returns:
        List of backend info dicts with 'name' and 'description' keys.
    """
    return [
        {
            "name": "dap",
            "description": "Debug Adapter Protocol - connects to lldb-dap server",
        },
        {
            "name": "sbapi",
            "description": "LLDB Python API - direct LLDB access (fastest, requires lldb module)",
        },
        {
            "name": "lldb_mcp",
            "description": "Native LLDB MCP - connects to LLDB's built-in MCP server",
        },
        {
            "name": "mock",
            "description": "Mock Backend - simulates debugging for testing/verification",
        },
    ]


def check_backend_available(backend_type: BackendType) -> tuple[bool, str | None]:
    """Check if a backend is available.

    Args:
        backend_type: Backend type to check.

    Returns:
        Tuple of (available, error_message).
        If available is True, error_message is None.
        If available is False, error_message explains why.
    """
    if backend_type == "dap":
        # DAP is always available (pure Python)
        return True, None

    if backend_type == "sbapi":
        try:
            import lldb  # noqa: F401

            return True, None
        except ImportError:
            return False, "SBAPI backend requires the lldb Python module"

    if backend_type == "lldb_mcp":
        # LLDB MCP is always available (pure Python client)
        return True, None

    if backend_type == "mock":
        return True, None

    return False, f"Unknown backend type: {backend_type}"


__all__ = [
    "BackendType",
    "DEFAULT_BACKEND",
    "get_backend",
    "list_backends",
    "check_backend_available",
]
