"""ALF configuration management.

Config file precedence (highest to lowest):
1. CLI flags (handled by Click)
2. `.alf.toml` in current directory or parent directories
3. `~/.config/alf/config.toml` (user config)
4. Environment variables (fallback for CI/scripts)

Example config file:
```toml
[provider]
name = "lmstudio"
model = "mistralai/devstral-small-2-2512"
timeout = 180

[provider.lmstudio]
base_url = "http://localhost:1234/v1"

[provider.ollama]
base_url = "http://localhost:11434/v1"

[provider.anthropic]
# api_key from env or keychain

[lldb]
dap_path = "/usr/bin/lldb-dap"
timeout = 30
```
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import tomllib

# Config file names
LOCAL_CONFIG_NAME = ".alf.toml"
USER_CONFIG_PATH = Path.home() / ".config" / "alf" / "config.toml"

# Cache for loaded config
_config_cache: dict[str, Any] | None = None


def find_local_config() -> Path | None:
    """Find .alf.toml in current directory or parent directories."""
    cwd = Path.cwd().resolve()
    for directory in [cwd, *cwd.parents]:
        config_path = directory / LOCAL_CONFIG_NAME
        if config_path.is_file():
            return config_path
        # Stop at home directory or root
        if directory == Path.home() or directory == directory.parent:
            break
    return None


def load_config_file(path: Path) -> dict[str, Any]:
    """Load a TOML config file."""
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except FileNotFoundError:
        return {}
    except tomllib.TOMLDecodeError as e:
        import sys

        print(f"[!] Error parsing {path}: {e}", file=sys.stderr)
        return {}


def load_config(*, force_reload: bool = False) -> dict[str, Any]:
    """Load merged configuration from all sources.

    Precedence (highest to lowest):
    1. `.alf.toml` in current/parent directory
    2. `~/.config/alf/config.toml`

    Environment variables are NOT merged here - they're handled
    as fallbacks in the specific config accessors.

    Args:
        force_reload: Force reload from disk (ignore cache).

    Returns:
        Merged configuration dictionary.
    """
    global _config_cache

    if _config_cache is not None and not force_reload:
        return _config_cache

    # Start with user config (lowest priority)
    config: dict[str, Any] = {}
    if USER_CONFIG_PATH.is_file():
        config = load_config_file(USER_CONFIG_PATH)

    # Merge local config (higher priority)
    local_path = find_local_config()
    if local_path:
        local_config = load_config_file(local_path)
        config = _deep_merge(config, local_config)

    _config_cache = config
    return config


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Deep merge two dictionaries. Override values take precedence."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def get(key: str, default: Any = None) -> Any:
    """Get a config value by dot-notation key.

    Example:
        get("provider.name")  # Returns provider name
        get("provider.lmstudio.base_url")  # Returns LM Studio URL

    Args:
        key: Dot-notation key (e.g., "provider.name").
        default: Default value if key not found.

    Returns:
        Config value or default.
    """
    config = load_config()
    parts = key.split(".")
    value: Any = config

    for part in parts:
        if isinstance(value, dict) and part in value:
            value = value[part]
        else:
            return default

    return value


def get_provider_config(provider_name: str | None = None) -> dict[str, Any]:
    """Get provider-specific configuration.

    Args:
        provider_name: Provider name, or None to use configured default.

    Returns:
        Dict with provider settings (name, model, base_url, api_key, timeout).
    """
    config = load_config()
    provider_section = config.get("provider", {})

    # Determine provider name
    name = provider_name or provider_section.get("name")

    # Get provider-specific overrides
    provider_overrides = provider_section.get(name, {}) if name else {}

    # Build result with fallbacks
    result: dict[str, Any] = {
        "name": name,
        "model": provider_overrides.get("model") or provider_section.get("model"),
        "base_url": provider_overrides.get("base_url"),
        "api_key": provider_overrides.get("api_key"),
        "timeout": provider_overrides.get("timeout") or provider_section.get("timeout"),
        "jit_ttl": provider_overrides.get("jit_ttl"),  # LM Studio JIT loading TTL
    }

    return result


def get_lldb_config() -> dict[str, Any]:
    """Get LLDB/DAP configuration.

    LLDB connection modes:
    1. Local spawn (default): spawn_dap=true, spawns lldb-dap subprocess
    2. Local connect: spawn_dap=false, dap_host/dap_port to connect to existing
    3. Remote: remote_url="lldb://host:port" or "gdb://host:port"
    """
    config = load_config()
    lldb_section = config.get("lldb", {})

    return {
        "dap_path": lldb_section.get("dap_path"),
        "dap_host": lldb_section.get("dap_host", "127.0.0.1"),
        "dap_port": lldb_section.get("dap_port", 0),
        "timeout": lldb_section.get("timeout", 30.0),
        "spawn_dap": lldb_section.get("spawn_dap", True),
        # Remote debugging support
        "remote_url": lldb_section.get("remote_url"),  # e.g., "lldb://192.168.1.100:1234"
        "remote_platform": lldb_section.get("remote_platform"),  # e.g., "remote-ios"
    }


def get_director_config() -> dict[str, Any]:
    """Get director/agent configuration."""
    config = load_config()
    director_section = config.get("director", {})

    return {
        "max_turns": director_section.get("max_turns", 10),
        "mode": director_section.get("mode", "auto"),
        "minimal_tools": director_section.get("minimal_tools", False),
        "write_corpus": director_section.get("write_corpus", True),
        "write_dict": director_section.get("write_dict", True),
        "verbose": director_section.get("verbose", False),
    }


@dataclass
class AlfConfig:
    """Complete ALF configuration."""

    # Provider settings
    provider_name: str | None = None
    provider_model: str | None = None
    provider_base_url: str | None = None
    provider_api_key: str | None = None
    provider_timeout: float = 180.0

    # LLDB settings
    lldb_dap_path: str | None = None
    lldb_dap_host: str = "127.0.0.1"
    lldb_dap_port: int = 0
    lldb_timeout: float = 30.0
    lldb_spawn_dap: bool = True

    # Paths
    corpus_dir: str | None = None
    crashes_dir: str | None = None
    logs_dir: str | None = None

    @classmethod
    def load(cls) -> AlfConfig:
        """Load configuration from files and environment."""
        provider = get_provider_config()
        lldb = get_lldb_config()
        config = load_config()

        # Environment variable fallbacks for provider
        env_provider = os.environ.get("ALF_LLM_PROVIDER")
        env_model = os.environ.get("ALF_LLM_MODEL") or os.environ.get("LLDB_MCP_MODEL")
        env_base_url = os.environ.get("ALF_LLM_BASE_URL") or os.environ.get("OPENAI_BASE_URL")
        env_api_key = os.environ.get("ALF_LLM_API_KEY")
        env_timeout = os.environ.get("ALF_LLM_TIMEOUT")

        # Environment variable fallbacks for LLDB
        env_dap_path = os.environ.get("LLDB_DAP_BIN")

        return cls(
            # Provider (config file > env)
            provider_name=provider.get("name") or env_provider,
            provider_model=provider.get("model") or env_model,
            provider_base_url=provider.get("base_url") or env_base_url,
            provider_api_key=provider.get("api_key") or env_api_key,
            provider_timeout=float(provider.get("timeout") or env_timeout or 180.0),
            # LLDB (config file > env)
            lldb_dap_path=lldb.get("dap_path") or env_dap_path,
            lldb_dap_host=lldb.get("dap_host", "127.0.0.1"),
            lldb_dap_port=lldb.get("dap_port", 0),
            lldb_timeout=float(lldb.get("timeout", 30.0)),
            lldb_spawn_dap=lldb.get("spawn_dap", True),
            # Paths
            corpus_dir=config.get("paths", {}).get("corpus_dir"),
            crashes_dir=config.get("paths", {}).get("crashes_dir"),
            logs_dir=config.get("paths", {}).get("logs_dir"),
        )


def config_locations() -> list[tuple[str, Path, bool]]:
    """List config file locations and whether they exist.

    Returns:
        List of (description, path, exists) tuples.
    """
    local = find_local_config()
    return [
        ("local", local or Path.cwd() / LOCAL_CONFIG_NAME, local is not None),
        ("user", USER_CONFIG_PATH, USER_CONFIG_PATH.is_file()),
    ]


def print_config_info() -> None:
    """Print configuration info for debugging."""
    print("Config file locations:")
    for desc, path, exists in config_locations():
        status = "found" if exists else "not found"
        print(f"  [{desc}] {path} ({status})")

    config = load_config()
    if config:
        print("\nLoaded configuration:")
        _print_dict(config, indent=2)
    else:
        print("\nNo configuration loaded.")


def _print_dict(d: dict[str, Any], indent: int = 0) -> None:
    """Pretty print a dict."""
    prefix = " " * indent
    for key, value in d.items():
        if isinstance(value, dict):
            print(f"{prefix}{key}:")
            _print_dict(value, indent + 2)
        else:
            # Mask sensitive values
            if "key" in key.lower() or "secret" in key.lower() or "password" in key.lower():
                value = "***" if value else None
            print(f"{prefix}{key}: {value}")
