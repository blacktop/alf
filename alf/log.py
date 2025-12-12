"""ALF logging configuration using Loguru.

Provides styled CLI logging with:
- Debug: grey, shown with --verbose
- Info: blue [+]
- Success: green [+]
- Warning: yellow [!]
- Error: red [-]

Usage:
    from alf.log import logger, configure_logging

    # In CLI setup
    configure_logging(verbose=args.verbose)

    # Throughout code
    logger.debug("Debug details...")      # Grey, only with --verbose
    logger.info("Processing...")          # Blue [+]
    logger.success("Done!")               # Green [+]
    logger.warning("Watch out")           # Yellow [!]
    logger.error("Failed")                # Red [-]
"""

from __future__ import annotations

import sys

from loguru import logger

# Remove default handler
logger.remove()

# ANSI escape codes for colors (used in extra dict values since loguru markup
# only works in format strings, not interpolated values)
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"
_BLUE = "\033[34m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_RED = "\033[31m"

# Format strings - location info only shown in verbose/debug mode
_FORMAT_VERBOSE = "{extra[prefix]} {extra[message]} <dim>({name}:{function}:{line})</dim>"
_FORMAT_NORMAL = "{extra[prefix]} {extra[message]}"


def _style_patcher(record: dict) -> None:
    """Patch record with styled prefix and message using ANSI codes."""
    level = record["level"].name
    message = record["message"]

    # Define styles per level: (prefix_text, prefix_color, msg_color)
    styles = {
        "TRACE": (".", _DIM, _DIM),
        "DEBUG": (".", _DIM, _DIM),
        "INFO": ("+", _BLUE, ""),
        "SUCCESS": ("+", _GREEN, _GREEN),
        "WARNING": ("!", _YELLOW, _YELLOW),
        "ERROR": ("-", _RED, _RED),
        "CRITICAL": ("!", _RED + _BOLD, _RED + _BOLD),
    }

    prefix_char, prefix_color, msg_color = styles.get(level, ("*", "", ""))

    # Build styled prefix: [X] where X is colored
    if prefix_color:
        styled_prefix = f"[{prefix_color}{prefix_char}{_RESET}]"
    else:
        styled_prefix = f"[{prefix_char}]"

    # Build styled message
    if msg_color:
        styled_message = f"{msg_color}{message}{_RESET}"
    else:
        styled_message = message

    record["extra"]["prefix"] = styled_prefix
    record["extra"]["message"] = styled_message


def configure_logging(
    *,
    verbose: bool = False,
    debug: bool = False,
    quiet: bool = False,
) -> None:
    """Configure logging for CLI usage.

    Args:
        verbose: Show debug messages (grey).
        debug: Show debug with file:line info.
        quiet: Only show warnings and errors.
    """
    # Remove any existing handlers
    logger.remove()

    if quiet:
        level = "WARNING"
        fmt = _FORMAT_NORMAL
    elif debug:
        level = "DEBUG"
        fmt = _FORMAT_VERBOSE
    elif verbose:
        level = "DEBUG"
        fmt = _FORMAT_NORMAL
    else:
        level = "INFO"
        fmt = _FORMAT_NORMAL

    # Configure logger with patcher for styled output
    logger.configure(patcher=_style_patcher)

    # Add stderr handler
    logger.add(
        sys.stderr,
        level=level,
        format=fmt,
        colorize=True,
    )


def configure_logging_from_level(log_level: str) -> None:
    """Configure logging from a log level string.

    Args:
        log_level: One of DEBUG, INFO, WARNING, ERROR.
    """
    logger.remove()

    level_map = {
        "DEBUG": _FORMAT_VERBOSE,
        "INFO": _FORMAT_NORMAL,
        "WARNING": _FORMAT_NORMAL,
        "ERROR": _FORMAT_NORMAL,
    }

    fmt = level_map.get(log_level, _FORMAT_NORMAL)

    # Configure logger with patcher for styled output
    logger.configure(patcher=_style_patcher)

    logger.add(
        sys.stderr,
        level=log_level,
        format=fmt,
        colorize=True,
    )


# Configure with sensible defaults (INFO level, no location)
configure_logging(verbose=False)


__all__ = ["logger", "configure_logging", "configure_logging_from_level"]
