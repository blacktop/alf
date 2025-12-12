from __future__ import annotations

import os
import json
from typing import TYPE_CHECKING, Any

from ..schema import Tool, ToolParameter

if TYPE_CHECKING:
    from ...server.lldb import LLDBDirector

# Calculate paths relative to this file
# .../alf/tools/definitions/capabilities.py
# .../alf/capabilities/
DEFS_DIR = os.path.dirname(os.path.abspath(__file__))
ALF_DIR = os.path.dirname(os.path.dirname(DEFS_DIR))
CAP_DIR = os.path.join(ALF_DIR, "capabilities")

def _get_import_cmd(module: str) -> str:
    path = os.path.join(CAP_DIR, f"{module}.py")
    return f"command script import '{path}'"

def _run_capability(director: LLDBDirector, module: str, func: str, args: list[str] = None) -> str:
    """Helper to import module and run a function via result = func()."""
    import_cmd = _get_import_cmd(module)
    
    # We execute import first
    res = director.execute_lldb_command(import_cmd)
    if "error" in res.lower() and "no such file" in res.lower():
        return f"Failed to load module {module}: {res}"

    # Construct python call
    # We use 'script' command to run python code
    # args must be properly formatted python literals
    arg_str = ", ".join(args) if args else ""
    # We call it fully qualified assuming the file loader used the filename as module
    # or the module fixed sys.path and we import it.
    # Because of the 'command script import path', LLDB imports it as the basename of the file.
    # BUT our modules have 'package' structure inside them (from .objchelpers import ...).
    # The 'alf.capabilities.xpc' preamble handles sys.path.
    # We should access it via 'alf.capabilities.module' if it was imported that way?
    # NO, 'command script import' usually puts it in `sys.modules` under the filename (e.g. 'xpc').
    # But checking xpc.py: `from alf.capabilities.objchelpers`.
    # It probably registers 'alf' package too.
    
    # Safe bet: use the module name inferred from filename.
    # LLDB 15+: import .../xpc.py -> import xpc
    
    # However, to be safe, we can just run the function if we know where it is.
    # Let's try `alf.capabilities.{module}.{func}` first, assuming our sys.path hack worked.
    
    py_cmd = f"script import alf.capabilities.{module} as m; m.{func}({arg_str})"
    return director.execute_lldb_command(py_cmd)

def _xpc_sniff_handler(director: LLDBDirector) -> str:
    return _run_capability(director, "xpc", "sniff_xpc")

def _xpc_send_handler(director: LLDBDirector, service: str, message_json: str) -> str:
    # args: service (str), message (dict)
    # verify json
    try:
        json.loads(message_json)
    except:
        return "Error: message_json must be valid JSON string"
        
    return _run_capability(director, "xpc", "send_xpc", [f'"{service}"', message_json])

def _heap_inspect_handler(director: LLDBDirector, verbose: bool = True) -> str:
    return _run_capability(director, "heap", "inspect_heap", [str(verbose)])

def _heap_check_handler(director: LLDBDirector) -> str:
    return _run_capability(director, "heap", "heap_health")

def _objc_inspect_handler(director: LLDBDirector, class_name: str) -> str:
    # This returns an object, we want to print it or return json
    # helper: script print(json.dumps(m.get_class("foo").data))
    
    # We need a custom script wrapper here to return the data
    import_cmd = _get_import_cmd("objc")
    director.execute_lldb_command(import_cmd)
    
    script = f"""
    script
    import json
    import alf.capabilities.objc as m
    try:
        cls = m.get_class("{class_name}")
        print(json.dumps(cls.data, indent=2))
    except Exception as e:
        print(f"Error: {{e}}")
    """
    # The 'script' command enters interactive mode if on newline?
    # No, `script <code_on_line>` works for one line.
    # For multiline: `script` then lines. 
    # lldb-dap execute_lldb_command sends expression in 'repl'.
    # `script ...` works.
    # But multiline python in `script` command is tricky via DAP single command?
    # We can use `script` one-liner with ;
    
    # Also, we need to escape quotes in class_name
    
    py_code = f"import json; import alf.capabilities.objc as m; print(json.dumps(m.get_class('{class_name}').data, indent=2))"
    return director.execute_lldb_command(f"script {py_code}")

def _monitor_handler(director: LLDBDirector, symbol: str, regs: str = "") -> str:
    # regs is comma list?
    reg_list = [r.strip() for r in regs.split(',')] if regs else []
    reg_list_py = str(reg_list)
    return _run_capability(director, "monitor", "monitor_address", [f'"{symbol}"', f"regs={reg_list_py}"])

# Tools

XPC_SNIFF = Tool(
    name="xpc_sniff",
    description="Enable sniffing of XPC messages (xpc_connection_send_message).",
    parameters=[],
    handler=_xpc_sniff_handler,
    category="capabilities",
    requires_lock=True
)

XPC_SEND = Tool(
    name="xpc_send",
    description="Send an XPC message to a service.",
    parameters=[
        ToolParameter(name="service", type="string", description="Service name (e.g. com.apple.foobar)"),
        ToolParameter(name="message_json", type="string", description="JSON string representing the XPC dictionary")
    ],
    handler=_xpc_send_handler,
    category="capabilities",
    requires_lock=True
)

HEAP_INSPECT = Tool(
    name="heap_inspect",
    description="Inspect the default malloc zone.",
    parameters=[
        ToolParameter(name="verbose", type="boolean", description="Verbose output", required=False, default=True)
    ],
    handler=_heap_inspect_handler,
    category="capabilities",
    requires_lock=True
)

HEAP_CHECK = Tool(
    name="heap_check",
    description="Run consistency check on the heap (malloc_zone_check).",
    parameters=[],
    handler=_heap_check_handler,
    category="capabilities",
    requires_lock=True
)

OBJC_INSPECT = Tool(
    name="objc_inspect",
    description="Inspect an Objective-C class (methods, properties).",
    parameters=[
        ToolParameter(name="class_name", type="string", description="Class name (e.g. NSString)")
    ],
    handler=_objc_inspect_handler,
    category="capabilities",
    requires_lock=True
)

MONITOR_TRACE = Tool(
    name="monitor_trace",
    description="Trace calls to a function, printing registers.",
    parameters=[
        ToolParameter(name="symbol", type="string", description="Symbol name to trace"),
        ToolParameter(name="regs", type="string", description="Comma-separated list of registers to print (e.g. 'x0,x1')", required=False)
    ],
    handler=_monitor_handler,
    category="capabilities",
    requires_lock=True
)

CAPABILITY_TOOLS = [
    XPC_SNIFF,
    XPC_SEND,
    HEAP_INSPECT,
    HEAP_CHECK,
    OBJC_INSPECT,
    MONITOR_TRACE
]
