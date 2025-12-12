"""
XPC message sniffing and injection via LLDB.

Derived from Hilda (https://github.com/doronz88/hilda)
Copyright (c) 2012-2023 Doron Zarhi and Metan Perelman
Licensed under MIT License
"""

import lldb
import sys
import os

# Add package root to sys.path to allow imports from alf package
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(os.path.dirname(current_dir))
if root_dir not in sys.path:
    sys.path.append(root_dir)

try:
    from alf.capabilities.objchelpers import to_ns, from_ns, evaluate_expression, get_target
except ImportError:
    # Fallback for when loaded directly in some weird context
    pass

# Global cache for connections
active_connections = {}

def from_xpc(addr):
    """Convert XPC object address to Python object."""
    # _CFXPCCreateCFObjectFromXPCObject returns a CF object which we can decode as NS
    expr = f"(id)_CFXPCCreateCFObjectFromXPCObject((void*)0x{addr:x})"
    try:
        val = evaluate_expression(expr)
        return from_ns(val)
    except Exception as e:
        return f"<XPC Decode Failed: {e}>"

def to_xpc(py_obj):
    """Convert Python object to XPC object address (SBValue)."""
    ns_val = to_ns(py_obj)
    expr = f"(void*)_CFXPCCreateXPCObjectFromCFObject((void*){ns_val.GetValueAsUnsigned()})"
    return evaluate_expression(expr)

def xpc_sniffer_callback(frame, bp_loc, dict):
    """LLDB Breakpoint callback for xpc_connection_send_message."""
    # Assuming arm64 argument passing convention
    # x0 = connection
    # x1 = message
    try:
        conn = frame.FindRegister("x0").GetValueAsUnsigned()
        msg = frame.FindRegister("x1").GetValueAsUnsigned()
        
        print(f"\n[XPC Sniff] Connection: 0x{conn:x} | Message: 0x{msg:x}")
        
        # Determine service name if possible (complex, maybe from connection?)
        # For now, just decode message
        decoded = from_xpc(msg)
        print(f"[XPC Body]: {decoded}")
        
    except Exception as e:
        print(f"[XPC Sniff Error] {e}")
        
    return False # Continue execution

def sniff_xpc():
    """Install breakpoints to trace XPC messages."""
    target = get_target()
    if not target.IsValid():
        print("Error: No valid target.")
        return

    bp_name = "xpc_connection_send_message"
    bp = target.BreakpointCreateByName(bp_name)
    # Note: We assume this module is loaded as 'xpc' or 'alf.capabilities.xpc'
    # 'xpc' is safe if imported via command script import xpc.py
    # If loaded as package, it might differ.
    # We'll try 'xpc.xpc_sniffer_callback'
    bp.SetScriptCallbackFunction("alf.capabilities.xpc.xpc_sniffer_callback")
    print(f"XPC Sniffer installed on {bp_name}")

def send_xpc(service_name, message_data):
    """
    Send an XPC message to a service.
    message_data: dict/list/primitive (JSON serializable)
    """
    global active_connections
    
    conn = active_connections.get(service_name)
    if not conn:
        print(f"Connecting to {service_name}...")
        # xpc_connection_create_mach_service(name, q, flags)
        # q=0 (NULL) -> default queue? Or dispatch_get_main_queue()?
        # flags=0
        
        # We need a queue. 0 might crash?
        # Hilda uses 0, 0.
        
        create_expr = f'(void*)xpc_connection_create_mach_service("{service_name}", 0, 0)'
        val = evaluate_expression(create_expr)
        conn = val.GetValueAsUnsigned()
        
        if conn == 0:
            raise Exception("Failed to create XPC connection")
            
        # Set event handler (required?)
        # Hilda does: set_event_handler(conn, ^(id obj){})
        # We need blocks support or empty handler.
        # "extern void xpc_connection_set_event_handler(intptr_t, id);"
        # "xpc_connection_set_event_handler({conn}, ^(id obj) {{}})"
        # This uses clang block syntax which might work in expression parser.
        
        setup_expr = f'''
            typedef void (^xpc_handler_t)(void*);
            void xpc_connection_set_event_handler(void*, xpc_handler_t);
            xpc_connection_set_event_handler((void*)0x{conn:x}, ^(void* obj){{}});
            void xpc_connection_resume(void*);
            xpc_connection_resume((void*)0x{conn:x});
        '''
        evaluate_expression(setup_expr)
        active_connections[service_name] = conn

    # Create Message
    xpc_msg = to_xpc(message_data)
    
    # Send
    # xpc_connection_send_message_with_reply_sync(conn, msg)
    send_expr = f'''
        void* xpc_connection_send_message_with_reply_sync(void*, void*);
        xpc_connection_send_message_with_reply_sync((void*)0x{conn:x}, (void*){xpc_msg.GetValueAsUnsigned()});
    '''
    res = evaluate_expression(send_expr)
    
    # Decode result
    return from_xpc(res.GetValueAsUnsigned())

def __lldb_init_module(debugger, internal_dict):
    # This runs when the script is imported
    # We can expose commands if we want, or just let python code be used.
    # Expose 'xpc_sniff' command?
    debugger.HandleCommand('command script add -f alf.capabilities.xpc.sniff_xpc xpc_sniff')
    print("alf.capabilities.xpc loaded. Use 'xpc_sniff' to trace.")
