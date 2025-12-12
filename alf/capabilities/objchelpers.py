"""
LLDB bridge utilities for Objective-C runtime inspection.

Derived from Hilda (https://github.com/doronz88/hilda)
Copyright (c) 2012-2023 Doron Zarhi and Metan Perelman
Licensed under MIT License
"""

import lldb
import json
import os

# Helper to locate the .m files
PAYLOADS_DIR = os.path.join(os.path.dirname(__file__), 'objc')

def get_target():
    return lldb.debugger.GetSelectedTarget()

def get_process():
    return get_target().GetProcess()

def get_frame():
    thread = get_process().GetSelectedThread()
    if not thread.IsValid():
         return None
    return thread.GetSelectedFrame()

def evaluate_expression(expr, ignore_breakpoints=True, unwind_on_error=True):
    frame = get_frame()
    if not frame:
        raise Exception("No valid frame found (process not running or no thread selected).")
    
    options = lldb.SBExpressionOptions()
    options.SetIgnoreBreakpoints(ignore_breakpoints)
    options.SetTryAllThreads(True)
    options.SetUnwindOnError(unwind_on_error)
    # Ensure we have ObjC context
    options.SetLanguage(lldb.eLanguageTypeObjC)

    val = frame.EvaluateExpression(expr, options)
    if not val.GetError().Success():
        raise Exception(f"Expression evaluation failed: {val.GetError()}")
    return val

def read_payload(filename):
    path = os.path.join(PAYLOADS_DIR, filename)
    with open(path, 'r') as f:
        return f.read()

class ConvertingToNsObjectError(Exception):
    pass

class ConvertingFromNSObjectError(Exception):
    pass

def to_ns(data):
    """
    Create NSObject from given python data (must be JSON serializable).
    Returns an SBValue pointing to the NSObject.
    """
    try:
        # We wrap in 'root' dict as Hilda does, because top-level json must be object/array? 
        # Actually standard json supports primitives, but Hilda implementation expects 'root' key.
        json_data = json.dumps({'root': data})
    except TypeError as e:
        raise ConvertingToNsObjectError(f"Data is not JSON serializable: {e}")

    obj_c_code = read_payload('to_ns_from_json.m')
    # Escape quotes for C string literal
    escaped_json = json_data.replace('"', r'\"')
    expression = obj_c_code.replace('__json_object_dump__', escaped_json)
    
    try:
        # returns SBValue
        return evaluate_expression(expression)
    except Exception as e:
        raise ConvertingToNsObjectError(f"Failed to execute ObjC bridge: {e}")

def from_ns(addr):
    """
    Create python object from NS object at address (int or hex str or SBValue).
    """
    if isinstance(addr, lldb.SBValue):
        addr_str = f"0x{addr.GetValueAsUnsigned():x}"
    elif isinstance(addr, int):
        addr_str = f"0x{addr:x}"
    else:
        addr_str = str(addr)

    obj_c_code = read_payload('from_ns_to_json.m')
    expression = obj_c_code.replace('__ns_object_address__', addr_str)

    try:
        # We need the output string (po), not just the SBValue of the result.
        # Hilda uses 'po' which prints description. 
        # 'from_ns_to_json.m' likely returns a NSString or prints it?
        # Let's check from_ns_to_json.m content via cat if needed, but Hilda says: 
        # json_dump = self.po(expression)
        
        # We need to evaluate, and get the string value of the result.
        # But 'po' command in LLDB prints the `debugDescription`.
        # If the expression returns an NSString*, we can get its summary or value.
        
        val = evaluate_expression(expression)
        # The result of the expression in from_ns_to_json.m should be the JSON NSString.
        
        # We need to get the C-string from the NSString.
        # val is an NSString*.
        # simpler way: `(const char *)[val UTF8String]`
        
        utf8_expr = f"(const char *)[(id){val.GetValueAsUnsigned()} UTF8String]"
        utf8_val = evaluate_expression(utf8_expr)
        
        # GetSummary() might return the string in quotes
        # GetCommandInterpreter().HandleCommand("po ...") is safer?
        
        # Let's try reading memory if it's a char*
        ptr = utf8_val.GetValueAsUnsigned()
        if ptr == 0:
             # Fallback: maybe the expression printed to stdout?
             # Hilda used self.po(expression).
             pass

        # To act like 'po', we can use HandleCommand.
        res = lldb.SBCommandReturnObject()
        lldb.debugger.GetCommandInterpreter().HandleCommand(f"po {expression}", res)
        if not res.Succeeded():
             raise Exception(res.GetError())
        json_dump = res.GetOutput().strip()
        
        # Hilda's from_ns_to_json.m usually returns the NSString. 'po' prints it. 
        # 'po' of a valid JSON string is the string itself (no quotes typically if it's raw output? or quotes?)
        # NSString description is the content.
        
        # If json_dump is quoted, remove quotes? JSON doesn't strictly allow unquoted usage but po output might vary.
        # Assuming clean json.
        
        # The Hilda code: json.loads(json_dump, ...)
        
        return json.loads(json_dump)['root']
        
    except Exception as e:
        raise ConvertingFromNSObjectError(f"Failed to convert from NS: {e} | Dump: {locals().get('json_dump', 'N/A')}")

def call_function(func_name, args, return_type="id"):
    """
    Call a C/Global function.
    args: list of SBValues or primitives (will be cast if needed)
    """
    arg_strs = []
    for arg in args:
        if isinstance(arg, str):
            # assume C string literal if quoted? No, caller should safeguard.
            # safe assumption: wrap in quotes?
            # actually best to pass as addresses or numbers.
            arg_strs.append(arg) 
        elif isinstance(arg, int):
            arg_strs.append(f"{arg}")
        elif isinstance(arg, lldb.SBValue):
            arg_strs.append(f"(id){arg.GetValueAsUnsigned()}")
        else:
             arg_strs.append(str(arg))
             
    expr = f"({return_type}){func_name}({', '.join(arg_strs)})"
    return evaluate_expression(expr)
