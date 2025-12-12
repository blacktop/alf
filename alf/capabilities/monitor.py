"""
Function monitoring and return value fuzzing via LLDB breakpoints.

Derived from Hilda (https://github.com/doronz88/hilda)
Copyright (c) 2012-2023 Doron Zarhi and Metan Perelman
Licensed under MIT License
"""

import lldb
import sys

active_monitors = {}

def monitor_callback(frame, bp_loc, internal_dict):
    bp_id = bp_loc.GetBreakpoint().GetID()
    config = active_monitors.get(bp_id)
    
    if not config:
        return False
        
    symbol = config.get('name', 'Unknown')
    thread = frame.GetThread()
    
    # Log entry
    msg = f"[Monitor] Hit {symbol} (Thread {thread.GetIndexID()})"
    
    # Print Registers
    regs_config = config.get('regs', {})
    if regs_config:
        for reg_name in regs_config:
            reg_val = frame.FindRegister(reg_name)
            if reg_val.IsValid():
                # Format? For now just hex
                msg += f"\n  {reg_name} = 0x{reg_val.GetValueAsUnsigned():x}"
    
    print(msg)
    
    # Handle Return Value
    if config.get('retval'):
        target = lldb.debugger.GetSelectedTarget()
        debugger = target.GetDebugger()
        
        # Switch to sync mode for stepping
        old_async = debugger.GetAsync()
        debugger.SetAsync(False)
        
        try:
            # Step Out
            thread.StepOutOfFrame(frame)
            
            # Now we are in the caller frame, but the return value is in x0 (arm64) or rax (x64)
            # We need to read the register from the CURRENT frame (caller) ? 
            # OR the return value is typically in x0 after the call instruction completes.
            # Upon return, the PC is at the instruction after BL.
            # The register state reflects the return value.
            
            # Check architecture
            arch = target.GetTriple().split('-')[0]
            ret_reg = 'x0' if 'arm64' in arch else 'rax'
            
            val = thread.GetSelectedFrame().FindRegister(ret_reg)
            print(f"  [Return] {symbol} => 0x{val.GetValueAsUnsigned():x}")
            
        except Exception as e:
            print(f"  [Return Error] {e}")
        finally:
            debugger.SetAsync(old_async)
            # We must NOT return False here if we want to continue?
            # Wait, if we stepped, we are stopped at the return address.
            # If we return False from callback, LLDB *resumes*.
            # This is exactly what we want.
            
    return False # Continue execution

def monitor_address(symbol_name, regs=None, retval=False):
    """
    Monitor a function by name.
    regs: list of registers to print on entry (e.g. ['x0', 'x1'])
    retval: boolean, whether to print return value (requires stepping)
    """
    target = lldb.debugger.GetSelectedTarget()
    if not target.IsValid():
        print("Error: No target.")
        return

    bp = target.BreakpointCreateByName(symbol_name)
    bp.SetScriptCallbackFunction("alf.capabilities.monitor.monitor_callback")
    
    active_monitors[bp.GetID()] = {
        'name': symbol_name,
        'regs': regs or [],
        'retval': retval
    }
    print(f"Monitoring '{symbol_name}' established (BP #{bp.GetID()}).")

def fuzz_return(symbol_name, value):
    """
    Force a return value for a function.
    """
    target = lldb.debugger.GetSelectedTarget()
    bp = target.BreakpointCreateByName(symbol_name)
    
    # We define a specialized callback for this
    # Or reuse monitor callback with 'force_return' config?
    # Let's reuse.
    
    def force_return_callback(frame, bp_loc, d):
        thread = frame.GetThread()
        # ReturnFromFrame(frame, value)
        # We need an SBValue for value.
        # SBThread.ReturnFromFrame(SBFrame, SBValue)
        
        # Creating SBValue is hard from python script without context.
        # Alternative: StepOut + Write Register.
        
        target = lldb.debugger.GetSelectedTarget()
        debugger = target.GetDebugger()
        debugger.SetAsync(False)
        thread.StepOutOfFrame(frame)
        debugger.SetAsync(True)
        
        # Write x0
        val_int = int(value)
        frame = thread.GetSelectedFrame()
        reg = frame.FindRegister("x0")
        error = lldb.SBError()
        reg.SetValueFromCString(str(val_int), error)
        
        return False
        
    # Python API allows function object if we register it?
    # No, SetScriptCallbackFunction takes a NAME string.
    # We must definte it in the module scope.
    pass

# We need to implement force_return logic properly if requested.
# For now, monitor_address is the main feature.
