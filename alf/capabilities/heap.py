"""
Heap analysis utilities via LLDB expression evaluation.

Derived from Hilda (https://github.com/doronz88/hilda)
Copyright (c) 2012-2023 Doron Zarhi and Metan Perelman
Licensed under MIT License
"""

import lldb
from .objchelpers import evaluate_expression


def inspect_heap(verbose=True):
    """
    Print heap zone information to the process stdout/stderr.
    Useful for seeing memory layout and statistics.
    """
    print("[Heap] Inspecting default zone...")
    verbose_int = 1 if verbose else 0
    # We use extern declarations to ensure LLDB knows the signatures
    code = f"""
    extern void* malloc_default_zone(void);
    extern void malloc_zone_print(void*, int);
    void *zone = (void*)malloc_default_zone();
    if (zone) {{
        malloc_zone_print(zone, {verbose_int});
    }}
    """
    try:
        evaluate_expression(code)
        print("[Heap] Command executed. Check debug console/stdout for 'malloc_zone_print' output.")
    except Exception as e:
        print(f"[Heap] Inspection failed: {e}")

def heap_health():
    """
    Run malloc_zone_check on all zones.
    Returns True if healthy, False if corruption detected.
    """
    print("[Heap] Checking consistency...")
    code = """
    extern int malloc_zone_check(void*);
    // passing NULL checks all zones
    malloc_zone_check((void*)0);
    """
    # malloc_zone_check returns 1 if valid, 0 if corrupted?
    # Man page: "Returns 1 if values are consistent, 0 otherwise"
    
    try:
        val = evaluate_expression(code)
        res = val.GetValueAsUnsigned()
        if res == 1:
            print("[Heap] Status: HEALTHY")
            return True
        else:
            print("[Heap] Status: CORRUPTED")
            return False
    except Exception as e:
        print(f"[Heap] Health check failed to run: {e}")
        return False
