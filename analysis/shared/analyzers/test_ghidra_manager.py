#!/usr/bin/env python3
"""
Test script for GhidraManager - tests only the available methods.

Available methods in GhidraManager:
- __init__(install_dir)
- open_project(project_path, project_name, create)
- analyze_binary(binary_path, analyze)
- close_program()
- normalize_address(address)
- address_exists(address)
- get_functions()
- get_function_by_address(function_address)
- open_decompiler()
- decompile_function(function_address, timeout)
- close_decompiler()
- get_cfg(function_address)
- get_call_graph()

Usage: python test_ghidra_manager.py <binary>
  - GHIDRA_INSTALL_DIR must be set as env var
"""
import sys
from ghidra_manager import GhidraManager


def assert_true(cond, msg):
    if not cond:
        raise AssertionError(msg)


def banner(title):
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)


def section(title):
    print(f"\n[{title}]")


def print_kv(key, value, indent=2):
    print(" " * indent + f"{key:<20}: {value}")


def print_list(items, label=None, max_items=5, indent=2):
    if label:
        print(" " * indent + f"{label} (count={len(items)}):")
    for item in items[:max_items]:
        print(" " * (indent + 2) + str(item))
    if len(items) > max_items:
        print(" " * (indent + 2) + f"... ({len(items) - max_items} more)")


def test_all(ghidra_path, binary_path):
    banner("GhidraManager Analysis Report")

    # 1. Initialize (uses GHIDRA_INSTALL_DIR env var if ghidra_path is None)
    section("1. Initialization")
    mgr = GhidraManager(ghidra_path)  # Will use env var if None
    print("  PyGhidra initialized successfully")

    # 2. Analyze Binary
    section("2. Binary Analysis")
    program = mgr.analyze_binary(binary_path)
    assert_true(program is not None, "Program is None")
    assert_true(mgr.current_program is not None, "current_program not set")

    print_kv("Binary", binary_path)
    print_kv("Name", program.getName())
    print_kv("Format", program.getExecutableFormat())
    print_kv("Path", program.getExecutablePath())

    # 3. Get Functions
    section("3. Functions")
    funcs = mgr.get_functions()
    assert_true(len(funcs) > 0, "No functions found")

    print_kv("Total functions", len(funcs))
    print_list(
        [f"{f.getName()} @ {f.getEntryPoint()}" for f in funcs],
        label="Sample functions"
    )

    # 4. Get Function by Address
    section("4. Function Lookup by Address")
    f0 = funcs[0]
    addr0 = f0.getEntryPoint().getOffset()
    found_func = mgr.get_function_by_address(addr0)
    assert_true(found_func == f0, "Function lookup by address failed")
    print_kv("Lookup address", hex(addr0))
    print_kv("Found function", found_func.getName())

    # 5. Address Utilities
    section("5. Address Utilities")
    norm_addr = mgr.normalize_address(addr0)
    assert_true(norm_addr is not None, "normalize_address failed")
    print_kv("Normalized address", str(norm_addr))

    exists = mgr.address_exists(addr0)
    assert_true(exists, "address_exists returned False for valid address")
    print_kv("Address exists", exists)

    # 6. Control Flow Graph (CFG)
    section("6. Control Flow Graph (CFG)")
    cfg = mgr.get_cfg(addr0)
    assert_true(cfg is not None, "CFG is None")

    print_kv("CFG nodes", len(cfg["nodes"]))
    print_kv("CFG edges", len(cfg["edges"]))
    print_list(cfg["nodes"], label="CFG nodes")
    print_list(cfg["edges"], label="CFG edges")

    # 7. Call Graph
    section("7. Call Graph")
    cg = mgr.get_call_graph()
    assert_true(cg is not None, "Call graph is None")
    assert_true(len(cg["nodes"]) == len(funcs), "Call graph node count mismatch")

    print_kv("Call graph nodes", len(cg["nodes"]))
    print_kv("Call graph edges", len(cg["edges"]))
    print_list(
        [f"{addr} -> {name}" for addr, name in list(cg["nodes"].items())[:10]],
        label="Functions (first 10)"
    )
    print_list(cg["edges"][:10], label="Call edges (first 10)")

    # 8. Decompiler
    section("8. Decompiler")
    decompiled = mgr.decompile_function(addr0)
    if decompiled:
        print_kv("Decompiled function", f0.getName())
        print_kv("Code length", f"{len(decompiled)} chars")
        print("  Code preview:")
        for line in decompiled.split('\n')[:10]:
            print(f"    {line}")
        if decompiled.count('\n') > 10:
            print(f"    ... ({decompiled.count(chr(10)) - 10} more lines)")
    else:
        print("  Decompilation returned None (may be expected for some functions)")

    mgr.close_decompiler()
    print("  Decompiler closed")

    # 9. Cleanup
    section("9. Cleanup")
    mgr.close_program()
    assert_true(mgr.current_program is None, "Program not cleared on close")
    print("  Program closed cleanly")

    banner("ALL TESTS PASSED")


if __name__ == "__main__":
    import os

    if len(sys.argv) < 2:
        print("Usage: python test_ghidra_manager.py <binary> [ghidra_dir]")
        print("Example: python test_ghidra_manager.py /bin/ls")
        print("Example: python test_ghidra_manager.py /bin/ls /path/to/ghidra")
        print("Note: If ghidra_dir not provided, uses GHIDRA_INSTALL_DIR env var")
        sys.exit(1)

    binary = sys.argv[1]
    ghidra = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("GHIDRA_INSTALL_DIR")

    if not ghidra:
        print("Error: GHIDRA_INSTALL_DIR not set and no ghidra_dir argument provided")
        sys.exit(1)

    test_all(ghidra, binary)
