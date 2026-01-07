#!/usr/bin/env python3
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
    print(" " * indent + f"{key:<15}: {value}")


def print_list(items, label=None, max_items=5, indent=2):
    if label:
        print(" " * indent + f"{label} (count={len(items)}):")
    for item in items[:max_items]:
        print(" " * (indent + 2) + str(item))
    if len(items) > max_items:
        print(" " * (indent + 2) + f"... ({len(items) - max_items} more)")


def test_all(ghidra_path, binary_path):
    banner("GhidraManager Analysis Report")

    # 1. Initialize
    section("1. Initialization")
    mgr = GhidraManager(ghidra_path)
    print("  PyGhidra initialized")

    # 2. Analyze
    section("2. Binary Analysis")
    program = mgr.analyze_binary(binary_path)
    assert_true(program is not None, "Program is None")

    print_kv("Binary", binary_path)
    print_kv("Name", program.getName())
    print_kv("Format", program.getExecutableFormat())
    print_kv("Path", program.getExecutablePath())

    # 3. Program context
    section("3. Program Context")
    prog = mgr.get_program()
    assert_true(prog == program, "get_program mismatch")

    base = mgr.get_image_base()
    print_kv("Image Base", hex(base))

    # 4. Language
    section("4. Language")
    lang = mgr.get_language()
    assert_true(lang is not None, "Language missing")

    for k, v in lang.items():
        print_kv(k, v)

    # 5. Functions
    section("5. Functions")
    funcs = mgr.get_functions()
    assert_true(len(funcs) > 0, "No functions found")

    print_kv("Total functions", len(funcs))
    print_list(
        [f"{f.getName()} @ {f.getEntryPoint()}" for f in funcs],
        label="Sample functions"
    )

    f0 = funcs[0]
    addr0 = f0.getEntryPoint().getOffset()
    assert_true(
        mgr.get_function_by_address(addr0) == f0,
        "Function lookup by address failed"
    )

    # 6. CFG
    section("6. Control Flow Graph (CFG)")
    cfg = mgr.get_cfg(addr0)
    assert_true(cfg is not None, "CFG is None")

    print_kv("CFG nodes", len(cfg["nodes"]))
    print_kv("CFG edges", len(cfg["edges"]))

    print_list(cfg["nodes"], label="CFG nodes")
    print_list(cfg["edges"], label="CFG edges")

    # 7. Call graph
    section("7. Call Graph")
    cg = mgr.get_call_graph()
    assert_true(cg is not None, "Call graph is None")
    assert_true(len(cg["nodes"]) == len(funcs), "Call graph node count mismatch")

    print_kv("Call graph nodes", len(cg["nodes"]))
    print_kv("Call graph edges", len(cg["edges"]))

    print_list(
        [f"{addr} -> {name}" for addr, name in cg["nodes"].items()],
        label="Functions"
    )
    print_list(cg["edges"], label="Call edges")

    # 8. Strings
    section("8. Strings")
    strings = mgr.get_strings(min_length=5)
    assert_true(len(strings) > 0, "No strings found")

    print_kv("Strings found", len(strings))
    print_list(
        [f"{s['address']}: {s['value']}" for s in strings],
        label="Sample strings"
    )

    # 9. Imports
    section("9. Imports")
    imports = mgr.get_imports()
    print_kv("Imports found", len(imports))

    if imports:
        print_list(
            [f"{i['name']} @ {i['address']}" for i in imports],
            label="Sample imports"
        )

    # 10. Annotations
    section("10. Annotations")

    # Add annotations
    assert_true(mgr.add_comment(base, "test comment"), "Failed to add comment")
    assert_true(mgr.add_function_tag(addr0, "test_tag"), "Failed to add function tag")
    # Add a bookmark
    assert_true(
        mgr.add_bookmark(base, "Analysis", "Entry point reviewed"),
        "Failed to add bookmark"
    )

    # Read bookmarks at address
    bookmarks = mgr.get_bookmarks_at(base)


    # Read back comments
    comments = mgr.get_comments_at(base)
    print("  Address comments:")
    if comments:
        for ctype, text in comments.items():
            print(f"    [{ctype}] {text}")
    else:
        print("    (none)")

    # Read back function annotations
    func_ann = mgr.get_function_annotations(addr0)
    assert_true(func_ann is not None, "Failed to read function annotations")

    print("  Function annotations:")
    print(f"    Name   : {func_ann['name']}")
    print(f"    Entry  : {func_ann['entry']}")
    print(f"    Comment: {func_ann['comment']}")
    print(f"    Tags   : {func_ann['tags']}")

    print("  Bookmarks at address:")
    if bookmarks:
        for b in bookmarks:
            print(f"    [{b['type']}/{b['category']}] {b['comment']} @ {b['address']}")
    else:
        print("    (none)")

    # 11. Close
    section("11. Cleanup")
    mgr.close_program()
    assert_true(mgr.get_program() is None, "Program not cleared on close")
    print("  Program closed cleanly")

    banner("ALL TESTS PASSED")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python test_ghidra_manager.py <ghidra_dir> <binary>")
        sys.exit(1)

    test_all(sys.argv[1], sys.argv[2])
