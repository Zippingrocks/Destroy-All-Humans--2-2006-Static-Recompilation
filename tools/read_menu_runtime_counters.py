"""Read bounded DAH2 menu loader/traversal counters from a private recomp."""
from __future__ import annotations
import argparse
import json
import struct
from pathlib import Path
from read_parity_state_ring import Reader, symbol_rva
SCALARS = (
    "g_dah2_object_loader_calls", "g_dah2_handle_alloc_calls",
    "g_dah2_resource_method_a5d30_calls",
    "g_dah2_callback_1044c0_calls",
    "g_dah2_dispatch_1040b0_calls",
    "g_dah2_script_callback_calls",
    "g_dah2_postloader_stack_calls",
    "g_dah2_vm_after_callback6_calls",
    "g_dah2_vm_native_trace_calls",
    "g_dah2_return_landmark_calls",
    "g_dah2_scheduler_queue_trace_calls",
    "g_dah2_dispatch_queue_trace_calls",
    "g_dah2_166b50_trace_calls",
    "g_dah2_dispatch_event_trace_calls",
    "g_dah2_completion_trace_calls",
    "g_dah2_input_shell_parent_reentries",
    "g_dah2_menu_world_calls", "g_dah2_menu_query_calls",
    "g_dah2_menu_query_last_count", "g_dah2_menu_query_max_count",
    "g_dah2_scene_query_result_count", "g_dah2_scene_query_manager_blocks",
    "g_dah2_scene_query_scratch_address", "g_dah2_menu_candidate_calls",
    "g_dah2_menu_object_dispatch_calls", "g_dah2_menu_last_world",
    "g_dah2_menu_last_query",
    "g_dah2_title_update_calls", "g_dah2_title_ready_commits",
    "g_dah2_title_remove_calls", "g_dah2_title_remove_matches",
    "g_dah2_title_remove_count_before", "g_dah2_title_remove_count_after",
    "g_dah2_title_append_calls", "g_dah2_title_append_rejected",
    "g_dah2_title_append_count_before", "g_dah2_title_append_count_after",
    "g_dah2_title_append_successes",
)
ARRAYS = {
    "g_dah2_object_loader_ecx": 128,
    "g_dah2_object_loader_arg1": 128,
    "g_dah2_object_loader_return": 128,
    "g_dah2_object_loader_trace": 128 * 48,
    "g_dah2_script_callback_trace": 8192 * 12,
    "g_dah2_object_loader_callback_ordinals": 128,
    "g_dah2_object_loader_state_after": 128 * 16,
    "g_dah2_object_loader_stack_after": 128 * 32,
    "g_dah2_postloader_stack_esp": 512,
    "g_dah2_postloader_stack_target": 512,
    "g_dah2_postloader_present_trace": 512,
    "g_dah2_postloader_stack_trace": 512 * 256,
    "g_dah2_postloader_proto_trace": 512 * 8,
    "g_dah2_postloader_source_words": 512 * 32,
    "g_dah2_postloader_lua_stack_trace": 512 * 32,
    "g_dah2_postloader_lua_below_top_trace": 512 * 32,
    "g_dah2_vm_after_callback6_trace": 2048 * 16,
    "g_dah2_vm_native_trace": 8192 * 12,
    "g_dah2_return_landmark_trace": 128 * 9,
    "g_dah2_scheduler_queue_trace": 2048 * 24,
    "g_dah2_dispatch_queue_trace": 1024 * 24,
    "g_dah2_166b50_trace": 256 * 20,
    "g_dah2_166b50_object_words": 64,
    "g_dah2_dispatch_event_trace": 256 * 20,
    "g_dah2_completion_trace": 256 * 16,
    "g_dah2_handle_alloc_callsites": 128,
    "g_dah2_handle_alloc_results": 128,
    "g_dah2_resource_method_a5d30_trace": 128 * 20,
    "g_dah2_callback_1044c0_trace": 64 * 40,
    "g_dah2_dispatch_1040b0_trace": 128 * 32,
    "g_dah2_scene_query_scratch_words": 4,
    "g_dah2_menu_candidate_nodes": 64,
    "g_dah2_menu_candidate_flags": 64,
    "g_dah2_menu_candidate_objects": 64,
    "g_dah2_menu_candidate_vtables": 64,
    "g_dah2_title_append_surfaces": 32,
    "g_dah2_title_append_sizes": 32,
    "g_dah2_title_append_callsites": 32,
    "g_dah2_title_remove_surfaces": 32,
    "g_dah2_title_remove_callsites": 32,
}
def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", required=True, type=int)
    parser.add_argument("--map", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    reader = Reader(args.pid)
    try:
        def read_symbol(name: str, size: int) -> bytes:
            return reader.read(reader.base + symbol_rva(args.map, name), size)
        scalars = {name: struct.unpack("<I", read_symbol(name, 4))[0] for name in SCALARS}
        arrays = {name: [f"{value:08X}" for value in struct.unpack(f"<{count}I", read_symbol(name, count * 4))] for name, count in ARRAYS.items()}
        module_base = reader.base
    finally:
        reader.close()
    result = {"schema": "dah2-menu-runtime-counters-v1", "pid": args.pid,
              "moduleBase": f"0x{module_base:x}", "scalars": scalars,
              "arrays": arrays}
    encoded = json.dumps(result, indent=2) + "\n"
    if args.output:
        if args.output.exists():
            raise SystemExit(f"refusing to overwrite {args.output}")
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
if __name__ == "__main__":
    main()