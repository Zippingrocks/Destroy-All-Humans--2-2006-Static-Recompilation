"""Capture a bounded retail callback sequence immediately after the first loader."""
from __future__ import annotations
import argparse, json, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
from parity_boot_trace import ControlGDB, ControlQMP, ProbeError, stamp, wait_stopped
from trace_xemu_loader_calls import active_proto
LOADER_ENTRY = 0x001A8EB0
DISPATCH_CALL = 0x002117F9
DISPATCH_RETURN = 0x002117FD

def u32(gdb, address):
    return int.from_bytes(gdb.memory(address, 4), "little")

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--qmp-port", required=True, type=int)
    p.add_argument("--gdb-port", required=True, type=int)
    p.add_argument("--count", type=int, default=32)
    p.add_argument("--timeout", type=float, default=180.0)
    p.add_argument("--reset", action="store_true")
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    if a.output.exists(): p.error("output must be new")
    result = {"schema":"dah2-xemu-callbacks-after-loader-v1", "started":stamp(),
              "callbacks":[], "cleanup":{"breakpoints_remaining":[], "resumed":False}}
    q = ControlQMP(a.qmp_port, 5); g = None; active = set()
    deadline = time.monotonic() + a.timeout
    def bp(address, install):
        if install: active.add(address)
        g.breakpoint(address, install)
        if not install: active.discard(address)
        result["cleanup"]["breakpoints_remaining"] = [f"0x{x:08x}" for x in sorted(active)]
    try:
        q.execute("stop"); wait_stopped(q, 5, 0.02)
        if a.reset:
            q.execute("system_reset"); q.execute("stop"); wait_stopped(q, 5, 0.02)
        g = ControlGDB(a.gdb_port, 5)
        result["initial_stop"] = g.request("?").decode(errors="replace")
        bp(LOADER_ENTRY, True); q.execute("cont")
        wait_stopped(q, max(0.1, deadline-time.monotonic()), 0.02)
        regs = g.registers()["i386"]
        if int(regs["eip"],16) != LOADER_ENTRY: raise ProbeError(f"stopped before loader at {regs['eip']}")
        state = int(regs["ecx"],16)
        result["first_loader"] = {"registers":regs,
            "state_words":[f"0x{u32(g,state+i*4):08x}" for i in range(16)]}
        bp(LOADER_ENTRY, False); bp(DISPATCH_CALL, True)
        for ordinal in range(1, a.count+1):
            q.execute("cont"); wait_stopped(q, max(0.1, deadline-time.monotonic()), 0.02)
            regs = g.registers()["i386"]
            if int(regs["eip"],16) != DISPATCH_CALL: raise ProbeError(f"unexpected stop at {regs['eip']}")
            ebx=int(regs["ebx"],16); state=int(regs["esi"],16); esp=int(regs["esp"],16)
            d=g.memory(ebx,16)
            stack_bytes=g.memory(esp,0x100)
            top=u32(g,state)
            row = {"ordinal_after_loader":ordinal,
                "target":f"0x{int.from_bytes(d[0:4],'little'):08x}",
                "outer_return":f"0x{u32(g,esp+8):08x}", "state":f"0x{state:08x}",
                "top":f"0x{u32(g,state):08x}", "base":f"0x{u32(g,state+4):08x}",
                "capacity":f"0x{u32(g,state+8):08x}", "descriptor":f"0x{ebx:08x}",
"argc":int.from_bytes(d[14:16],"little",signed=True),
                "stack_words":[f"0x{int.from_bytes(stack_bytes[i:i+4],'little'):08x}" for i in range(0,0x100,4)],
                "proto_candidates":active_proto(g,stack_bytes),
                "state_words":[f"0x{u32(g,state+i*4):08x}" for i in range(32)],
                "lua_stack_near_top":[f"0x{u32(g,top-0x40+i*4):08x}" for i in range(32)]}
            row["lua_stack_below_top"] = [
                f"0x{u32(g, top - 0x80 + i * 4):08x}" for i in range(32)
            ]
            result["callbacks"].append(row)
            a.output.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
            bp(DISPATCH_CALL, False); bp(DISPATCH_RETURN, True)
            q.execute("cont"); wait_stopped(q, max(0.1, deadline-time.monotonic()), 0.02)
            ret = g.registers()["i386"]
            if int(ret["eip"],16) != DISPATCH_RETURN: raise ProbeError(f"unexpected return stop at {ret['eip']}")
            row["return_eax"] = ret["eax"]
            row["return_ecx"] = ret["ecx"]
            row["return_edx"] = ret["edx"]
            row["top_after"] = f"0x{u32(g,state):08x}"
            bp(DISPATCH_RETURN, False); bp(DISPATCH_CALL, True)
            if int(row["target"], 16) == LOADER_ENTRY:
                result["second_loader_ordinal_after_first"] = ordinal
                break
    finally:
        try: q.execute("stop"); wait_stopped(q,5,0.02)
        except Exception as exc: result["cleanup"].setdefault("errors",[]).append(f"stop: {exc}")
        if g:
            for address in list(active):
                try: bp(address,False)
                except Exception as exc: result["cleanup"].setdefault("errors",[]).append(str(exc))
        try: q.execute("cont"); result["cleanup"]["resumed"]=True
        except Exception as exc: result["cleanup"]["resume_error"]=str(exc)
        result["finished"]=stamp(); a.output.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
        if g: g.close()
        q.close()
    print(json.dumps({"callbacks":len(result["callbacks"]),"cleanup":result["cleanup"]}))
if __name__ == "__main__": main()
