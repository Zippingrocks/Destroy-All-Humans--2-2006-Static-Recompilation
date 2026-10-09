"""Trace retail Lua VM steps after post-loader callback 6.

The probe is bounded, uses only the supplied private QMP/GDB ports, removes
every breakpoint, and resumes the guest during cleanup.
"""
from __future__ import annotations
import argparse, json, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from parity_boot_trace import ControlGDB, ControlQMP, ProbeError, memory_record, stamp, wait_stopped
from trace_xemu_loader_calls import active_proto
from trace_xemu_vm_handoff import StepGDB

LOADER_ENTRY=0x001A8EB0
DISPATCH_CALL=0x002117F9
DISPATCH_RETURN=0x002117FD
VM_DISPATCH=0x00218DF1

def u32(gdb,address):
    return int.from_bytes(gdb.memory(address,4),"little")

def vm_row(gdb,ordinal):
    regs=gdb.registers()["i386"]; sp=int(regs["esp"],16)
    stack=gdb.memory(sp,0x100); pc=u32(gdb,sp+0x10); top=int(regs["ebp"],16)
    return {"ordinal":ordinal,"registers":regs,"stack":memory_record(gdb,sp,0x100),
            "pc":f"0x{pc:08x}","opcode":f"0x{u32(gdb,pc):08x}","top":f"0x{top:08x}",
            "operands":memory_record(gdb,top-0x20,0x40),
            "proto_candidates":active_proto(gdb,stack)}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--qmp-port",required=True,type=int); p.add_argument("--gdb-port",required=True,type=int)
    p.add_argument("--steps",type=int,default=128); p.add_argument("--timeout",type=float,default=180.0)
    p.add_argument("--output",required=True,type=Path); a=p.parse_args()
    if a.output.exists(): p.error("output must be new")
    result={"schema":"dah2-xemu-vm-after-loader-callback6-v1","started":stamp(),
            "callbacks":[],"vm_steps":[],"cleanup":{"breakpoints_remaining":[],"resumed":False}}
    q=ControlQMP(a.qmp_port,5); g=None; active=set(); deadline=time.monotonic()+a.timeout
    def bp(address,install):
        g.breakpoint(address,install)
        if install: active.add(address)
        else: active.discard(address)
        result["cleanup"]["breakpoints_remaining"]=[f"0x{x:08x}" for x in sorted(active)]
    def run():
        q.execute("cont"); wait_stopped(q,max(0.1,deadline-time.monotonic()),0.01)
        return g.registers()["i386"]
    try:
        q.execute("stop"); wait_stopped(q,5,0.01)
        q.execute("system_reset"); q.execute("stop"); wait_stopped(q,5,0.01)
        g=StepGDB(a.gdb_port,5); result["initial_stop"]=g.request("?").decode(errors="replace")
        bp(LOADER_ENTRY,True); regs=run()
        if int(regs["eip"],16)!=LOADER_ENTRY: raise ProbeError(f"expected loader, stopped at {regs['eip']}")
        result["loader"]={"registers":regs}; bp(LOADER_ENTRY,False); bp(DISPATCH_CALL,True)
        for ordinal in range(1,7):
            regs=run()
            if int(regs["eip"],16)!=DISPATCH_CALL: raise ProbeError(f"expected callback {ordinal}, stopped at {regs['eip']}")
            ebx=int(regs["ebx"],16); sp=int(regs["esp"],16); stack=g.memory(sp,0x100)
            row={"ordinal":ordinal,"target":f"0x{u32(g,ebx):08x}","registers":regs,
                 "stack":memory_record(g,sp,0x100),"proto_candidates":active_proto(g,stack)}
            result["callbacks"].append(row); bp(DISPATCH_CALL,False); bp(DISPATCH_RETURN,True)
            returned=run()
            if int(returned["eip"],16)!=DISPATCH_RETURN: raise ProbeError(f"expected callback return, stopped at {returned['eip']}")
            row["return_registers"]=returned; bp(DISPATCH_RETURN,False)
            if ordinal!=6: bp(DISPATCH_CALL,True)
        bp(DISPATCH_CALL,True); bp(VM_DISPATCH,True)
        for ordinal in range(1,a.steps+1):
            regs=run(); eip=int(regs["eip"],16)
            if eip==DISPATCH_CALL:
                sp=int(regs["esp"],16); ebx=int(regs["ebx"],16); stack=g.memory(sp,0x100)
                result["next_callback"]={"target":f"0x{u32(g,ebx):08x}","registers":regs,
                    "stack":memory_record(g,sp,0x100),"proto_candidates":active_proto(g,stack)}
                break
            if eip!=VM_DISPATCH: raise ProbeError(f"unexpected stop at 0x{eip:08x}")
            result["vm_steps"].append(vm_row(g,ordinal))
            a.output.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
            bp(VM_DISPATCH,False); g.step(); bp(VM_DISPATCH,True)
        else: result["step_limit_reached"]=True
    finally:
        try: q.execute("stop"); wait_stopped(q,5,0.01)
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
    print(json.dumps({"callbacks":len(result["callbacks"]),"vm_steps":len(result["vm_steps"]),
        "next_callback":result.get("next_callback",{}).get("target"),"cleanup":result["cleanup"]}))
if __name__=="__main__": main()
