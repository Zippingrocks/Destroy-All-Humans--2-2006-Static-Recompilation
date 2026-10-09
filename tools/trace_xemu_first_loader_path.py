"""Capture the retail first object-loader branch key and dispatch return."""
from __future__ import annotations
import argparse, json, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
from parity_boot_trace import ControlGDB, ControlQMP, ProbeError, memory_record, stamp, wait_stopped
ENTRY = 0x001A8EB0
BRANCH_KEY = 0x001A8ED3
DISPATCH_RETURN = 0x002117FD

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--qmp-port",required=True,type=int); p.add_argument("--gdb-port",required=True,type=int)
    p.add_argument("--timeout",type=float,default=180.0); p.add_argument("--reset",action="store_true")
    p.add_argument("--output",required=True,type=Path); a=p.parse_args()
    if a.output.exists(): p.error("output must be new")
    result={"schema":"dah2-xemu-first-loader-path-v1","started":stamp(),"cleanup":{"breakpoints_remaining":[],"resumed":False}}
    q=ControlQMP(a.qmp_port,5); g=None; active=set(); deadline=time.monotonic()+a.timeout
    def bp(address,install):
        if install: active.add(address)
        g.breakpoint(address,install)
        if not install: active.discard(address)
        result["cleanup"]["breakpoints_remaining"]=[f"0x{x:08x}" for x in sorted(active)]
    def capture(name):
        regs=g.registers()["i386"]; esp=int(regs["esp"],16); ecx=int(regs["ecx"],16); esi=int(regs["esi"],16)
        row={"registers":regs,"stack":memory_record(g,esp,0x100)}
        if 0x80000000 <= ecx < 0x90000000: row["ecx_memory"]=memory_record(g,ecx,0x80)
        if 0x80000000 <= esi < 0x90000000:
            row["esi_memory"]=memory_record(g,esi,0x80)
            top=int.from_bytes(g.memory(esi,4),"little")
            if 0x80000040 <= top < 0x90000000: row["lua_stack_near_top"]=memory_record(g,top-0x40,0x80)
        result[name]=row; a.output.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8"); return regs
    try:
        q.execute("stop"); wait_stopped(q,5,0.02)
        if a.reset: q.execute("system_reset"); q.execute("stop"); wait_stopped(q,5,0.02)
        g=ControlGDB(a.gdb_port,5); result["initial_stop"]=g.request("?").decode(errors="replace")
        bp(ENTRY,True); q.execute("cont"); wait_stopped(q,max(0.1,deadline-time.monotonic()),0.02)
        regs=capture("entry")
        if int(regs["eip"],16)!=ENTRY: raise ProbeError(f"unexpected entry stop {regs['eip']}")
        bp(ENTRY,False); bp(BRANCH_KEY,True); q.execute("cont"); wait_stopped(q,max(0.1,deadline-time.monotonic()),0.02)
        regs=capture("branch_key")
        if int(regs["eip"],16)!=BRANCH_KEY: raise ProbeError(f"unexpected key stop {regs['eip']}")
        bp(BRANCH_KEY,False); bp(DISPATCH_RETURN,True); q.execute("cont"); wait_stopped(q,max(0.1,deadline-time.monotonic()),0.02)
        regs=capture("dispatch_return")
        if int(regs["eip"],16)!=DISPATCH_RETURN: raise ProbeError(f"unexpected return stop {regs['eip']}")
        result["post_loader_fixed"]={
            "generation":memory_record(g,0x002EC144,0x10),
            "handle_table":memory_record(g,0x0031FF10,0xD4),
            "manager_global":memory_record(g,0x002EC1C4,4),
        }
        slot_object=int.from_bytes(g.memory(0x0031FF24,4),"little")
        result["post_loader_fixed"]["slot_object_address"]=f"0x{slot_object:08x}"
        result["post_loader_fixed"]["slot_object"]=memory_record(g,slot_object,0x400)
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
    print(json.dumps({"event_id":result["branch_key"]["registers"]["edi"],"return_eax":result["dispatch_return"]["registers"]["eax"],"cleanup":result["cleanup"]}))
if __name__=="__main__": main()
