"""Capture retail model-build arguments on the dedicated xemu without reset."""
import argparse, json, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
from parity_boot_trace import ControlQMP, ProbeError, memory_record, stamp, wait_stopped
from trace_xemu_vm_handoff import StepGDB

TARGET = 0x001BC540
def word(data, offset=0): return int.from_bytes(data[offset:offset+4], "little")
def valid(p): return 0x10000 <= p < 0x04000000 or 0x80000000 <= p < 0x88000000

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--qmp-port",type=int,required=True); ap.add_argument("--gdb-port",type=int,required=True)
    ap.add_argument("--output",type=Path,required=True); ap.add_argument("--count",type=int,default=24); ap.add_argument("--timeout",type=float,default=60)
    a=ap.parse_args();
    if a.output.exists(): ap.error("output must be new")
    result={"schema":"dah2-retail-model-build-v1","started":stamp(),"calls":[],"cleanup":{"breakpoint_removed":False,"resumed":False}}
    q=ControlQMP(a.qmp_port,5); g=None; installed=False; deadline=time.monotonic()+a.timeout
    try:
        q.execute("stop"); wait_stopped(q,5,0.01); g=StepGDB(a.gdb_port,5); result["initial_stop"]=g.request("?").decode(errors="replace")
        g.breakpoint(TARGET,True); installed=True
        while len(result["calls"])<a.count and time.monotonic()<deadline:
            q.execute("cont"); wait_stopped(q,max(0.1,deadline-time.monotonic()),0.01)
            regs=g.registers()["i386"]; eip=int(regs["eip"],16); esp=int(regs["esp"],16)
            if eip!=TARGET: raise ProbeError(f"unexpected stop at 0x{eip:08x}")
            stack=g.memory(esp,0x30); ref=word(stack,4); descriptor=word(g.memory(ref,4)) if valid(ref) else 0
            call={"captured":stamp(),"registers":regs,"stack":memory_record(g,esp,0x30),"descriptor_ref":f"0x{ref:08x}","descriptor":f"0x{descriptor:08x}"}
            if valid(descriptor): call["descriptor_memory"]=memory_record(g,descriptor,0x60)
            owner=int(regs["ecx"],16); call["owner"]=f"0x{owner:08x}"
            if valid(owner):
                call["owner_memory"]=memory_record(g,owner,0x240)
                nested=word(g.memory(owner+0x88,4)); call["owner_88"]=f"0x{nested:08x}"
                if valid(nested): call["owner_88_memory"]=memory_record(g,nested,0x20)
            result["calls"].append(call); a.output.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8"); g.step()
        if not result["calls"]: raise ProbeError("no model-build calls")
    except Exception as exc: result["error"]=f"{type(exc).__name__}: {exc}"
    finally:
        try: q.execute("stop"); wait_stopped(q,5,0.01)
        except Exception as exc: result["cleanup"].setdefault("errors",[]).append(str(exc))
        if g and installed:
            try: g.breakpoint(TARGET,False); result["cleanup"]["breakpoint_removed"]=True
            except Exception as exc: result["cleanup"].setdefault("errors",[]).append(str(exc))
        try: q.execute("cont"); result["cleanup"]["resumed"]=True
        except Exception as exc: result["cleanup"]["resume_error"]=str(exc)
        result["finished"]=stamp(); a.output.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
        if g:g.close()
        q.close()
    print(json.dumps({"calls":len(result["calls"]),"error":result.get("error"),"cleanup":result["cleanup"]}))
if __name__=="__main__": main()
