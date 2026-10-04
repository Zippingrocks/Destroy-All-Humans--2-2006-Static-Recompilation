"""Capture retail animation-state flags around the render/non-render branch."""
import argparse, json, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
from parity_boot_trace import ControlQMP, ProbeError, memory_record, stamp, wait_stopped
from trace_xemu_vm_handoff import StepGDB

TARGETS = (0x001BDDDC, 0x001BDDE0, 0x001BDDF2, 0x001BDE0F)

def valid(p):
    return 0x10000 <= p < 0x04000000 or 0x80000000 <= p < 0x88000000

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--qmp-port", type=int, required=True)
    ap.add_argument("--gdb-port", type=int, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--count", type=int, default=48)
    ap.add_argument("--timeout", type=float, default=180)
    ap.add_argument("--reset", action="store_true")
    a = ap.parse_args()
    if a.output.exists(): ap.error("output must be new")
    out = {"schema":"dah2-retail-animation-state-slot-v1", "started":stamp(),
           "targets":[f"0x{x:08x}" for x in TARGETS], "stops":[],
           "cleanup":{"breakpoints_removed":False,"resumed":False}}
    qmp = ControlQMP(a.qmp_port, 5); gdb = None; installed = []
    deadline = time.monotonic() + a.timeout
    try:
        if a.reset:
            qmp.execute("system_reset"); time.sleep(.1)
        qmp.execute("stop"); wait_stopped(qmp, 5, .01)
        gdb = StepGDB(a.gdb_port, 5); out["initial_stop"] = gdb.request("?").decode(errors="replace")
        for t in TARGETS: gdb.breakpoint(t, True); installed.append(t)
        while len(out["stops"]) < a.count and time.monotonic() < deadline:
            qmp.execute("cont"); wait_stopped(qmp, max(.1, deadline-time.monotonic()), .01)
            r = gdb.registers()["i386"]; eip=int(r["eip"],16); esp=int(r["esp"],16)
            if eip not in TARGETS: raise ProbeError(f"unexpected stop at 0x{eip:08x}")
            s={"captured":stamp(),"target":f"0x{eip:08x}","registers":r,
               "stack":memory_record(gdb,esp,0x40)}
            for name in ("esi","edi","ebp"):
                p=int(r[name],16)
                if valid(p): s[name+"_memory"]=memory_record(gdb,p,0x90)
            out["stops"].append(s); a.output.write_text(json.dumps(out,indent=2)+"\n",encoding="utf-8")
            gdb.step()
        if not out["stops"]: raise ProbeError("no animation-state stops")
    except Exception as e: out["error"]=f"{type(e).__name__}: {e}"
    finally:
        try: qmp.execute("stop"); wait_stopped(qmp,5,.01)
        except Exception as e: out["cleanup"].setdefault("errors",[]).append(str(e))
        if gdb:
            ok=True
            for t in installed:
                try: gdb.breakpoint(t,False)
                except Exception as e: ok=False; out["cleanup"].setdefault("errors",[]).append(str(e))
            out["cleanup"]["breakpoints_removed"]=ok
        try: qmp.execute("cont"); out["cleanup"]["resumed"]=True
        except Exception as e: out["cleanup"]["resume_error"]=str(e)
        out["finished"]=stamp(); a.output.write_text(json.dumps(out,indent=2)+"\n",encoding="utf-8")
        if gdb: gdb.close()
        qmp.close()
    print(json.dumps({"stops":len(out["stops"]),"error":out.get("error"),"cleanup":out["cleanup"]}))

if __name__ == "__main__": main()
