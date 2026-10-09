"""Capture retail return/unwind landmarks after post-loader callback 6."""
from __future__ import annotations
import argparse,json,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from parity_boot_trace import ControlGDB,ControlQMP,ProbeError,memory_record,stamp,wait_stopped
LOADER=0x001A8EB0
CALL=0x002117F9
RET=0x002117FD
LANDMARKS=(0x000F7C50,0x001046A0,0x001047B9,0x001047ED,0x0021964C,0x00211896,0x0021198B,0x002115C7,0x002119BF,0x00103FE6,0x00103FF0,0x00103FFD,0x00104012,0x00104016,0x00104021,0x00104077,0x001037A0,0x001037AD,0x001047F2,0x000F7C76,0x00115030,0x0011504E,0x00115072,0x0011508C,0x001150A8,0x000F7D6D,0x00115120,0x0015ECA0,0x0015ECAD,0x0015ECD1,0x0015ECE7,0x0015ECF3,0x0015ED9D,0x0015EDB4,0x0015EDBF,0x0015EDE3,0x0011512B,0x000F7DAE,0x000F7DB6,0x001577C4,0x00157740,0x000F7C50,0x001046A0,0x001047ED,0x0021964C,0x00218DF1)

def u32(g,a): return int.from_bytes(g.memory(a,4),"little")
def snapshot(g,address):
    r=g.registers()["i386"]; sp=int(r["esp"],16)
    row={"address":f"0x{address:08x}","registers":r,"stack":memory_record(g,sp,0x100),"scene_record0_flag_ac":g.memory(0x003153DC,1).hex()}
    row["pointed_memory"]={}
    for name in ("edi","esi","ecx"):
        pointer=int(r[name],16)
        if 0x10000 <= pointer < 0x90000000:
            row["pointed_memory"][name]=memory_record(g,pointer,0x80)
    return row

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--qmp-port",required=True,type=int);p.add_argument("--gdb-port",required=True,type=int)
    p.add_argument("--timeout",type=float,default=180);p.add_argument("--output",required=True,type=Path)
    a=p.parse_args()
    if a.output.exists():p.error("output must be new")
    out={"schema":"dah2-xemu-return-landmarks-after-loader-callback6-v1","started":stamp(),
         "callbacks":[],"landmarks":[],"cleanup":{"breakpoints_remaining":[],"resumed":False}}
    q=ControlQMP(a.qmp_port,5);g=None;active=set();deadline=time.monotonic()+a.timeout
    def bp(address,install):
        g.breakpoint(address,install)
        if install:active.add(address)
        else:active.discard(address)
        out["cleanup"]["breakpoints_remaining"]=[f"0x{x:08x}" for x in sorted(active)]
    def run(expected):
        q.execute("cont");wait_stopped(q,max(.1,deadline-time.monotonic()),.01)
        r=g.registers()["i386"];actual=int(r["eip"],16)
        if actual!=expected:raise ProbeError(f"expected 0x{expected:08x}, stopped at 0x{actual:08x}")
        return r
    try:
        q.execute("stop");wait_stopped(q,5,.01);q.execute("system_reset");q.execute("stop");wait_stopped(q,5,.01)
        g=ControlGDB(a.gdb_port,5);out["initial_stop"]=g.request("?").decode(errors="replace")
        bp(LOADER,True);out["loader"]={"registers":run(LOADER),"scene_record0_flag_ac":g.memory(0x003153DC,1).hex()};bp(LOADER,False);bp(CALL,True)
        for ordinal in range(1,7):
            r=run(CALL);ebx=int(r["ebx"],16);sp=int(r["esp"],16)
            row={"ordinal":ordinal,"target":f"0x{u32(g,ebx):08x}","registers":r,"stack":memory_record(g,sp,0x100),"scene_record0_flag_ac":g.memory(0x003153DC,1).hex()}
            out["callbacks"].append(row);bp(CALL,False);bp(RET,True)
            row["return_registers"]=run(RET);bp(RET,False)
            if ordinal!=6:bp(CALL,True)
        for address in LANDMARKS:
            bp(address,True);run(address);out["landmarks"].append(snapshot(g,address));bp(address,False)
        last=out["landmarks"][-1];pc=u32(g,int(last["registers"]["esp"],16)+0x10)
        last["vm_pc"]=f"0x{pc:08x}";last["vm_opcode"]=f"0x{u32(g,pc):08x}"
    finally:
        try:q.execute("stop");wait_stopped(q,5,.01)
        except Exception as exc:out["cleanup"].setdefault("errors",[]).append(f"stop: {exc}")
        if g:
            for address in list(active):
                try:bp(address,False)
                except Exception as exc:out["cleanup"].setdefault("errors",[]).append(str(exc))
        try:q.execute("cont");out["cleanup"]["resumed"]=True
        except Exception as exc:out["cleanup"]["resume_error"]=str(exc)
        out["finished"]=stamp();a.output.write_text(json.dumps(out,indent=2)+"\n",encoding="utf-8")
        if g:g.close()
        q.close()
    print(json.dumps({"landmarks":[x["address"] for x in out["landmarks"]],"cleanup":out["cleanup"]}))
if __name__=="__main__":main()
