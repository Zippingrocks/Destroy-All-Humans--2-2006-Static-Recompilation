"""Trace retail scheduler landmarks between two post-loader callbacks."""
from __future__ import annotations
import argparse,json,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from parity_boot_trace import ControlQMP,ProbeError,memory_record,stamp,wait_stopped
from trace_xemu_vm_handoff import StepGDB
LOADER=0x001A8EB0; CALLBACK=0x002117F9; CALLBACK_RETURN=0x002117FD
LANDMARKS={
 0x00218D70,0x00218DF1,0x0021964C,0x00211896,0x0021198B,0x002115C7,0x002119BF,
 0x001046A0,0x001047B9,0x001047ED,0x001047F2,
 0x00103FE6,0x00103FF0,0x00103FFD,0x00104012,0x00104016,0x00104021,0x00104077,
 0x001037A0,0x001037AD,
 0x000F7DC0,0x000F7DCF,0x000F7DD4,0x000F7DDD,
 0x001020C0,0x001020CB,0x001020D5,
 0x001063B0,0x001063D0,0x00106412,0x0010641C,0x00106421,0x0010644B,
 0x00106459,0x00106467,0x00106469,0x00106473,0x00106483,
 0x00111CF0,0x00111D1A,0x00105410,0x0010546D,0x00105475,
 0x00111D2B,0x00111D2F,0x00111D3C,0x00111D3E,0x00111D46,
 0x0010DA80,0x0010DAD3,0x0010DADD,0x0010DAF1,
 0x0010E2BD,0x0010E2BE,0x0010E2CA,
 0x00107390,0x001073A9,0x00107CFB,0x00107D03,0x00107D06,0x00107D19,
 0x00107D27,0x00107D2F,0x00107D35,0x00107D3F,0x00107D46,
 0x00107D4E,0x00107D7D,0x00107D84,0x00107D86,0x00107D98,
 0x00107DA7,0x00107DBA,0x00107DC9,0x00107DD3,0x00107DE1,
 0x00107DF3,0x00107E00,0x00107E0D,0x00107E4B,0x00107E50,
 0x00107E54,0x00107E60,
 0x00166B50,0x00166B6B,0x00166B7B,0x00166B86,0x00166B9A,0x00166BAA,
 0x00166BD7,0x00166BEE,0x00166C00,0x00166C1D,0x00166C25,0x00166C42,
 0x00166C69,0x00166DB4,0x00166DC5,0x00166DD8,0x00166E13,
 0x00166EC3,0x00166ED4,0x00166EE7,0x00166F22,0x00166FE4,
 0x00167130,0x00167175,0x00167188,0x0016722A,0x00167245,0x00167299,
 0x0016729E,0x0016738D,0x001673A8,0x001673FC,0x00167401,
 0x001674F6,0x00167511,0x00167565,0x0016756A,0x0016760F,
 0x0016762A,0x0016767C,0x00167681,
 0x000F7C50,0x000F7C76,0x000F7D6D,0x000F7DAE,0x000F7DB6,
 0x00115030,0x0011504E,0x00115072,0x0011508C,0x001150A8,0x00115120,0x0011512B,
 0x0015ECA0,0x0015ECAD,0x0015ECD1,0x0015ECE7,0x0015ECF3,
 0x0015ED9D,0x0015EDB4,0x0015EDBF,0x0015EDE3,
}
def u8(g,a): return g.memory(a,1)[0]
def u32(g,a): return int.from_bytes(g.memory(a,4),"little")
def queue_snapshot(g,global_address=0x0030FC10):
 q=u32(g,global_address)
 result={"global":f"0x{global_address:08x}","queue":f"0x{q:08x}","words":memory_record(g,q,0x30),"nodes":[]}
 node=u32(g,q); count=min(u32(g,q+0x20),16)
 seen=set()
 for ordinal in range(count):
  if not node or node in seen: break
  seen.add(node)
  event=u32(g,node+8); vtable=u32(g,event) if event else 0
  target=u32(g,vtable+0x10) if vtable else 0
  result["nodes"].append({"ordinal":ordinal,"address":f"0x{node:08x}",
                          "words":memory_record(g,node,0x1c),"event":f"0x{event:08x}",
                          "vtable":f"0x{vtable:08x}","target":f"0x{target:08x}",
                          "target14":f"0x{u32(g,vtable+0x14) if vtable else 0:08x}",
                          "target18":f"0x{u32(g,vtable+0x18) if vtable else 0:08x}",
                          "flags3c":f"0x{u32(g,event+0x3c) if event else 0:08x}",
                          "fieldA0":f"0x{u32(g,event+0xa0) if event else 0:08x}",
                          "eventMemory":memory_record(g,event,0xb0) if event else None})
  node=u32(g,node)
 return result
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument("--qmp-port",required=True,type=int); p.add_argument("--gdb-port",required=True,type=int)
 p.add_argument("--start-callback",required=True,type=int); p.add_argument("--max-hits",type=int,default=4096)
 p.add_argument("--timeout",type=float,default=300.0); p.add_argument("--output",required=True,type=Path); a=p.parse_args()
 if a.output.exists(): p.error("output must be new")
 out={"schema":"dah2-xemu-scheduler-between-callbacks-v1","started":stamp(),"start_callback":a.start_callback,
      "hits":[],"cleanup":{"breakpoints_remaining":[],"resumed":False}}
 q=ControlQMP(a.qmp_port,5); g=None; active=set(); deadline=time.monotonic()+a.timeout
 def bp(address,install):
  g.breakpoint(address,install)
  if install: active.add(address)
  else: active.discard(address)
  out["cleanup"]["breakpoints_remaining"]=[f"0x{x:08x}" for x in sorted(active)]
 def run():
  q.execute("cont"); wait_stopped(q,max(.1,deadline-time.monotonic()),.01)
  regs=g.registers()["i386"]; return int(regs["eip"],16),regs
 try:
  q.execute("stop"); wait_stopped(q,5,.01); q.execute("system_reset"); q.execute("stop"); wait_stopped(q,5,.01)
  g=StepGDB(a.gdb_port,5); out["initial_stop"]=g.request("?").decode(errors="replace")
  bp(LOADER,True); eip,out["loader_registers"]=run()
  if eip!=LOADER: raise ProbeError(f"expected loader, stopped at 0x{eip:08x}")
  bp(LOADER,False); bp(CALLBACK,True)
  for ordinal in range(1,a.start_callback+1):
   eip,regs=run()
   if eip!=CALLBACK: raise ProbeError(f"expected callback {ordinal}, stopped at 0x{eip:08x}")
   if ordinal==a.start_callback:
    out["from"]={"ordinal":ordinal,"target":f"0x{u32(g,int(regs['ebx'],16)):08x}","registers":regs,
                 "stack":memory_record(g,int(regs["esp"],16),0x100)}
   bp(CALLBACK,False); bp(CALLBACK_RETURN,True); eip,_=run()
   if eip!=CALLBACK_RETURN: raise ProbeError(f"expected callback return, stopped at 0x{eip:08x}")
   bp(CALLBACK_RETURN,False)
   if ordinal!=a.start_callback: bp(CALLBACK,True)
  bp(CALLBACK,True)
  for address in sorted(LANDMARKS): bp(address,True)
  while len(out["hits"])<a.max_hits:
   eip,regs=run()
   if eip==CALLBACK:
    out["to"]={"ordinal":a.start_callback+1,"target":f"0x{u32(g,int(regs['ebx'],16)):08x}","registers":regs,
               "stack":memory_record(g,int(regs["esp"],16),0x100)}; break
   if eip not in LANDMARKS: raise ProbeError(f"unexpected stop at 0x{eip:08x}")
   esp=int(regs["esp"],16); row={"ordinal":len(out["hits"])+1,"address":f"0x{eip:08x}","registers":regs,
                                "stack":memory_record(g,esp,0x80)}
   if eip in (0x00218D70,0x00218DF1): row["vm_pc"]=f"0x{u32(g,esp+0x10):08x}"
   if eip==0x00111D2F:
    event=int(regs["esi"],16); callee=u32(g,event+0xA4); vtable=u32(g,callee) if callee else 0
    row["event"]=f"0x{event:08x}"; row["callee"]=f"0x{callee:08x}"
    row["callee_vtable"]=f"0x{vtable:08x}"; row["callee_target"]=f"0x{u32(g,vtable+4):08x}" if vtable else None
    if callee: row["callee_memory"]=memory_record(g,callee,0xE0)
   if eip==0x0015ECF3:
    record=int(regs["eax"],16)
    row["scheduler_record"]={"address":f"0x{record:08x}","status_ac":u8(g,record+0xAC),
                             "memory":memory_record(g,record,0xB0)}
   if eip==0x001047ED: row["scheduler_queue"]=queue_snapshot(g)
   if eip==0x001063B0: row["dispatch_queue"]=queue_snapshot(g,0x0030FD10)
   out["hits"].append(row); bp(eip,False); g.step(); bp(eip,True)
  else: raise ProbeError("next callback not reached within hit limit")
 finally:
  try: q.execute("stop"); wait_stopped(q,5,.01)
  except Exception as exc: out["cleanup"].setdefault("errors",[]).append(f"stop: {exc}")
  if g:
   for address in list(active):
    try: bp(address,False)
    except Exception as exc: out["cleanup"].setdefault("errors",[]).append(str(exc))
  try: q.execute("cont"); out["cleanup"]["resumed"]=True
  except Exception as exc: out["cleanup"]["resume_error"]=str(exc)
  out["finished"]=stamp(); a.output.write_text(json.dumps(out,indent=2)+"\n",encoding="utf-8")
  if g: g.close()
  q.close()
 print(json.dumps({"hits":len(out["hits"]),"from":out.get("from",{}).get("target"),
                   "to":out.get("to",{}).get("target"),"cleanup":out["cleanup"]}))
if __name__=="__main__": main()