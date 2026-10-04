"""Sample a private Windows process thread and resolve RIPs through an MSVC map."""
from __future__ import annotations
import argparse, bisect, ctypes, json, re, time
from collections import Counter
from ctypes import wintypes
from pathlib import Path
K32=ctypes.WinDLL("kernel32",use_last_error=True)
THREAD_GET_CONTEXT=0x0008; THREAD_QUERY_INFORMATION=0x0040; THREAD_SUSPEND_RESUME=0x0002
TH32CS_SNAPTHREAD=0x00000004; CONTEXT_CONTROL_AMD64=0x00100001
INVALID_HANDLE_VALUE=ctypes.c_void_p(-1).value
class THREADENTRY32(ctypes.Structure):
    _fields_=[("dwSize",wintypes.DWORD),("cntUsage",wintypes.DWORD),("th32ThreadID",wintypes.DWORD),("th32OwnerProcessID",wintypes.DWORD),("tpBasePri",wintypes.LONG),("tpDeltaPri",wintypes.LONG),("dwFlags",wintypes.DWORD)]
def thread_ids(pid):
    snapshot=K32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0)
    if snapshot==INVALID_HANDLE_VALUE: raise ctypes.WinError(ctypes.get_last_error())
    result=[]; entry=THREADENTRY32(dwSize=ctypes.sizeof(THREADENTRY32))
    try:
        ok=K32.Thread32First(snapshot,ctypes.byref(entry))
        while ok:
            if entry.th32OwnerProcessID==pid: result.append(entry.th32ThreadID)
            ok=K32.Thread32Next(snapshot,ctypes.byref(entry))
    finally: K32.CloseHandle(snapshot)
    return result
def open_thread(tid):
    return K32.OpenThread(THREAD_GET_CONTEXT|THREAD_QUERY_INFORMATION|THREAD_SUSPEND_RESUME,False,tid) or None
def thread_cpu_100ns(handle):
    values=[wintypes.FILETIME() for _ in range(4)]
    if not K32.GetThreadTimes(handle,*(ctypes.byref(v) for v in values)): raise ctypes.WinError(ctypes.get_last_error())
    number=lambda v:(v.dwHighDateTime<<32)|v.dwLowDateTime
    return number(values[2])+number(values[3])
def hottest_thread(pid,interval):
    handles={tid:open_thread(tid) for tid in thread_ids(pid)}; handles={tid:h for tid,h in handles.items() if h}
    try:
        before={tid:thread_cpu_100ns(h) for tid,h in handles.items()}; time.sleep(interval)
        deltas={tid:thread_cpu_100ns(h)-before[tid] for tid,h in handles.items()}
        return max(deltas.items(),key=lambda item:item[1])
    finally:
        for h in handles.values(): K32.CloseHandle(h)
def sample_rip(handle):
    storage=ctypes.create_string_buffer(1248); address=(ctypes.addressof(storage)+15)&~15
    ctypes.c_uint32.from_address(address+48).value=CONTEXT_CONTROL_AMD64
    if K32.SuspendThread(handle)==0xFFFFFFFF: return None
    try:
        if not K32.GetThreadContext(handle,ctypes.c_void_p(address)): return None
        return ctypes.c_uint64.from_address(address+248).value
    finally: K32.ResumeThread(handle)
def map_symbols(path):
    text=path.read_text(encoding="utf-8",errors="replace")
    preferred=int(re.search(r"Preferred load address is ([0-9A-Fa-f]+)",text).group(1),16)
    pattern=re.compile(r"^\s*[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+([^\s]+)\s+([0-9A-Fa-f]{16})\s+f\s",re.MULTILINE)
    symbols=sorted((int(m.group(2),16)-preferred,m.group(1)) for m in pattern.finditer(text))
    return [x[0] for x in symbols],[x[1] for x in symbols]
def main():
    p=argparse.ArgumentParser(); p.add_argument("--pid",required=True,type=int); p.add_argument("--map",required=True,type=Path); p.add_argument("--base",required=True,type=lambda v:int(v,0)); p.add_argument("--size",required=True,type=lambda v:int(v,0)); p.add_argument("--seconds",type=float,default=5.0); p.add_argument("--interval-ms",type=float,default=1.0); p.add_argument("--output",required=True,type=Path); a=p.parse_args()
    tid,cpu_delta=hottest_thread(a.pid,0.5); handle=open_thread(tid)
    if not handle: raise RuntimeError(f"cannot open hottest thread {tid}")
    rvas,names=map_symbols(a.map); counts=Counter(); raw=Counter(); samples=0; deadline=time.perf_counter()+a.seconds
    try:
        while time.perf_counter()<deadline:
            rip=sample_rip(handle)
            if rip is not None:
                samples+=1; rva=rip-a.base; index=bisect.bisect_right(rvas,rva)-1
                if 0<=rva<a.size and index>=0: counts[f"{names[index]}+0x{rva-rvas[index]:x}"]+=1
                else: raw[f"0x{rip:016x}"]+=1
            time.sleep(a.interval_ms/1000.0)
    finally: K32.CloseHandle(handle)
    report={"schema":"dah2-process-rip-samples-v1","pid":a.pid,"thread_id":tid,"thread_cpu_100ns_during_selection":cpu_delta,"module_base":f"0x{a.base:016x}","module_size":a.size,"duration_seconds":a.seconds,"interval_ms":a.interval_ms,"samples":samples,"symbols":counts.most_common(),"unmapped":raw.most_common()}
    a.output.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8"); print(json.dumps(report,indent=2))
if __name__=="__main__": main()