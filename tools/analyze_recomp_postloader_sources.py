"""Resolve Lua Proto/source candidates from bounded recomp callback stack copies."""
from __future__ import annotations
import argparse, json, struct
from pathlib import Path
from read_parity_state_ring import Reader

def u32(data, offset): return struct.unpack_from("<I", data, offset)[0]
def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument("--pid",required=True,type=int); p.add_argument("--input",required=True,type=Path); p.add_argument("--output",required=True,type=Path); a=p.parse_args()
    if a.output.exists(): p.error("output must be new")
    snap=json.loads(a.input.read_text(encoding="utf-8")); count=min(snap["scalars"]["g_dah2_postloader_stack_calls"],512); flat=snap["arrays"]["g_dah2_postloader_stack_trace"]; targets=snap["arrays"]["g_dah2_postloader_stack_target"]
    reader=Reader(a.pid); rows=[]
    try:
        for ordinal in range(count):
            words=[int(x,16) for x in flat[ordinal*64:(ordinal+1)*64]]; candidates=[]
            for index in range(2,len(words)):
                function=words[index]
                if not 0x80000000 <= function < 0x90000000: continue
                try:
                    fields=reader.read(function,0x48); f08,code,code_count=u32(fields,8),u32(fields,0x18),u32(fields,0x1c); pc=words[index-2]
                    if words[index-1]!=f08 or not code <= pc <= code+max(4,code_count*4): continue
                    source_object=u32(fields,0x40); source=""
                    if 0x80000000 <= source_object < 0x90000000:
                        raw=reader.read(source_object+20,512); source=raw.split(b"\0",1)[0].decode("latin1",errors="replace")
                    candidates.append({"stack_index":index,"function":f"{function:08X}","pc":f"{pc:08X}","source_object":f"{source_object:08X}","source":source})
                except OSError: pass
            rows.append({"ordinal_after_loader":ordinal+1,"target":targets[ordinal],"candidates":candidates})
    finally: reader.close()
    result={"schema":"dah2-recomp-postloader-sources-v1","pid":a.pid,"rows":rows}; a.output.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8"); print(json.dumps({"rows":len(rows),"with_candidates":sum(bool(x["candidates"]) for x in rows)}))
if __name__=="__main__": main()
