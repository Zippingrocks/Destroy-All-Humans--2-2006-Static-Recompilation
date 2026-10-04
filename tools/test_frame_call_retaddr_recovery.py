"""Audit every manual frame-dispatch direct CALL against the original XBE.

Checks both return VAs and the actual tracing macro's guest push. Mutation tests
reject each omitted/wrong callsite and removal of the macro's stack write.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xboxrecomp"))
from tools.recomp import config
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
config.configure_from_xbe(str(ROOT / "game_files/default.xbe"))
image=(ROOT/"game_files/default.xbe").read_bytes()
source=(ROOT/"src/recomp_manual.c").read_text(encoding="utf-8")
decoder=Cs(CS_ARCH_X86,CS_MODE_32)

def disassemble(start,end):
    s=next(s for s in config._SECTIONS if s.va<=start<s.va+s.raw_size)
    offset=s.raw_addr+start-s.va
    return list(decoder.disasm(image[offset:offset+end-start],start))

retail=[(int(i.op_str,16),i.address+i.size) for i in disassemble(0xF7C50,0xF7DBF)
        if i.mnemonic=="call" and i.op_str.startswith("0x")]
assert len(retail)==25

def audit(text):
    macro=re.search(r"#define F7C50_CALL\(name, return_va\).*?while \(0\)",text,re.S)
    assert macro, "Tracing CALL macro missing"
    assert "g_esp -= 4; *manual_mem32(g_esp) = (return_va);" in macro.group()
    assert macro.group().index("g_esp -= 4;")<macro.group().index("name();")
    body=re.search(r"^void sub_000F7C50\(void\)\n\{.*?^\}",text,re.M|re.S).group()
    sites=re.findall(r"F7C50_CALL\(sub_([0-9A-F]{8}), 0x([0-9A-F]{8})u\)",body)
    assert [(int(target,16),int(ret,16)) for target,ret in sites]==retail
    nested=disassemble(0x12C9B8,0x12C9BD)[0]
    assert nested.mnemonic=="call" and nested.op_str=="0x12b870"
    assert "g_esp -= 4; *manual_mem32(g_esp) = 0x0012C9BDu;\n            sub_0012B870();" in text

audit(source)
mutants=[source.replace("g_esp -= 4; *manual_mem32(g_esp) = (return_va);", "", 1),
         source.replace("g_esp -= 4; *manual_mem32(g_esp) = 0x0012C9BDu;", "", 1)]
for target,ret in retail:
    site=f"F7C50_CALL(sub_{target:08X}, 0x{ret:08X}u)"
    mutants.append(source.replace(site,f"F7C50_CALL(sub_{target:08X}, 0u)",1))
for mutant in mutants:
    try: audit(mutant)
    except AssertionError: pass
    else: raise AssertionError("Omitted/wrong return-address mutation escaped audit")
print(f"PASS: {len(retail)} retail frame CALLs plus nested12B870; {len(mutants)} return-push mutations rejected")
