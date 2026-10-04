"""Timing observer fixtures: decoder/state comparison, cleanup, and native ABI.

Default: offline Python tests. --native: additionally compile a tiny C harness
with the actual observer, checking global budget across two caller TUs and that
guest registers/memory are unchanged. No game or emulator is started.
"""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from parity_timing_trace import POINTS, LAYOUT, collect_events, compare_events, clock_checks, event_capture, retail_clock_quotient
from parity_probe import ProbeError


def fixture(ordinal, now, delta, count, kind="clock_sample", pointer=0x1000):
    state = {name: dict(pointer=f"0x{pointer:08x}", **{field: "0x00000000" for field in fields})
             for name, (_, fields) in LAYOUT.items()}
    state["clock"].update(current_ms=f"0x{now:08x}", delta_ms=f"0x{delta:08x}", sample_count=f"0x{count:08x}")
    state["device"].update(put=f"0x{pointer+8:08x}", ring_base=f"0x{pointer:08x}", ring_end=f"0x{pointer+0x1000:08x}")
    return {"ordinal": ordinal, "kind": kind, "address": f"0x{next(a for a,n in POINTS.items() if n==kind):08x}", "state": state}


class FakeQMP:
    def __init__(self, fail_cont=None): self.commands=[]; self.conts=0; self.fail_cont=fail_cont
    def execute(self, command):
        self.commands.append(command)
        if command == "cont":
            self.conts += 1
            if self.conts == self.fail_cont: raise ProbeError("fixture timeout")
        return {"running": False, "status": "debug"}


class FakeGDB:
    def __init__(self): self.active=set(); self.removed=[]; self.steps=0
    def breakpoint(self, address, insert=True):
        if insert:self.active.add(address)
        else:self.active.discard(address); self.removed.append(address)
    def single_step(self): self.steps+=1


class TimingTests(unittest.TestCase):
    def test_retail_clock_signed_quotient(self):
        mask = (1 << 64) - 1
        self.assertEqual(retail_clock_quotient(0), 0)
        self.assertEqual(retail_clock_quotient(733333333), 999)
        self.assertEqual(retail_clock_quotient(2200000), 3)
        self.assertEqual(retail_clock_quotient(mask), 0)  # -3 / 2200000 truncates to zero.
        self.assertEqual(retail_clock_quotient((1 << 64) - 733334), mask)
        self.assertEqual(retail_clock_quotient(1 << 63), (-((1 << 63) // 2200000)) & mask)
        # 3 * inverse(3) wraps exactly to1 instead of using an unbounded product.
        self.assertEqual(retail_clock_quotient(0xAAAAAAAAAAAAAAAB), 0)

    def test_clock_wrap(self):
        checks=clock_checks([fixture(1,0xFFFFFFF0,1,0xFFFFFFFF),fixture(2,0x20,0x30,0)])
        self.assertTrue(checks[1]["counter_increment_one"])
        self.assertTrue(checks[1]["delta_matches_u32_subtraction"])
        broken=clock_checks([fixture(1,10,1,4),fixture(2,15,6,8)])
        self.assertFalse(broken[1]["counter_increment_one"])
        self.assertFalse(broken[1]["delta_matches_u32_subtraction"])

    def test_normalizes_addresses_not_values(self):
        left=[fixture(1,100,16,4)]; right=[fixture(1,100000,16,4,pointer=0x80000000)]
        result=compare_events(left,right)
        self.assertTrue(result["event_order_equal"])
        self.assertEqual(result["rows"][0]["differences"],{})
        right[0]["state"]["simulation"]["delta_bits"]="0x3c888889"
        self.assertIn("simulation.delta_bits",compare_events(left,right)["rows"][0]["differences"])
        self.assertFalse(result["timing_parity_verified"])

    def test_missing_events(self):
        left=[fixture(1,1,1,1),fixture(2,1,1,1,"simulation_delta"),fixture(3,1,1,1,"swap")]
        result=compare_events(left,[left[0],left[2]])
        self.assertFalse(result["event_order_equal"])
        self.assertEqual(result["rows"][1]["alignment"],"delete")

    def test_null_reads(self):
        class G:
            def registers(self): return {"i386": dict.fromkeys(("eax","ecx","edx","ebx","esi","edi","esp","ebp"),"0x00000000")|{"eip":"0x0013d898"}}
            def memory(self,a,n): raise ProbeError("fixture unmapped")
        event=event_capture(G(),1,POINTS)
        self.assertEqual(len(event["read_errors"]),4)
        self.assertIsNone(event["state"]["clock"]["delta_ms"])

    def test_bound_and_cleanup(self):
        q,g=FakeQMP(),FakeGDB();result={"events":[],"checkpoints":{f"0x{a:08x}":n for a,n in POINTS.items()}}
        with patch("parity_timing_trace.event_capture",side_effect=lambda g,n,p:fixture(n,n,1,n)):
            collect_events(q,g,result,4,2,5,.01,lambda:None)
        self.assertEqual(len(result["events"]),4);self.assertEqual(g.steps,3)
        self.assertFalse(g.active);self.assertTrue(result["cleanup"]["completed"])
        self.assertFalse(result["status_final"]["running"])

    def test_failure_preserves_partial_and_cleans(self):
        q,g=FakeQMP(fail_cont=2),FakeGDB();result={"events":[],"checkpoints":{f"0x{a:08x}":n for a,n in POINTS.items()}}
        with patch("parity_timing_trace.event_capture",side_effect=lambda g,n,p:fixture(n,n,1,n)):
            collect_events(q,g,result,4,2,5,.01,lambda:None)
        self.assertEqual(len(result["events"]),1);self.assertIn("fixture timeout",result["error"])
        self.assertFalse(g.active);self.assertTrue(result["cleanup"]["completed"])


def native_test():
    root=Path(__file__).resolve().parents[1]
    out=root/"diagnostics/parity_timing_test";out.mkdir(exist_ok=True)
    out=Path(tempfile.mkdtemp(prefix="run_",dir=out))
    harness=r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "recomp/recomp_types.h"
#include "parity_timing.h"
ptrdiff_t g_xbox_mem_offset;
RECOMP_TLS uint32_t g_eax,g_ecx,g_edx,g_esp,g_ebx,g_esi,g_edi;
void from_a(void); void from_b(void);
#define WORD(a) (*(uint32_t *)(memory+(a)))
int main(void) {
    unsigned char *memory=calloc(1,0x400000), *before=malloc(0x400000);
    if(!memory||!before)return 5;
    g_xbox_mem_offset=(ptrdiff_t)memory;
    WORD(0x2C9C88)=0x1000;WORD(0x30FDE4)=0x10000;WORD(0x2CA6A0)=0x20000;WORD(0x25E5A8)=0x30000;
    WORD(0x1024)=100;WORD(0x1028)=16;WORD(0x102C)=6;
    WORD(0x10004)=0x42700000;WORD(0x10010)=0x3C888889;memory[0x1303D]=1;
    WORD(0x20238)=1;WORD(0x2027C)=1;
    WORD(0x30000)=0x80001800;WORD(0x30024)=0x80001000;WORD(0x30028)=0x80201000;WORD(0x32478)=8;
    memcpy(before,memory,0x400000);
    g_eax=1;g_ecx=2;g_edx=3;g_esp=4;g_ebx=5;g_esi=6;g_edi=7;
    for(unsigned i=0;i<12;++i) { if(i&1)from_b();else from_a(); }
    if(g_eax!=1||g_ecx!=2||g_edx!=3||g_esp!=4||g_ebx!=5||g_esi!=6||g_edi!=7)return 2;
    if(memcmp(before,memory,0x400000))return 3;
    free(before);free(memory);puts("PASS: native observer leaves guest registers and entire memory unchanged");return 0;
}
'''
    (out/"test.c").write_text(harness)
    (out/"a.c").write_text('#include "parity_timing.h"\nvoid from_a(void){dah2_parity_timing("clock_sample",0x13D898,8);}\n')
    (out/"b.c").write_text('#include "parity_timing.h"\nvoid from_b(void){dah2_parity_timing("simulation_delta",0x1152AD,8);}\n')
    vcvars=Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
    command=f'call "{vcvars}" >nul && cl /nologo /Od /W4 /I"{root / "src"}" test.c a.c b.c "{root / "src/parity_timing.c"}" /Fe:test.exe'
    subprocess.run('cmd.exe /d /s /c "'+command+'"',cwd=out,check=True,creationflags=subprocess.CREATE_NO_WINDOW)
    import os
    env=os.environ.copy();env.update(DAH2_PARITY_TRACE="1",DAH2_PARITY_EVENTS="5")
    completed=subprocess.run([str(out/"test.exe")],env=env,capture_output=True,text=True,check=True,creationflags=subprocess.CREATE_NO_WINDOW)
    events=[json.loads(line.split('[PARITY-TIME] ',1)[1]) for line in completed.stderr.splitlines()]
    assert [e["ordinal"] for e in events]==list(range(1,6))
    assert [e["kind"] for e in events]==["clock_sample","simulation_delta","clock_sample","simulation_delta","clock_sample"]
    assert all(e["state"]["simulation"]["delta_bits"]=="0x3c888889" for e in events)
    env["DAH2_PARITY_TRACE"]="0"
    disabled=subprocess.run([str(out/"test.exe")],env=env,capture_output=True,text=True,check=True,creationflags=subprocess.CREATE_NO_WINDOW)
    assert disabled.stderr==""
    print(completed.stdout.strip());print("PASS: shared 5-event budget/order across two TUs, schema values, disabled path silent")


if __name__=="__main__":
    run_native="--native" in sys.argv
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(TimingTests))
    if not result.wasSuccessful():raise SystemExit(1)
    if run_native:native_test()
