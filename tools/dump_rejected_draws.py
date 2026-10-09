"""Dump the register state of the recent NV2A draws the D3D11 translator rejected (and accepted), from a live recomp's telemetry ring
(DAH2_PARITY_TIMING_MEMORY=1 builds):  py -3 tools/dump_rejected_draws.py --pid P --map M [--all]
Prints one line per recent draw (profile, reason/detail, mode, count, key combiner / texture / blend / fog / depth registers) and a
summary of the distinct register tuples."""
import argparse, collections, pathlib, re, struct, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from read_parity_state_ring import Reader, symbol_rva
ap = argparse.ArgumentParser(); ap.add_argument("--pid", type=int, required=True); ap.add_argument("--map", type=pathlib.Path, required=True)
ap.add_argument("--all", action="store_true"); a = ap.parse_args()
hdr = (pathlib.Path(__file__).resolve().parent.parent / "xboxrecomp/src/nv2a/nv2a_regs.h").read_text(errors="replace")
R = {m.group(1): int(m.group(2), 16) for m in re.finditer(r"#\s*define (NV097_[A-Z0-9_]+)\s+(0x[0-9A-Fa-f]+)\s*$", hdr, re.M)}
rev = collections.defaultdict(list)
for k, v in R.items(): rev[v].append(k)
r = Reader(a.pid, suspend=False)
tel = r.read(r.base + symbol_rva(a.map, "g_dah2_pgraph_draw_telemetry"), 64 * 48)
regs = r.read(r.base + symbol_rva(a.map, "g_dah2_pgraph_draw_registers"), 64 * 0x2000)
cur = struct.unpack("<I", r.read(r.base + symbol_rva(a.map, "g_dah2_pgraph_draw_telemetry_cursor"), 4))[0]
names = ["none", "state", "shader", "guest-memory", "vertex-output", "device", "limit", "topology", "legacy-inline"]
def reg(i, off): return struct.unpack_from("<I", regs, i * 0x2000 + off)[0]
KEYS = ["NV097_SET_COMBINER_CONTROL", "NV097_SET_SHADER_STAGE_PROGRAM", "NV097_SET_COMBINER_COLOR_ICW", "NV097_SET_COMBINER_COLOR_OCW",
        "NV097_SET_COMBINER_ALPHA_ICW", "NV097_SET_COMBINER_ALPHA_OCW", "NV097_SET_COMBINER_SPECULAR_FOG_CW0", "NV097_SET_COMBINER_SPECULAR_FOG_CW1",
        "NV097_SET_TEXTURE_FORMAT", "NV097_SET_TEXTURE_CONTROL0", "NV097_SET_TEXTURE_FILTER", "NV097_SET_FOG_ENABLE", "NV097_SET_FOG_MODE",
        "NV097_SET_FOG_GEN_MODE", "NV097_SET_BLEND_ENABLE", "NV097_SET_BLEND_FUNC_SFACTOR", "NV097_SET_BLEND_FUNC_DFACTOR", "NV097_SET_ALPHA_TEST_ENABLE",
        "NV097_SET_ALPHA_FUNC", "NV097_SET_ALPHA_REF", "NV097_SET_DEPTH_TEST_ENABLE", "NV097_SET_DEPTH_FUNC", "NV097_SET_CULL_FACE_ENABLE", "NV097_SET_CULL_FACE",
        "NV097_SET_FRONT_FACE", "NV097_SET_LIGHTING_ENABLE", "NV097_SET_SURFACE_FORMAT", "NV097_SET_CONTROL0", "NV097_SET_SURFACE_CLIP_HORIZONTAL"]
KEYS = [k for k in KEYS if k in R]
summ = collections.Counter()
for k in range(64):
    i = (cur + k) % 64
    prof, count, mode, target, tex, ch, cv, comb, reason, detail, so, sn = struct.unpack_from("<12I", tel, i * 48)
    if reason == 0 and not a.all: continue
    vals = tuple(reg(i, R[k]) for k in KEYS)
    summ[(prof, reason, detail) + vals] += 1
    print("draw %2d prof %d %-8s detail %04x mode %d count %4d" % (i, prof, names[reason] if reason < 9 else reason, detail, mode, count))
print("\n== distinct states (count x) ==")
for key, n in summ.most_common():
    prof, reason, detail = key[:3]
    print("%2dx prof %d %s detail %04x" % (n, prof, names[reason] if reason < 9 else reason, detail))
    print("     " + " ".join("%s=%x" % (k.replace("NV097_SET_", ""), v) for k, v in zip(KEYS, key[3:])))
