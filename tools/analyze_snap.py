"""Analyze g_snap_frozen_pre/post.bin written by dump_heap_check.py: replay the semantic effect of the SAP 'move proxy' call on the pre state
and compare with the recompiled function's post state.  py -3 tools/analyze_snap.py RUNDIR"""
import struct, sys
from pathlib import Path
import numpy as np
d = Path(sys.argv[1])
def load(n):
    b = (d / n).read_bytes(); w = struct.unpack("<%dI" % (len(b) // 4), b)
    hdr = w[:16]; S = w[16:52]; L = [w[52 + 514 * i: 52 + 514 * (i + 1)] for i in range(3)]; rec = w[52 + 1542:]
    return hdr, S, L, rec
pre, post = load("g_snap_frozen_pre.bin"), load("g_snap_frozen_post.bin")
hdr = pre[0]; fl = lambda x: struct.unpack("<f", struct.pack("<I", x))[0]
print("pre: tag %x nat %d id %x self %x box %x" % (hdr[0], hdr[1], hdr[2], hdr[3], hdr[4]), [round(fl(x), 4) for x in hdr[5:13]])
S = pre[1]; cnt = S[0x11]; print("count", cnt, "list counts", S[0x14], S[0x17], S[0x1a])
f = lambda x: np.float32(fl(x))
mins = [f(S[4 + i]) for i in range(3)]      # S+0x10
off2 = [f(S[8 + i]) for i in range(3)]      # S+0x20
scale = [f(S[12 + i]) for i in range(3)]    # S+0x30
box = [np.float32(fl(x)) for x in hdr[5:13]]
bias, lo, hi = np.float32(65536.0), np.float32(0.0), np.float32(65532.0)
def key(v, axis, is_max):
    base = box[(4 if is_max else 0) + axis]
    x = np.float32((base + (mins if not is_max else mins)[axis]) )   # + S+0x10 for both min and max (S+0x10 = -world_min)
    x = np.float32(x * scale[axis])
    x = np.minimum(x, hi) if not np.isnan(x) else hi
    x = np.maximum(x, lo)
    x = np.float32(x + bias)
    bits = struct.unpack("<I", struct.pack("<f", x))[0]
    k = (bits >> 7) & 0xffff
    return (k | 1) if is_max else (k & 0xfffe)
# NOTE: the asm adds [esi+0x10] to min and [esi+0x20] to the max box, as in 1D0260 (addps xmm5,[ebx+0x10] for min; addps [ebx+0x20] for max)
def key2(axis, is_max):
    base = box[(4 if is_max else 0) + axis]
    off = off2[axis] if is_max else mins[axis]
    x = np.float32(np.float32(base + off) * scale[axis])
    x = hi if np.isnan(x) else min(x, hi)
    x = max(x, lo)
    x = np.float32(x + bias)
    k = (struct.unpack("<I", struct.pack("<f", x))[0] >> 7) & 0xffff
    return (k | 1) if is_max else (k & 0xfffe)
idv = hdr[2]
names = ["L0(x)", "L1(y)", "L2(z)"]
# list L0 uses axis x (S+0x4c), L1 y, L2 z
for li in range(3):
    n = S[0x14 + 3 * li]
    e = list(pre[2][li][:n]); e2 = list(post[2][li][:post[1][0x14 + 3 * li]])
    kmin, kmax = key2(li, False), key2(li, True)
    mine = [(i, x) for i, x in enumerate(e) if (x >> 16) == idv]
    print(names[li], "entries of id in pre:", [(i, hex(x & 0xffff)) for i, x in mine], " new keys min %x max %x" % (kmin, kmax))
    # reference result: remove id's entries and re-insert
    rest = [x for x in e if (x >> 16) != idv]
    # positions: insert min entry after all entries with key <= ? (stable behaviour unknown) -> only check sortedness + multiset
    ref_multiset = sorted(rest + [(idv << 16) | kmin, (idv << 16) | kmax])
    post_multiset = sorted(e2)
    print("   post multiset == reference multiset:", post_multiset == ref_multiset, " post sorted:", all((e2[i] & 0xffff) <= (e2[i + 1] & 0xffff) for i in range(len(e2) - 1)))
    bad = [i for i in range(len(e2) - 1) if (e2[i] & 0xffff) > (e2[i + 1] & 0xffff)]
    print("   unsorted positions in post:", bad[:6], " post entries of id:", [(i, hex(x & 0xffff)) for i, x in enumerate(e2) if (x >> 16) == idv])
    if bad:
        i0 = bad[0]; print("   post around:", ["%04x:%04x" % (x & 0xffff, x >> 16) for x in e2[max(0, i0 - 4): i0 + 6]])
        j = [i for i, x in enumerate(e) if (x >> 16) == idv]
        print("   pre  around id:", ["%04x:%04x" % (x & 0xffff, x >> 16) for x in e[max(0, j[0] - 3): j[0] + 4]])
rec = pre[3]; r = rec[idv * 4: idv * 4 + 4]
print("rec id pre:", " ".join("%08x" % x for x in r), "post:", " ".join("%08x" % x for x in post[3][idv * 4: idv * 4 + 4]))
