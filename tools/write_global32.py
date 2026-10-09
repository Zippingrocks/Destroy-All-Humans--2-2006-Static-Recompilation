"""Write a 32-bit exported global of an OWNED running recomp (diagnostic switch flip).
   py -3 tools/write_global32.py --pid P --map X.map g_fnt_on 1"""
import argparse, ctypes, struct, sys
from ctypes import wintypes
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from read_parity_state_ring import Reader, symbol_rva
ap = argparse.ArgumentParser(); ap.add_argument("--pid", type=int, required=True); ap.add_argument("--map", type=Path, required=True)
ap.add_argument("name"); ap.add_argument("value", type=lambda x: int(x, 0)); a = ap.parse_args()
base = Reader(a.pid, suspend=False).base
k = ctypes.WinDLL("kernel32", use_last_error=True)
k.OpenProcess.restype = wintypes.HANDLE; k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k.WriteProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
h = k.OpenProcess(0x0020 | 0x0008, False, a.pid)   # VM_WRITE | VM_OPERATION
n = ctypes.c_size_t()
ok = k.WriteProcessMemory(h, base + symbol_rva(a.map, a.name), struct.pack("<I", a.value), 4, ctypes.byref(n))
print("ok" if ok else "FAILED %d" % ctypes.get_last_error())
