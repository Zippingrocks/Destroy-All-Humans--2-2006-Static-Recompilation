from pathlib import Path
source = (Path(__file__).resolve().parents[1] / "src/guest_nv2a_bridge.c").read_text(encoding="utf-8")
body = source.split("static int dah2_guest_gpu_read_physical", 1)[1].split("static int dah2_guest_gpu_init_locked", 1)[0]
assert "static __declspec(thread) uintptr_t cached_start;" in body
assert "if (native < cached_start || native_last >= cached_end)" in body
assert "VirtualQuery((const void *)native" in body
assert "info.State != MEM_COMMIT" in body
assert "PAGE_NOACCESS | PAGE_GUARD" in body
assert "memcpy(output, (const void *)native, bytes);" in body
print("Guest reader committed-region cache regression checks passed")