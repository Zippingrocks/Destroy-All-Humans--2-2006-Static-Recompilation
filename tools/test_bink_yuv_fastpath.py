from pathlib import Path

source = (Path(__file__).resolve().parents[1] / "src" / "recomp_manual.c").read_text(encoding="utf-8")
body = source.split("void sub_0028DDC0(void)", 1)[1].split("recomp_func_t recomp_lookup_manual", 1)[0]
assert "const uint8_t *y0 = manual_mem8(y0_va);" in body
assert "y0term = (int16_t)(((int32_t)(int16_t)y0w * y_scale[lane]) >> 16);" in body
assert "manual_bink_mmx_clamp(green) << 8" in body
assert "*manual_mem32(0x336FA4) = v_va + groups * 2;" in body
assert "if (xbox_va == 0x0028DDC0) return sub_0028DDC0;" in source
print("Bink YUV pointer-hoisted fast path regression checks passed")