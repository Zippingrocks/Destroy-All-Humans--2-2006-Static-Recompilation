"""Guard xemu-compatible linear-texture interpolation in the D3D11 bridge."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DRAW = (ROOT / "xboxrecomp/src/nv2a/nv2a_indexed_draw.h").read_text()
SHADERS = (ROOT / "xboxrecomp/src/d3d/d3d8_shaders.c").read_text()

assert "profile==PGRAPH_ARRAY_PROFILE_DAH2_ACCUMULATE4_XRGB ? 15u" in DRAW
for profile in (
    "PGRAPH_ARRAY_PROFILE_TEXTURED_ARGB",
    "PGRAPH_ARRAY_PROFILE_TEXTURED_XRGB",
    "PGRAPH_ARRAY_PROFILE_DAH2_SUBTRACT_XRGB",
):
    assert profile in DRAW

assert "texel_coords ? r->output[9][0] : r->output[9][0]/tw" in DRAW
assert "texel_coord_mask&(1u<<stage)" in DRAW
assert "d3d8_shaders_set_texel_coord_mask(texel_coord_mask);" in DRAW
assert "d3d8_shaders_set_texel_coord_mask(0);" in DRAW

for stage, bit in enumerate((8, 16, 32, 64)):
    assert f"(PSFlags & {bit:2d}u) ? input.tex{stage} / float2(w{stage}, h{stage})" in SHADERS
    assert f"texels[{stage}] = tex{stage}.Sample(samp{stage}, tc{stage});" in SHADERS

print("PASS: linear NV2A texel coordinates interpolate before per-fragment normalization on all four stages")
