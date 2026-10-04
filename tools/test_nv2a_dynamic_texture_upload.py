from pathlib import Path
root = Path(__file__).resolve().parents[1]
draw = (root / "xboxrecomp/src/nv2a/nv2a_indexed_draw.h").read_text(encoding="utf-8")
internal = (root / "xboxrecomp/src/d3d/d3d8_internal.h").read_text(encoding="utf-8")
resources = (root / "xboxrecomp/src/d3d/d3d8_resources.c").read_text(encoding="utf-8")
assert "D3DUSAGE_DYNAMIC,D3DFMT_LIN_A8R8G8B8" in draw
assert "BOOL                    dynamic;" in internal
assert "D3D11_MAP_WRITE_DISCARD" in resources
assert "td.Usage = tex->dynamic ? D3D11_USAGE_DYNAMIC : D3D11_USAGE_DEFAULT;" in resources
assert "array_textures[" not in (root / "xboxrecomp/src/nv2a/nv2a_pgraph_d3d11.c").read_text(encoding="utf-8")
print("NV2A dynamic texture upload regression checks passed")