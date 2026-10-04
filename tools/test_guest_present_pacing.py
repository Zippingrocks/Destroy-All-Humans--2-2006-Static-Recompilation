"""Guard the single-authority QPC pacing path used by translated frames."""
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "xboxrecomp/src/d3d/d3d8_device.c").read_text(encoding="utf-8")
start = SOURCE.index("void d3d8_PresentFrame(void)")
end = SOURCE.index("/* ================================================================", start + 40)
body = SOURCE[start:end]
assert body.count("IDXGISwapChain_Present(g_device_state.swap_chain, 0, 0);") == 1
assert "IDXGISwapChain_Present(g_device_state.swap_chain, 1, 0);" not in body
print("PASS: translated frame pump does not stack VSync on the 30 Hz QPC cap")