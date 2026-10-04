"""Test opt-in native frame export using 2x2 offscreen WARP resources.

No window or real swap chain is created. The actual capture helpers are compiled
from d3d8_device.c; a tiny mock swap-chain GetBuffer supplies a real GPU texture.
Artifacts stay in a fresh diagnostics/frame_capture_test/run_* directory.
"""
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "xboxrecomp/src/d3d/d3d8_device.c").read_text(encoding="utf-8")
match = re.search(r"/\* DAH2_FRAME_CAPTURE_BEGIN.*?/\* DAH2_FRAME_CAPTURE_END \*/", source, re.S)
assert match, "Actual frame-capture helpers missing"
present = re.search(r"^void d3d8_PresentFrame\(void\)\n\{.*?^\}", source, re.M | re.S).group()
assert present.index("d3d8_capture_backbuffer_if_requested") < present.index("IDXGISwapChain_Present")
assert not re.search(r"\b(?:PrintWindow|BitBlt|GetDC|GetWindowDC|SwitchDesktop|SetThreadDesktop)\s*\(", match.group())

prefix = r'''
#include "d3d/d3d8_internal.h"
#include <stdio.h>
#include <string.h>
static struct {
    ID3D11Device *d3d11_device;
    ID3D11DeviceContext *d3d11_context;
    IDXGISwapChain *swap_chain;
} g_device_state;
'''
harness = r'''
#define CHECK(expression) do { if (!(expression)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expression); return 3; \
} } while (0)
static ID3D11Texture2D *source_texture;
static unsigned get_buffer_calls;

static HRESULT STDMETHODCALLTYPE fake_GetBuffer(IDXGISwapChain *self, UINT index,
                                                 REFIID iid, void **value) {
    (void)self;
    if (index != 0 || memcmp(iid, &IID_ID3D11Texture2D, sizeof(*iid)) != 0)
        return E_INVALIDARG;
    get_buffer_calls++;
    ID3D11Texture2D_AddRef(source_texture);
    *value = source_texture;
    return S_OK;
}

int main(int argc, char **argv) {
    UINT selected[3], count;
    const char *invalid[] = { "", "0", "-1", "1,", ",1", "1,1", "1,2,3,4",
                              "4294967296", "1 x", "1,,2", "1\n", "  " };
    ID3D11Device *device = NULL;
    ID3D11DeviceContext *context = NULL;
    ID3D11Texture2D *other = NULL;
    D3D_FEATURE_LEVEL level;
    D3D11_TEXTURE2D_DESC desc = {0};
    D3D11_SUBRESOURCE_DATA initial = {0};
    IDXGISwapChainVtbl fake_vtable = {0};
    IDXGISwapChain fake_chain;
    BYTE padded_rgba[32] = {
        0,0,0,0, 255,0,0,255, 0xCD,0xCD,0xCD,0xCD,0xCD,0xCD,0xCD,0xCD,
        0,128,255,17, 1,2,3,4, 0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE
    };
    HANDLE sentinel;
    DWORD written;

    if (argc > 1) {
        CHECK(SetEnvironmentVariableA("DAH2_CAPTURE_PRESENT",
              strcmp(argv[1], "disabled") == 0 ? NULL : "1,2,3,4"));
        d3d8_capture_backbuffer_if_requested(1);
        d3d8_capture_backbuffer_if_requested(50);
        CHECK(get_buffer_calls == 0);
        puts("PASS: unset/invalid capture setting performs no GPU access");
        return 0;
    }
    CHECK(!d3d8_parse_capture_presents(NULL, selected, &count) && count == 0);
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        CHECK(!d3d8_parse_capture_presents(invalid[i], selected, &count) && count == 0);
    CHECK(d3d8_parse_capture_presents("1", selected, &count) && count == 1 && selected[0] == 1);
    CHECK(d3d8_parse_capture_presents(" 1 ,\t50,4294967295 ", selected, &count)
          && count == 3 && selected[0] == 1 && selected[1] == 50 && selected[2] == 0xFFFFFFFFu);

    CHECK(SUCCEEDED(D3D11CreateDevice(NULL, D3D_DRIVER_TYPE_WARP, NULL, 0, NULL, 0,
        D3D11_SDK_VERSION, &device, &level, &context)));
    desc.Width = 2; desc.Height = 2;
    desc.MipLevels = 1; desc.ArraySize = 1;
    desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_RENDER_TARGET;
    initial.pSysMem = padded_rgba;
    initial.SysMemPitch = 16; /* Deliberately padded source rows. */
    CHECK(SUCCEEDED(ID3D11Device_CreateTexture2D(device, &desc, &initial, &source_texture)));
    fake_vtable.GetBuffer = fake_GetBuffer;
    fake_chain.lpVtbl = &fake_vtable;
    g_device_state.d3d11_device = device;
    g_device_state.d3d11_context = context;
    g_device_state.swap_chain = &fake_chain;
    CHECK(SetEnvironmentVariableA("DAH2_CAPTURE_PRESENT", "1,50,100"));
    for (unsigned present = 1; present <= 100; ++present)
        d3d8_capture_backbuffer_if_requested(present);
    CHECK(get_buffer_calls == 3);
    CHECK(SUCCEEDED(d3d8_capture_texture(device, context, source_texture, 7)));

    /* Different pixels must not overwrite an existing image/metadata pair. */
    memset(padded_rgba, 255, sizeof(padded_rgba));
    ID3D11DeviceContext_UpdateSubresource(context, (ID3D11Resource *)source_texture,
                                        0, NULL, padded_rgba, 16, 0);
    CHECK(FAILED(d3d8_capture_texture(device, context, source_texture, 7)));
    sentinel = CreateFileA("parity_frame_8.ppm", GENERIC_WRITE, 0, NULL,
                          CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(sentinel != INVALID_HANDLE_VALUE);
    CHECK(WriteFile(sentinel, "image-sentinel", 14, &written, NULL) && written == 14);
    CloseHandle(sentinel);
    CHECK(FAILED(d3d8_capture_texture(device, context, source_texture, 8)));
    sentinel = CreateFileA("parity_frame_9.json", GENERIC_WRITE, 0, NULL,
                          CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(sentinel != INVALID_HANDLE_VALUE);
    CHECK(WriteFile(sentinel, "metadata-sentinel", 17, &written, NULL) && written == 17);
    CloseHandle(sentinel);
    CHECK(FAILED(d3d8_capture_texture(device, context, source_texture, 9)));

    desc.Format = DXGI_FORMAT_R16G16B16A16_FLOAT;
    CHECK(SUCCEEDED(ID3D11Device_CreateTexture2D(device, &desc, NULL, &other)));
    CHECK(d3d8_capture_texture(device, context, other, 10) == E_NOTIMPL);
    CHECK(d3d8_capture_texture(NULL, context, NULL, 11) == E_INVALIDARG);
    ID3D11Texture2D_Release(other);
    ID3D11Texture2D_Release(source_texture);
    ID3D11DeviceContext_Release(context);
    ID3D11Device_Release(device);
    puts("PASS: actual GPU readback, selected presents, parser limits, exclusive output and unsupported-resource failures");
    return 0;
}
'''
out = ROOT / "diagnostics/frame_capture_test"
out.mkdir(exist_ok=True)
run = Path(tempfile.mkdtemp(prefix="run_", dir=out))
(run / "capture_test.c").write_text(prefix + match.group() + harness, encoding="utf-8")
vcvars = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")
include = ROOT / "xboxrecomp/src"
command = (
    f'call "{vcvars}" >nul && cl /nologo /Od /TC /I"{include}" '
    f'capture_test.c /Fe:capture_test.exe /link d3d11.lib dxgi.lib dxguid.lib'
)
subprocess.run(
    'cmd.exe /d /s /c "' + command + '"', cwd=run, check=True,
    creationflags=subprocess.CREATE_NO_WINDOW,
)
for mode in ["disabled", "invalid", None]:
    target = run if mode is None else run / mode
    target.mkdir(exist_ok=True)
    result = subprocess.run(
        [str(run / "capture_test.exe"), *([] if mode is None else [mode])],
        cwd=target, capture_output=True, text=True, timeout=30,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    print(result.stdout, end="")
    if result.returncode:
        print(result.stderr)
    result.check_returncode()
    if mode:
        assert list(target.iterdir()) == [], f"Disabled capture wrote files: {mode}"

rgba = bytes([0,0,0,0, 255,0,0,255, 0,128,255,17, 1,2,3,4])
rgb = b"".join(rgba[i:i+3] for i in range(0, len(rgba), 4))
expected_ppm = b"P6\n2 2\n255\n" + rgb
fingerprint = 14695981039346656037
for byte in rgba:
    fingerprint = ((fingerprint ^ byte) * 1099511628211) & ((1 << 64) - 1)
for frame in (1, 7, 50, 100):
    assert (run / f"parity_frame_{frame}.ppm").read_bytes() == expected_ppm
    record = json.loads((run / f"parity_frame_{frame}.json").read_text())
    assert record["status"] == "captured" and record["present"] == frame
    assert record["width"] == 2 and record["height"] == 2 and record["dxgi_format"] == 28
    assert record["row_pitch"] >= 8
    assert record["pixels_read"] == 4 and record["nonblack_pixels"] == 3
    assert record["rgba_fnv1a64"] == f"{fingerprint:016x}"
    assert record["timing_perturbed"] is True
assert (run / "parity_frame_8.ppm").read_bytes() == b"image-sentinel"
assert (run / "parity_frame_9.json").read_bytes() == b"metadata-sentinel"
assert not (run / "parity_frame_9.ppm").exists()
for frame in (8, 10, 11):
    assert json.loads((run / f"parity_frame_{frame}.json").read_text())["status"] == "failed"
for frame in (10, 11):
    assert not (run / f"parity_frame_{frame}.ppm").exists()
print("PASS: exact PPM RGB/top-to-bottom pixels, padding exclusion, RGBA hash, nonblack count, failure metadata, no overwrites")
print(f"Artifacts: {run}")
