"""Known-answer tests for the kernel host functions the bridge now routes.

Run: py -3 tools/test_kernel_host_vectors.py

XcSHAInit/Update/Final, XcHMAC, RtlTimeFieldsToTime, RtlTimeToTimeFields and
RtlCompareMemoryUlong had wrappers but were unrouted, so no title ever ran
them. Routing them makes their output real, so their output is checked here
against published vectors by compiling the actual xboxrecomp kernel sources:

  * SHA-1: FIPS 180-1 ("abc", the 448-bit message, one million 'a'), plus an
    unaligned multi-chunk update that must match the one-shot digest.
  * HMAC-SHA1: RFC 2202 cases 1, 2 and 6 (6 uses an 80-byte key, longer than
    the 64-byte block, which must be hashed first). XcHMAC takes TWO data
    buffers hashed back to back, so each vector is also split at every offset.
  * Time: 1970-01-01 and 2000-01-01 FILETIMEs, weekday, milliseconds, and a
    full round trip.
  * RtlCompareMemoryUlong: whole-ULONG matching, early mismatch, short length.

Nothing here launches a game. Skipped if the MSVC toolchain is not installed.
"""
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KERNEL = ROOT / "xboxrecomp" / "src" / "kernel"
VCVARS = Path("C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat")

C_SOURCE = r'''
#include <stdio.h>
#include <string.h>
#include "kernel.h"

/* kernel_crypto.c / kernel_rtl.c only need the logger from the rest of the layer. */
void xbox_log(int level, int category, const char *fmt, ...) { (void)level; (void)category; (void)fmt; }

static int failures = 0;
static void check(const char *name, int ok) {
    if (!ok) { printf("FAIL %s\n", name); ++failures; }
}
static void hex(const unsigned char *d, int n, char *out) {
    int i; for (i = 0; i < n; ++i) sprintf(out + i * 2, "%02x", d[i]); out[n * 2] = 0;
}
static void sha1(const unsigned char *msg, unsigned len, unsigned chunk, char *out) {
    XBOX_SHA_CONTEXT c; unsigned char dg[20]; unsigned i;
    xbox_XcSHAInit(&c);
    for (i = 0; i < len; i += chunk) xbox_XcSHAUpdate(&c, msg + i, (len - i < chunk) ? len - i : chunk);
    xbox_XcSHAFinal(&c, dg);
    hex(dg, 20, out);
}
static void hmac2(const unsigned char *key, unsigned kl, const unsigned char *d, unsigned dl,
                  unsigned split, char *out) {
    unsigned char dg[20];
    xbox_XcHMAC(key, kl, d, split, d + split, dl - split, dg);
    hex(dg, 20, out);
}

int main(void) {
    char got[64]; unsigned i;
    const char *abc = "abc";
    const char *m448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    static unsigned char million[1000000];

    sha1((const unsigned char*)"", 0, 1, got);
    check("sha1 empty", !strcmp(got, "da39a3ee5e6b4b0d3255bfef95601890afd80709"));
    sha1((const unsigned char*)abc, 3, 3, got);
    check("sha1 abc", !strcmp(got, "a9993e364706816aba3e25717850c26c9cd0d89d"));
    sha1((const unsigned char*)m448, (unsigned)strlen(m448), 7, got);
    check("sha1 448-bit, 7-byte chunks", !strcmp(got, "84983e441c3bd26ebaae4aa1f95129e5e54670f1"));
    memset(million, 'a', sizeof(million));
    sha1(million, sizeof(million), 1000000, got);
    check("sha1 million a, one shot", !strcmp(got, "34aa973cd4c4daa4f61eeb2bdbad27316534016f"));
    sha1(million, sizeof(million), 61, got);
    check("sha1 million a, 61-byte chunks", !strcmp(got, "34aa973cd4c4daa4f61eeb2bdbad27316534016f"));

    {   /* RFC 2202 case 1 */
        unsigned char key[20]; memset(key, 0x0b, 20);
        for (i = 0; i <= 8; ++i) {
            hmac2(key, 20, (const unsigned char*)"Hi There", 8, i, got);
            if (strcmp(got, "b617318655057264e28bc0b6fb378c8ef146be00")) { check("hmac case1", 0); break; }
        }
    }
    {   /* RFC 2202 case 2 */
        const char *d = "what do ya want for nothing?"; unsigned dl = (unsigned)strlen(d);
        for (i = 0; i <= dl; ++i) {
            hmac2((const unsigned char*)"Jefe", 4, (const unsigned char*)d, dl, i, got);
            if (strcmp(got, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")) { check("hmac case2", 0); break; }
        }
    }
    {   /* RFC 2202 case 6: key longer than the block size */
        unsigned char key[80]; const char *d = "Test Using Larger Than Block-Size Key - Hash Key First";
        unsigned dl = (unsigned)strlen(d);
        memset(key, 0xaa, 80);
        for (i = 0; i <= dl; ++i) {
            hmac2(key, 80, (const unsigned char*)d, dl, i, got);
            if (strcmp(got, "aa4ae5e15272d00e95705637ce8a3b55ed402112")) { check("hmac case6", 0); break; }
        }
    }

    {   /* time: 1970-01-01 and 2000-01-01, round trip, weekday, milliseconds */
        XBOX_TIME_FIELDS tf; LARGE_INTEGER t; XBOX_TIME_FIELDS back;
        memset(&tf, 0, sizeof(tf)); tf.Year = 1970; tf.Month = 1; tf.Day = 1;
        check("fields->time 1970 ok", xbox_RtlTimeFieldsToTime(&tf, &t));
        check("filetime 1970", t.QuadPart == 116444736000000000LL);
        xbox_RtlTimeToTimeFields(&t, &back);
        check("1970 round trip", back.Year == 1970 && back.Month == 1 && back.Day == 1 && back.Weekday == 4);

        memset(&tf, 0, sizeof(tf)); tf.Year = 2000; tf.Month = 1; tf.Day = 1;
        xbox_RtlTimeFieldsToTime(&tf, &t);
        check("filetime 2000", t.QuadPart == 125911584000000000LL);
        xbox_RtlTimeToTimeFields(&t, &back);
        check("2000 weekday saturday", back.Weekday == 6);

        memset(&tf, 0, sizeof(tf)); tf.Year = 2026; tf.Month = 10; tf.Day = 8;
        tf.Hour = 13; tf.Minute = 37; tf.Second = 59; tf.Milliseconds = 123;
        xbox_RtlTimeFieldsToTime(&tf, &t);
        xbox_RtlTimeToTimeFields(&t, &back);
        check("2026 round trip", back.Year == 2026 && back.Month == 10 && back.Day == 8 &&
              back.Hour == 13 && back.Minute == 37 && back.Second == 59 && back.Milliseconds == 123);

        memset(&tf, 0, sizeof(tf)); tf.Year = 2001; tf.Month = 13; tf.Day = 1;
        check("invalid month rejected", !xbox_RtlTimeFieldsToTime(&tf, &t));
    }

    {   /* RtlCompareMemoryUlong */
        unsigned long buf[4] = { 0xDEADBEEFul, 0xDEADBEEFul, 0xDEADBEEFul, 0x12345678ul };
        check("ulong all match 12", xbox_RtlCompareMemoryUlong(buf, 12, 0xDEADBEEFul) == 12);
        check("ulong stops at mismatch", xbox_RtlCompareMemoryUlong(buf, 16, 0xDEADBEEFul) == 12);
        check("ulong first mismatch", xbox_RtlCompareMemoryUlong(buf + 3, 4, 0xDEADBEEFul) == 0);
        check("ulong zero length", xbox_RtlCompareMemoryUlong(buf, 0, 0xDEADBEEFul) == 0);
        check("ulong short length", xbox_RtlCompareMemoryUlong(buf, 7, 0xDEADBEEFul) == 4);
    }

    if (failures) { printf("%d FAILED\n", failures); return 1; }
    printf("all native vectors passed\n");
    return 0;
}
'''


def main():
    if not VCVARS.exists():
        print("skip  MSVC (vcvars64.bat) not found")
        return 0
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        (d / "t.c").write_text(C_SOURCE, encoding="utf-8")
        cmd = (f'call "{VCVARS}" >nul && cl /nologo /TC /W3 /O2 /I"{KERNEL}" '
               f'/I"{ROOT / "xboxrecomp" / "src"}" '
               f'/DWIN32_LEAN_AND_MEAN t.c "{KERNEL / "kernel_crypto.c"}" '
               f'"{KERNEL / "kernel_rtl.c"}" /Fe:t.exe')
        r = subprocess.run('cmd.exe /d /s /c "' + cmd + '"', cwd=d, capture_output=True,
                           text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        if r.returncode != 0:
            print(r.stdout[-3000:], r.stderr[-1500:])
            print("FAIL  could not build the native vector test")
            return 1
        run = subprocess.run([str(d / "t.exe")], capture_output=True, text=True, timeout=60,
                             creationflags=subprocess.CREATE_NO_WINDOW)
        print(run.stdout.strip())
        return run.returncode


if __name__ == "__main__":
    sys.exit(main())
