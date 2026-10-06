#!/usr/bin/env python3
"""A CASPAL on an executable allocation's alias completes in the Mach handler.

FEX's unaligned-atomic helpers (DoCAS, RunCASPAL in libarm64ecfex.dll) issue
`caspal x6, x7, x2, x3, [x0]` on guest memory from inside FEX's exception
handler. Stardew Valley's first save froze when that store hit a .NET
executable allocation that had just been copied into the pool again: the fault
went back to the guest, FEX ran the same CASPAL, and the nesting overflowed the
stack while FEX's ThreadCreationMutex was held.

Compiles the production ios_mach_emulate_casp from
build/ntdll-unix/signal_arm64_ios.c and runs it on a real shared RW mapping:
64-bit and 32-bit pairs, a failed compare, alignment, and encodings it must
decline. Also checks that the Mach store path calls it for both alias kinds.
Needs python3 and a C compiler for arm64 with LSE (AddressSanitizer/UBSan).
"""
from pathlib import Path
import os
import platform
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / 'build/ntdll-unix/signal_arm64_ios.c').read_text()


def function(signature):
    start = source.index(signature)
    return source[start:source.index('\n}', start) + 2] + '\n'


start = source.index('if (!emulated && (insn & 0xbfa07c00u) == 0x08207c00u)')
call = source[start:source.index('ios_mach_emulate_casp(insn, casp_rw, state.__x)', start)]
assert 'ios_jit_anon_alias_lookup( first )' in call and 'rw + (first - rx)' in call
assert 'casp_rw_end == casp_rw + casp_width - 1' in call

if platform.machine() not in ('arm64', 'aarch64'):
    print('SKIP: CASPAL needs an arm64 host')
    sys.exit(0)

code = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
''' + function('static int ios_mach_emulate_casp(uint32_t insn, uintptr_t rw_addr, uint64_t gpr[29])') + r'''
#define CASPAL_X6_X2_X0 0x4866fc02u   /* RunCASPAL+0xd8: caspal x6, x7, x2, x3, [x0] */
#define CASPAL_X6_X4_X11 0x4866fd64u  /* DoCAS+0xa00:    caspal x6, x7, x4, x5, [x11] */
int main(void)
{
    uint64_t *page = mmap(0, 0x4000, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANON, -1, 0);
    uint64_t g[29] = {0};
    assert(page != MAP_FAILED);
    page[0x1c0 / 8] = 11; page[0x1c8 / 8] = 22;
    uintptr_t cell = (uintptr_t)page + 0x1c0;

    g[6] = 11; g[7] = 22; g[2] = 33; g[3] = 44;
    assert(ios_mach_emulate_casp(CASPAL_X6_X2_X0, cell, g));
    assert(page[0x1c0 / 8] == 33 && page[0x1c8 / 8] == 44 && g[6] == 11 && g[7] == 22);

    g[6] = 1; g[7] = 2;                                   /* compare fails: old value returned */
    assert(ios_mach_emulate_casp(CASPAL_X6_X2_X0, cell, g));
    assert(page[0x1c0 / 8] == 33 && page[0x1c8 / 8] == 44 && g[6] == 33 && g[7] == 44);

    g[6] = 33; g[7] = 44; g[4] = 55; g[5] = 66;
    assert(ios_mach_emulate_casp(CASPAL_X6_X4_X11, cell, g));
    assert(page[0x1c0 / 8] == 55 && page[0x1c8 / 8] == 66);

    uint32_t *w = (uint32_t *)((uintptr_t)page + 0x200);  /* 32-bit pair */
    w[0] = 5; w[1] = 6; g[6] = 5; g[7] = 6; g[2] = 7; g[3] = 8;
    assert(ios_mach_emulate_casp(0x0866fc02u, (uintptr_t)w, g) && w[0] == 7 && w[1] == 8);

    assert(!ios_mach_emulate_casp(CASPAL_X6_X2_X0, cell + 8, g));      /* misaligned pair */
    assert(!ios_mach_emulate_casp(0x0866fc02u, (uintptr_t)w + 4, g));  /* misaligned 32-bit pair */
    assert(!ios_mach_emulate_casp(CASPAL_X6_X2_X0, 0, g));             /* no alias */
    assert(!ios_mach_emulate_casp(0x4867fc02u, cell, g));              /* odd Rs */
    assert(!ios_mach_emulate_casp(0x4866fc03u, cell, g));              /* odd Rt */
    assert(!ios_mach_emulate_casp(0x487cfc02u, cell, g));              /* Rs+1 is x29 */
    assert(!ios_mach_emulate_casp(0xc8e9fec8u, cell, g));              /* CASAL, not a pair */
    assert(page[0x1c0 / 8] == 55 && page[0x1c8 / 8] == 66);
    munmap(page, 0x4000);
    puts("PASS: CASPAL completes on the RW alias; misaligned and invalid encodings decline");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-mach-casp-') as tmp:
    src, exe = Path(tmp) / 'check.c', Path(tmp) / 'check'
    src.write_text(code)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                    '-march=armv8.1-a', '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                    str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
