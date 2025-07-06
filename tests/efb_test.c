/* efb.h - v0.1 - public domain data structures - nickscha 2025

A C89 standard compliant, single header, nostdlib (no C Standard Library) executable file/format builder (EFB).

This Test class defines cases to verify that we don't break the excepted behaviours in the future upon changes.

LICENSE

  Placed in the public domain and also MIT licensed.
  See end of file for detailed license information.

*/
#include "../efb.h"

#include "test.h" /* Simple Testing framework */

void efb_test_hello_world(void)
{
  /* x64 Windows syscall-based hello world (hardcoded IAT & handles) */
  static unsigned char machine_code_hello[] = {
      /* sub rsp, 0x28 (shadow space) */
      0x48, 0x83, 0xEC, 0x28,

      /* mov ecx, -11 (STD_OUTPUT_HANDLE) */
      0xB9, 0xF5, 0xFF, 0xFF, 0xFF,

      /* call GetStdHandle (at RIP + offset) */
      0xE8, 0x1B, 0x00, 0x00, 0x00, /* offset to GetStdHandle */

      /* mov rcx, rax ; handle */
      0x48, 0x89, 0xC1,

      /* lea rdx, [rip + str_offset] ; message */
      0x48, 0x8D, 0x15, 0x1B, 0x00, 0x00, 0x00,

      /* mov r8d, 13 ; string length */
      0x41, 0xB8, 0x0D, 0x00, 0x00, 0x00,

      /* lea r9, [rsp + 0x20] ; lpNumberOfCharsWritten */
      0x4C, 0x8D, 0x4C, 0x24, 0x20,

      /* xor rax, rax ; lpReserved = NULL */
      0x48, 0x31, 0xC0,

      /* call WriteConsoleA */
      0xE8, 0x1A, 0x00, 0x00, 0x00,

      /* mov ecx, 0 ; ExitProcess(0) */
      0xB9, 0x00, 0x00, 0x00, 0x00,

      /* call ExitProcess */
      0xE8, 0x17, 0x00, 0x00, 0x00,

      /* add rsp, 0x28 ; restore stack */
      0x48, 0x83, 0xC4, 0x28,

      /* ret */
      0xC3,

      /* --- string "Hello, world!\n" --- */
      'H', 'e', 'l', 'l', 'o', ',', ' ', 'w', 'o', 'r', 'l', 'd', '!', '\n',

      /* --- IAT (Import Address Table) --- */
      /* (dummy placeholder function pointers to patch manually or resolve dynamically if desired) */
  };

  assert(efb_build_executable("hello_world.exe", machine_code_hello, sizeof(machine_code_hello)));
}

int main(void)
{
  /*
  ret
  */
  unsigned char machine_code_ret_undefined[] = {0xC3};

  /*
  mov eax, 0;
  ret
  */
  unsigned char machine_code_ret_valid[] = {0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3};

  /*
  ud2
  */
  unsigned char machine_code_illegal_opcode[] = {0x0F, 0x0B};

  /*
  jmp $
  */
  unsigned char machine_code_infinite_loop[] = {0xEB, 0xFE};

  /* Build executable format */
  assert(efb_build_executable("ret_undefined.exe", machine_code_ret_undefined, sizeof(machine_code_ret_undefined)));
  assert(efb_build_executable("ret_valid.exe", machine_code_ret_valid, sizeof(machine_code_ret_valid)));
  assert(efb_build_executable("illegal_opcode.exe", machine_code_illegal_opcode, sizeof(machine_code_illegal_opcode)));
  assert(efb_build_executable("infinite_loop.exe", machine_code_infinite_loop, sizeof(machine_code_infinite_loop)));

  efb_test_hello_world();

  return 0;
}

/*
   ------------------------------------------------------------------------------
   This software is available under 2 licenses -- choose whichever you prefer.
   ------------------------------------------------------------------------------
   ALTERNATIVE A - MIT License
   Copyright (c) 2025 nickscha
   Permission is hereby granted, free of charge, to any person obtaining a copy of
   this software and associated documentation files (the "Software"), to deal in
   the Software without restriction, including without limitation the rights to
   use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
   of the Software, and to permit persons to whom the Software is furnished to do
   so, subject to the following conditions:
   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.
   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
   ------------------------------------------------------------------------------
   ALTERNATIVE B - Public Domain (www.unlicense.org)
   This is free and unencumbered software released into the public domain.
   Anyone is free to copy, modify, publish, use, compile, sell, or distribute this
   software, either in source code form or as a compiled binary, for any purpose,
   commercial or non-commercial, and by any means.
   In jurisdictions that recognize copyright laws, the author or authors of this
   software dedicate any and all copyright interest in the software to the public
   domain. We make this dedication for the benefit of the public at large and to
   the detriment of our heirs and successors. We intend this dedication to be an
   overt act of relinquishment in perpetuity of all present and future rights to
   this software under copyright law.
   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
   ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
   WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
   ------------------------------------------------------------------------------
*/
