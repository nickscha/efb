/* efb.h - v0.1 - public domain data structures - nickscha 2025

A C89 standard compliant, single header, nostdlib (no C Standard Library) executable file/format builder (EFB).

This Test class defines cases to verify that we don't break the excepted behaviours in the future upon changes.

LICENSE

  Placed in the public domain and also MIT licensed.
  See end of file for detailed license information.

*/
#include "../efb.h"                /* Executable File Builder */
#include "../efb_platform_write.h" /* Optional: OS-Specific write file implementations */

#include "test.h" /* Simple Testing framework */

int main(void)
{
  /*
  ret
  */
  unsigned char machine_code_ret_undefined[] = {0xC3};

  /*
  mov eax, 0
  ret
  */
  unsigned char machine_code_ret_valid[] = {0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3};

  /*
  ud2
  */
  unsigned char machine_code_ud2[] = {0x0F, 0x0B};

  /*
  jmp $
  */
  unsigned char machine_code_infinite_loop[] = {0xEB, 0xFE};

  /*
  int 3
  jmp $
  */
  unsigned char machine_code_debug[] = {0xCC, 0xEB, 0xFE};

#define BINARY_CAPACITY 4096
  unsigned char binary_buffer[BINARY_CAPACITY];

  efb_model model = {0};
  model.arch = EFB_ARCH_X86_64;
  model.format = EFB_FORMAT_PE;
  model.out_binary = binary_buffer;
  model.out_binary_capacity = BINARY_CAPACITY;
  model.code = machine_code_ret_undefined;
  model.code_size = sizeof(machine_code_ret_undefined);

  assert(efb_build(&model));
  assert(efb_platform_write("ret_undefined.exe", model.out_binary, model.out_binary_size));

  model.code = machine_code_ret_valid;
  model.code_size = sizeof(machine_code_ret_valid);
  assert(efb_build(&model));
  assert(efb_platform_write("ret_valid.exe", model.out_binary, model.out_binary_size));

  model.code = machine_code_ud2;
  model.code_size = sizeof(machine_code_ud2);
  assert(efb_build(&model));
  assert(efb_platform_write("ud2.exe", model.out_binary, model.out_binary_size));

  model.code = machine_code_infinite_loop;
  model.code_size = sizeof(machine_code_infinite_loop);
  assert(efb_build(&model));
  assert(efb_platform_write("infinite_loop.exe", model.out_binary, model.out_binary_size));

  model.code = machine_code_debug;
  model.code_size = sizeof(machine_code_debug);
  assert(efb_build(&model));
  assert(efb_platform_write("debug.exe", model.out_binary, model.out_binary_size));

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
