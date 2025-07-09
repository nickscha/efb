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

#define EFB_ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* Copies a string literal into a buffer, returns pointer after the last copied char */
#define EFB_STRCPY(dest, src) \
  do                          \
  {                           \
    char *_s = (src);         \
    char *_d = (dest);        \
    while (*_s)               \
    {                         \
      *_d++ = *_s++;          \
    }                         \
    *_d = '\0';               \
  } while (0)

/* Appends a suffix to a buffer (assumes enough space) */
#define EFB_APPEND_SUFFIX(dest, suffix) \
  do                                    \
  {                                     \
    char *_d = (dest);                  \
    char *_suf;                         \
    while (*_d)                         \
      _d++;                             \
    _suf = (suffix);                    \
    while (*_suf)                       \
    {                                   \
      *_d++ = *_suf++;                  \
    }                                   \
    *_d = '\0';                         \
  } while (0)

typedef struct efb_machine_codes
{
  unsigned char code[64];
  unsigned int code_size;
  char basename[64];
} efb_machine_codes;

#define BINARY_CAPACITY 4096
unsigned char binary_buffer[BINARY_CAPACITY];

void efb_test_build_executables(efb_arch arch, efb_format format, efb_machine_codes *machine_codes, int machine_codes_size)
{
  char filename[256];
  int i;

  efb_model model = {0};
  model.arch = arch;
  model.format = format;
  model.out_binary = binary_buffer;
  model.out_binary_capacity = BINARY_CAPACITY;

  for (i = 0; i < machine_codes_size; ++i)
  {
    model.code = machine_codes[i].code;
    model.code_size = machine_codes[i].code_size;

    assert(efb_build(&model));

    /* Copy base name */
    EFB_STRCPY(filename, machine_codes[i].basename);

    /* Append suffix based on architecture */
    switch (model.arch)
    {
    case EFB_ARCH_I386:
      EFB_APPEND_SUFFIX(filename, "_i386");
      break;
    case EFB_ARCH_X86_64:
      EFB_APPEND_SUFFIX(filename, "_x86_64");
      break;
    case EFB_ARCH_AARCH64:
      EFB_APPEND_SUFFIX(filename, "_arm64");
      break;
    default:
      break;
    }

    /* Append suffix based on format */
    switch (model.format)
    {
    case EFB_FORMAT_PE:
      EFB_APPEND_SUFFIX(filename, ".exe");
      break;
    case EFB_FORMAT_ELF:
      EFB_APPEND_SUFFIX(filename, ".out");
      break;
    case EFB_FORMAT_MACHO:
      EFB_APPEND_SUFFIX(filename, ".o");
      break;
    default:
      break;
    }

    assert(efb_platform_write(filename, model.out_binary, model.out_binary_size));
  }
}

int main(void)
{
  efb_machine_codes machine_codes_i386[] = {
      {{0xC3}, 1, "ret_undefined"},                           /* ret */
      {{0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3}, 6, "ret_valid"}, /* mov eax, 0; ret */
      {{0x0F, 0x0B}, 2, "ud2"},                               /* ud2 */
      {{0xEB, 0xFE}, 2, "infinite_loop"},                     /* jmp $ */
      {{0xCC, 0xEB, 0xFE}, 3, "debug"},                       /* int3; jmp $ */
  };

  efb_machine_codes machine_codes_x86_64[] = {
      {{0xC3}, 1, "ret_undefined"},                           /* ret */
      {{0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3}, 6, "ret_valid"}, /* mov eax, 0; ret */
      {{0x0F, 0x0B}, 2, "ud2"},                               /* ud2 */
      {{0xEB, 0xFE}, 2, "infinite_loop"},                     /* jmp $ */
      {{0xCC, 0xEB, 0xFE}, 3, "debug"},                       /* int 3; jmp $ */
  };

  efb_machine_codes machine_codes_arm64[] = {
      {{0xC0, 0x03, 0x5F, 0xD6}, 4, "ret_undefined"},                     /* ret */
      {{0x00, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6}, 8, "ret_valid"}, /* movz x0, #0; ret */
      {{0x00, 0x00, 0x20, 0xD4}, 4, "udf"},                               /* brk #0 (used as undefined/trap) */
      {{0x00, 0x00, 0x00, 0x14}, 4, "infinite_loop"},                     /* b . (branch to self) */
      {{0x00, 0x00, 0x20, 0xD4, 0x00, 0x00, 0x00, 0x14}, 8, "debug"}      /* brk #0; b . */
  };

  efb_test_build_executables(EFB_ARCH_I386, EFB_FORMAT_PE, machine_codes_i386, EFB_ARRAY_SIZE(machine_codes_i386));
  efb_test_build_executables(EFB_ARCH_I386, EFB_FORMAT_ELF, machine_codes_i386, EFB_ARRAY_SIZE(machine_codes_i386));
  efb_test_build_executables(EFB_ARCH_X86_64, EFB_FORMAT_PE, machine_codes_x86_64, EFB_ARRAY_SIZE(machine_codes_x86_64));
  efb_test_build_executables(EFB_ARCH_X86_64, EFB_FORMAT_ELF, machine_codes_x86_64, EFB_ARRAY_SIZE(machine_codes_x86_64));
  efb_test_build_executables(EFB_ARCH_AARCH64, EFB_FORMAT_PE, machine_codes_arm64, EFB_ARRAY_SIZE(machine_codes_arm64));
  efb_test_build_executables(EFB_ARCH_AARCH64, EFB_FORMAT_ELF, machine_codes_arm64, EFB_ARRAY_SIZE(machine_codes_arm64));

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
