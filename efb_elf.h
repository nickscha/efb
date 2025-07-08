/* efb_elf.h - v0.1 - public domain data structures - nickscha 2025

Contains elf format definitions.

LICENSE

  Placed in the public domain and also MIT licensed.
  See end of file for detailed license information.

*/
#ifndef EFB_ELF_H
#define EFB_ELF_H

#define EFB_ELF_CODE_VADDR 0x400000 + 0x80
#define EFB_ELF_ALIGN 0x1000

#define EFB_ELF64_MAGIC0 0x7f
#define EFB_ELF64_MAGIC1 'E'
#define EFB_ELF64_MAGIC2 'L'
#define EFB_ELF64_MAGIC3 'F'
#define EFB_ELF64_CLASS 2 /* 64-bit */
#define EFB_ELF64_DATA 1  /* little endian */
#define EFB_ELF64_VERSION 1
#define EFB_ELF64_OSABI 0
#define EFB_ELF64_TYPE_EXEC 2
#define EFB_ELF64_MACHINE_X86_64 62
#define EFB_ELF64_PT_LOAD 1
#define EFB_ELF64_PF_X 1
#define EFB_ELF64_PF_W 2
#define EFB_ELF64_PF_R 4

#define EFB_ELF64_IDENT_SIZE 16

typedef struct EFB_ELF64_EHDR
{
  unsigned char e_ident[EFB_ELF64_IDENT_SIZE];
  unsigned short e_type;
  unsigned short e_machine;
  unsigned int e_version;
  unsigned long e_entry;
  unsigned long e_phoff;
  unsigned long e_shoff;
  unsigned int e_flags;
  unsigned short e_ehsize;
  unsigned short e_phentsize;
  unsigned short e_phnum;
  unsigned short e_shentsize;
  unsigned short e_shnum;
  unsigned short e_shstrndx;

} EFB_ELF64_EHDR;

typedef struct EFB_ELF64_PHDR
{
  unsigned int p_type;
  unsigned int p_flags;
  unsigned long p_offset;
  unsigned long p_vaddr;
  unsigned long p_paddr;
  unsigned long p_filesz;
  unsigned long p_memsz;
  unsigned long p_align;

} EFB_ELF64_PHDR;

#endif /* EFB_ELF_H */

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
