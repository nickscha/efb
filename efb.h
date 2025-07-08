/* efb.h - v0.1 - public domain data structures - nickscha 2025

A C89 standard compliant, single header, nostdlib (no C Standard Library) executable file/format builder (EFB).

LICENSE

  Placed in the public domain and also MIT licensed.
  See end of file for detailed license information.

*/
#ifndef EFB_H
#define EFB_H

#include "efb_elf.h" /* ELF-Format for Linux/Unix/... */
#include "efb_pe.h"  /* PE-Format for Windows         */

/* #############################################################################
 * # COMPILER SETTINGS
 * #############################################################################
 */
/* Check if using C99 or later (inline is supported) */
#if __STDC_VERSION__ >= 199901L
#define EFB_INLINE inline
#define EFB_API extern
#elif defined(__GNUC__) || defined(__clang__)
#define EFB_INLINE __inline__
#define EFB_API static
#elif defined(_MSC_VER)
#define EFB_INLINE __inline
#define EFB_API static
#else
#define EFB_INLINE
#define EFB_API static
#endif

typedef int efb_bool;

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif

#ifndef EFB_MAX_EXECUTABLE_SIZE
#define EFB_MAX_EXECUTABLE_SIZE 8192
#endif

#define EFB_ALIGN_UP(val, align) (((val) + (align) - 1) & ~((align) - 1))

EFB_API EFB_INLINE void efb_zero_memory(unsigned char *buffer, unsigned long size)
{
  unsigned long i;
  for (i = 0; i < size; ++i)
  {
    buffer[i] = 0;
  }
}

EFB_API EFB_INLINE efb_bool efb_build_elf(char *out_file_name, unsigned char *text_section, unsigned long text_section_size)
{
  efb_bool ended = false;

  unsigned long i;
  void *hFile;
  unsigned long bytes_written = 0;

  EFB_ELF64_EHDR *ehdr;
  EFB_ELF64_PHDR *phdr;
  unsigned char *code_dest;

  unsigned long code_offset = 0x80;
  unsigned long file_size = code_offset + text_section_size;

  unsigned char elf_buffer[EFB_MAX_EXECUTABLE_SIZE];
  efb_zero_memory(elf_buffer, sizeof(elf_buffer));

  ehdr = (EFB_ELF64_EHDR *)elf_buffer;
  phdr = (EFB_ELF64_PHDR *)(elf_buffer + sizeof(EFB_ELF64_EHDR));
  code_dest = elf_buffer + 0x80;

  ehdr->e_ident[0] = EFB_ELF64_MAGIC0;
  ehdr->e_ident[1] = EFB_ELF64_MAGIC1;
  ehdr->e_ident[2] = EFB_ELF64_MAGIC2;
  ehdr->e_ident[3] = EFB_ELF64_MAGIC3;
  ehdr->e_ident[4] = EFB_ELF64_CLASS;
  ehdr->e_ident[5] = EFB_ELF64_DATA;
  ehdr->e_ident[6] = EFB_ELF64_VERSION;
  ehdr->e_ident[7] = EFB_ELF64_OSABI;

  ehdr->e_type = EFB_ELF64_TYPE_EXEC;
  ehdr->e_machine = EFB_ELF64_MACHINE_X86_64;
  ehdr->e_version = EFB_ELF64_VERSION;
  ehdr->e_entry = EFB_ELF_CODE_VADDR;
  ehdr->e_phoff = sizeof(EFB_ELF64_EHDR);
  ehdr->e_ehsize = sizeof(EFB_ELF64_EHDR);
  ehdr->e_phentsize = sizeof(EFB_ELF64_PHDR);
  ehdr->e_phnum = 1;

  phdr->p_type = EFB_ELF64_PT_LOAD;
  phdr->p_flags = EFB_ELF64_PF_R | EFB_ELF64_PF_X;
  phdr->p_offset = 0x0;
  phdr->p_vaddr = 0x400000;
  phdr->p_paddr = 0x400000;
  phdr->p_filesz = 0x80 + text_section_size;
  phdr->p_memsz = 0x80 + text_section_size;
  phdr->p_align = EFB_ELF_ALIGN;

  /* Write code */
  for (i = 0; i < text_section_size; ++i)
  {
    code_dest[i] = text_section[i];
  }

  /* === Write to File === */
  hFile = CreateFileA(out_file_name, EFB_WIN32_GENERIC_WRITE, 0, 0, EFB_WIN32_CREATE_ALWAYS, EFB_WIN32_FILE_ATTRIBUTE_NORMAL, 0);
  ended = (WriteFile(hFile, elf_buffer, file_size, &bytes_written, 0) != 0) && (bytes_written == file_size);
  CloseHandle(hFile);

  return ended;
}

EFB_API EFB_INLINE efb_bool efb_build_executable(char *out_file_name, unsigned char *text_section, unsigned long text_section_size)
{
  unsigned char efb_buffer[EFB_MAX_EXECUTABLE_SIZE];

  void *hFile;
  unsigned long bytes_written;

  /* Constants */
  unsigned long file_align = 0x200;
  unsigned long section_align = 0x1000;
  unsigned long code_va = 0x1000;
  unsigned long entry_point_rva = code_va;
  unsigned short machine_type = EFB_PE_IMAGE_FILE_MACHINE_AMD64;

  /* Header sizes */
  long nt_headers_offset = 0x40;
  unsigned long raw_size = EFB_ALIGN_UP(text_section_size, file_align);
  unsigned long virtual_size = EFB_ALIGN_UP(text_section_size, section_align);
  unsigned long size_of_headers = EFB_ALIGN_UP(0x200, file_align);
  unsigned long size_of_image = EFB_ALIGN_UP(code_va + virtual_size, section_align);
  unsigned long file_size = size_of_headers + raw_size;

  EFB_PE_DOS_HEADER *dos;
  EFB_PE_IMAGE_NT_HEADERS64 *nt;
  EFB_PE_IMAGE_SECTION_HEADER *section;

  unsigned char *code_dest;
  unsigned long i;

  efb_bool ended = false;

  if (!out_file_name || !text_section)
  {

    return (ended);
  }

  /* Fail if file_size exceeds static buffer*/
  if (file_size > EFB_MAX_EXECUTABLE_SIZE)
  {
    return (ended);
  }

  efb_zero_memory(efb_buffer, file_size);

  /* === DOS Header === */
  dos = (EFB_PE_DOS_HEADER *)efb_buffer;
  dos->e_magic = 0x5A4D; /* 'MZ' */
  dos->e_lfanew = nt_headers_offset;

  /* === NT Headers === */
  nt = (EFB_PE_IMAGE_NT_HEADERS64 *)(efb_buffer + nt_headers_offset);
  nt->Signature = 0x00004550; /* 'PE\0\0' */

  nt->FileHeader.Machine = machine_type;
  nt->FileHeader.NumberOfSections = 1;
  nt->FileHeader.SizeOfOptionalHeader = sizeof(EFB_PE_IMAGE_OPTIONAL_HEADER64);
  nt->FileHeader.Characteristics = EFB_PE_IMAGE_FILE_EXECUTABLE_IMAGE | EFB_PE_IMAGE_FILE_RELOCS_STRIPPED | EFB_PE_IMAGE_FILE_LARGE_ADDRESS_AWARE;

  nt->OptionalHeader.Magic = EFB_PE_IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  nt->OptionalHeader.MajorLinkerVersion = 14;
  nt->OptionalHeader.MinorLinkerVersion = 0;
  nt->OptionalHeader.SizeOfCode = raw_size;
  nt->OptionalHeader.AddressOfEntryPoint = entry_point_rva;
  nt->OptionalHeader.BaseOfCode = code_va;
  nt->OptionalHeader.ImageBaseLowPart = 0x40000000; /* 0x140000000 */
  nt->OptionalHeader.ImageBaseHighPart = 0x1;       /* 0x140000000 */
  nt->OptionalHeader.SectionAlignment = section_align;
  nt->OptionalHeader.FileAlignment = file_align;
  nt->OptionalHeader.MajorOperatingSystemVersion = 6;
  nt->OptionalHeader.MinorOperatingSystemVersion = 0;
  nt->OptionalHeader.MajorSubsystemVersion = 6;
  nt->OptionalHeader.MinorSubsystemVersion = 0;
  nt->OptionalHeader.SizeOfImage = size_of_image;
  nt->OptionalHeader.SizeOfHeaders = size_of_headers;
  nt->OptionalHeader.Subsystem = EFB_PE_IMAGE_SUBSYSTEM_WINDOWS_CUI;
  nt->OptionalHeader.NumberOfRvaAndSizes = EFB_PE_IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

  /* === Section Header ===*/
  section = (EFB_PE_IMAGE_SECTION_HEADER *)((unsigned char *)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
  section->Name[0] = '.';
  section->Name[1] = 't';
  section->Name[2] = 'e';
  section->Name[3] = 'x';
  section->Name[4] = 't';
  section->Misc.VirtualSize = text_section_size;
  section->VirtualAddress = code_va;
  section->SizeOfRawData = raw_size;
  section->PointerToRawData = size_of_headers;
  section->Characteristics = EFB_PE_IMAGE_SCN_CNT_CODE | EFB_PE_IMAGE_SCN_MEM_EXECUTE | EFB_PE_IMAGE_SCN_MEM_READ;

  /* === Write Code ===*/
  code_dest = efb_buffer + size_of_headers;
  for (i = 0; i < text_section_size; ++i)
  {
    code_dest[i] = text_section[i];
  }

  /* === Write to File === */
  hFile = CreateFileA(out_file_name, EFB_WIN32_GENERIC_WRITE, 0, 0, EFB_WIN32_CREATE_ALWAYS, EFB_WIN32_FILE_ATTRIBUTE_NORMAL, 0);
  ended = (WriteFile(hFile, efb_buffer, file_size, &bytes_written, 0) != 0) && (bytes_written == file_size);
  ended = CloseHandle(hFile);

  return (ended);
}

#endif /* EFB_H */

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
