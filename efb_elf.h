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

#define EFB_ELF_MAGIC0 0x7f
#define EFB_ELF_MAGIC1 'E'
#define EFB_ELF_MAGIC2 'L'
#define EFB_ELF_MAGIC3 'F'
#define EFB_ELF_CLASS32 1
#define EFB_ELF_CLASS64 2
#define EFB_ELF_DATA 1 /* little endian */
#define EFB_ELF_VERSION 1
#define EFB_ELF_OSABI 0
#define EFB_ELF_TYPE_EXEC 2
#define EFB_ELF_MACHINE_386 3
#define EFB_ELF_MACHINE_X86_64 62
#define EFB_ELF_MACHINE_AARCH64 183
#define EFB_ELF_PT_LOAD 1
#define EFB_ELF_PF_X 1
#define EFB_ELF_PF_W 2
#define EFB_ELF_PF_R 4

#define EFB_ELF_IDENT_SIZE 16

/* ELF32 Header (Executable + Linkable Format) */
typedef struct EFB_ELF32_EHDR
{
  unsigned char e_ident[EFB_ELF_IDENT_SIZE]; /* Magic number and other info */
  unsigned short e_type;                     /* Object file type */
  unsigned short e_machine;                  /* Architecture */
  unsigned int e_version;                    /* Object file version */
  unsigned int e_entry;                      /* Entry point virtual address */
  unsigned int e_phoff;                      /* Program header table file offset */
  unsigned int e_shoff;                      /* Section header table file offset */
  unsigned int e_flags;                      /* Processor-specific flags */
  unsigned short e_ehsize;                   /* ELF header size in bytes */
  unsigned short e_phentsize;                /* Program header table entry size */
  unsigned short e_phnum;                    /* Program header table entry count */
  unsigned short e_shentsize;                /* Section header table entry size */
  unsigned short e_shnum;                    /* Section header table entry count */
  unsigned short e_shstrndx;                 /* Section header string table index */

} EFB_ELF32_EHDR;

/* ELF32 Program Header */
typedef struct EFB_ELF32_PHDR
{
  unsigned int p_type;   /* Segment type */
  unsigned int p_offset; /* Segment file offset */
  unsigned int p_vaddr;  /* Segment virtual address */
  unsigned int p_paddr;  /* Segment physical address */
  unsigned int p_filesz; /* Segment size in file */
  unsigned int p_memsz;  /* Segment size in memory */
  unsigned int p_flags;  /* Segment flags */
  unsigned int p_align;  /* Segment alignment */

} EFB_ELF32_PHDR;

/* Section header (not required for minimal executables) */
typedef struct EFB_ELF32_SHDR
{
  unsigned int sh_name;      /* Offset to section name in the section header string table */
  unsigned int sh_type;      /* Section type (e.g., SHT_PROGBITS, SHT_SYMTAB) */
  unsigned int sh_flags;     /* Section attributes/flags (e.g., SHF_WRITE, SHF_ALLOC) */
  unsigned int sh_addr;      /* Virtual address in memory where the section will reside */
  unsigned int sh_offset;    /* Offset in the file where the section starts */
  unsigned int sh_size;      /* Size of the section in bytes */
  unsigned int sh_link;      /* Section index of a related section (e.g., symbol table link) */
  unsigned int sh_info;      /* Extra information (usage varies by section type) */
  unsigned int sh_addralign; /* Required alignment of the section in memory */
  unsigned int sh_entsize;   /* Size of each entry for sections with fixed-size entries (e.g., symbol tables) */

} EFB_ELF32_SHDR;

typedef struct EFB_ELF64_EHDR
{
  unsigned char e_ident[EFB_ELF_IDENT_SIZE]; /* ELF identification bytes (magic number, architecture, etc.) */
  unsigned short e_type;                     /* Object file type (e.g., ET_EXEC for executable) */
  unsigned short e_machine;                  /* Target architecture (e.g., EM_X86_64, EM_AARCH64) */
  unsigned int e_version;                    /* Object file version (usually 1) */
  unsigned long e_entry;                     /* Entry point virtual address for the program */
  unsigned long e_phoff;                     /* Offset to the program header table in the file */
  unsigned long e_shoff;                     /* Offset to the section header table in the file */
  unsigned int e_flags;                      /* Processor-specific flags */
  unsigned short e_ehsize;                   /* Size of this ELF header */
  unsigned short e_phentsize;                /* Size of one entry in the program header table */
  unsigned short e_phnum;                    /* Number of entries in the program header table */
  unsigned short e_shentsize;                /* Size of one entry in the section header table */
  unsigned short e_shnum;                    /* Number of entries in the section header table */
  unsigned short e_shstrndx;                 /* Index of the section header string table */

} EFB_ELF64_EHDR;

typedef struct EFB_ELF64_PHDR
{
  unsigned int p_type;    /* Segment type (e.g., PT_LOAD for loadable segment) */
  unsigned int p_flags;   /* Segment flags (e.g., PF_R, PF_W, PF_X) */
  unsigned long p_offset; /* Offset in the file where the segment begins */
  unsigned long p_vaddr;  /* Virtual address of the segment in memory */
  unsigned long p_paddr;  /* Physical address (not usually used on modern systems) */
  unsigned long p_filesz; /* Size of the segment in the file */
  unsigned long p_memsz;  /* Size of the segment in memory */
  unsigned long p_align;  /* Alignment of the segment in memory and file */

} EFB_ELF64_PHDR;

typedef struct EFB_ELF64_SHDR
{
  unsigned int sh_name;       /* Section name (string table index) */
  unsigned int sh_type;       /* Section type */
  unsigned long sh_flags;     /* Section flags */
  unsigned long sh_addr;      /* Section virtual address at execution */
  unsigned long sh_offset;    /* Section file offset */
  unsigned long sh_size;      /* Section size in bytes */
  unsigned int sh_link;       /* Link to another section */
  unsigned int sh_info;       /* Additional section information */
  unsigned long sh_addralign; /* Section alignment */
  unsigned long sh_entsize;   /* Entry size if section holds table */

} EFB_ELF64_SHDR;

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
