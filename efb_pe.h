/* efb_pe.h - v0.1 - public domain data structures - nickscha 2025

Contains the PE-Format definitions

LICENSE

  Placed in the public domain and also MIT licensed.
  See end of file for detailed license information.

*/
#ifndef EFB_PE_H
#define EFB_PE_H

/* ------------------------------------ */
/* - PE32 Format Structs (32 & 64 bit)  */
/* ------------------------------------ */
#define EFB_PE_IMAGE_FILE_RELOCS_STRIPPED 0x0001
#define EFB_PE_IMAGE_FILE_EXECUTABLE_IMAGE 0x0002
#define EFB_PE_IMAGE_FILE_LARGE_ADDRESS_AWARE 0x0020
#define EFB_PE_IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
#define EFB_PE_IMAGE_SUBSYSTEM_NATIVE 1
#define EFB_PE_IMAGE_SUBSYSTEM_WINDOWS_GUI 2
#define EFB_PE_IMAGE_SUBSYSTEM_WINDOWS_CUI 3
#define EFB_PE_IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define EFB_PE_IMAGE_SCN_CNT_CODE 0x00000020
#define EFB_PE_IMAGE_SCN_MEM_EXECUTE 0x20000000
#define EFB_PE_IMAGE_SCN_MEM_READ 0x40000000
#define EFB_PE_IMAGE_FILE_MACHINE_I386 0x014c
#define EFB_PE_IMAGE_FILE_MACHINE_ARM64 0xaa64
#define EFB_PE_IMAGE_FILE_MACHINE_AMD64 0x8664

typedef struct EFB_PE_DOS_HEADER
{
    unsigned short e_magic;
    unsigned short e_cblp;
    unsigned short e_cp;
    unsigned short e_crlc;
    unsigned short e_cparhdr;
    unsigned short e_minalloc;
    unsigned short e_maxalloc;
    unsigned short e_ss;
    unsigned short e_sp;
    unsigned short e_csum;
    unsigned short e_ip;
    unsigned short e_cs;
    unsigned short e_lfarlc;
    unsigned short e_ovno;
    unsigned short e_res[4];
    unsigned short e_oemid;
    unsigned short e_oeminfo;
    unsigned short e_res2[10];
    long e_lfanew;

} EFB_PE_DOS_HEADER;

typedef struct EFB_PE_IMAGE_FILE_HEADER
{
    unsigned short Machine;
    unsigned short NumberOfSections;
    unsigned long TimeDateStamp;
    unsigned long PointerToSymbolTable;
    unsigned long NumberOfSymbols;
    unsigned short SizeOfOptionalHeader;
    unsigned short Characteristics;

} EFB_PE_IMAGE_FILE_HEADER;

typedef struct EFB_PE_IMAGE_DATA_DIRECTORY
{
    unsigned long VirtualAddress;
    unsigned long Size;

} EFB_PE_IMAGE_DATA_DIRECTORY;

typedef struct EFB_PE_IMAGE_SECTION_HEADER
{
    unsigned char Name[8];
    union
    {
        unsigned long PhysicalAddress;
        unsigned long VirtualSize;
    } Misc;
    unsigned long VirtualAddress;
    unsigned long SizeOfRawData;
    unsigned long PointerToRawData;
    unsigned long PointerToRelocations;
    unsigned long PointerToLinenumbers;
    unsigned short NumberOfRelocations;
    unsigned short NumberOfLinenumbers;
    unsigned long Characteristics;
} EFB_PE_IMAGE_SECTION_HEADER;

/* --------------------------------- */
/* - Optional Header (32bit)         */
/* --------------------------------- */
typedef struct EFB_PE_IMAGE_OPTIONAL_HEADER32
{
    unsigned short Magic;
    unsigned char MajorLinkerVersion;
    unsigned char MinorLinkerVersion;
    unsigned long SizeOfCode;
    unsigned long SizeOfInitializedData;
    unsigned long SizeOfUninitializedData;
    unsigned long AddressOfEntryPoint;
    unsigned long BaseOfCode;
    unsigned long BaseOfData;
    unsigned long ImageBase;
    unsigned long SectionAlignment;
    unsigned long FileAlignment;
    unsigned short MajorOperatingSystemVersion;
    unsigned short MinorOperatingSystemVersion;
    unsigned short MajorImageVersion;
    unsigned short MinorImageVersion;
    unsigned short MajorSubsystemVersion;
    unsigned short MinorSubsystemVersion;
    unsigned long Win32VersionValue;
    unsigned long SizeOfImage;
    unsigned long SizeOfHeaders;
    unsigned long CheckSum;
    unsigned short Subsystem;
    unsigned short DllCharacteristics;
    unsigned long SizeOfStackReserve;
    unsigned long SizeOfStackCommit;
    unsigned long SizeOfHeapReserve;
    unsigned long SizeOfHeapCommit;
    unsigned long LoaderFlags;
    unsigned long NumberOfRvaAndSizes;
    EFB_PE_IMAGE_DATA_DIRECTORY DataDirectory[EFB_PE_IMAGE_NUMBEROF_DIRECTORY_ENTRIES];

} EFB_PE_IMAGE_OPTIONAL_HEADER32;

typedef struct EFB_PE_IMAGE_NT_HEADERS32
{
    unsigned long Signature;
    EFB_PE_IMAGE_FILE_HEADER FileHeader;
    EFB_PE_IMAGE_OPTIONAL_HEADER32 OptionalHeader;

} EFB_PE_IMAGE_NT_HEADERS32;

/* --------------------------------- */
/* - Optional Header (64bit)         */
/* --------------------------------- */
typedef struct EFB_PE_IMAGE_OPTIONAL_HEADER64
{
    unsigned short Magic;
    unsigned char MajorLinkerVersion;
    unsigned char MinorLinkerVersion;
    unsigned long SizeOfCode;
    unsigned long SizeOfInitializedData;
    unsigned long SizeOfUninitializedData;
    unsigned long AddressOfEntryPoint;
    unsigned long BaseOfCode;
    unsigned long ImageBaseLowPart;
    unsigned long ImageBaseHighPart;
    unsigned long SectionAlignment;
    unsigned long FileAlignment;
    unsigned short MajorOperatingSystemVersion;
    unsigned short MinorOperatingSystemVersion;
    unsigned short MajorImageVersion;
    unsigned short MinorImageVersion;
    unsigned short MajorSubsystemVersion;
    unsigned short MinorSubsystemVersion;
    unsigned long Win32VersionValue;
    unsigned long SizeOfImage;
    unsigned long SizeOfHeaders;
    unsigned long CheckSum;
    unsigned short Subsystem;
    unsigned short DllCharacteristics;
    unsigned long SizeOfStackReserveLowPart;
    unsigned long SizeOfStackReserveHighPart;
    unsigned long SizeOfStackCommitLowPart;
    unsigned long SizeOfStackCommitHighPart;
    unsigned long SizeOfHeapReserveLowPart;
    unsigned long SizeOfHeapReserveHighPart;
    unsigned long SizeOfHeapCommitLowPart;
    unsigned long SizeOfHeapCommitHighPart;
    unsigned long LoaderFlags;
    unsigned long NumberOfRvaAndSizes;
    EFB_PE_IMAGE_DATA_DIRECTORY DataDirectory[EFB_PE_IMAGE_NUMBEROF_DIRECTORY_ENTRIES];

} EFB_PE_IMAGE_OPTIONAL_HEADER64;

typedef struct EFB_PE_IMAGE_NT_HEADERS64
{
    unsigned long Signature;
    EFB_PE_IMAGE_FILE_HEADER FileHeader;
    EFB_PE_IMAGE_OPTIONAL_HEADER64 OptionalHeader;

} EFB_PE_IMAGE_NT_HEADERS64;

#endif /* EFB_PE_H */

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
