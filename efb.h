/* efb.h - v0.2 - public domain data structures - nickscha 2025

A C89 standard compliant, single header, nostdlib (no C Standard Library) executable file/format builder (EFB).

LICENSE

  Placed in the public domain and also MIT licensed.
  See end of file for detailed license information.

*/
#ifndef EFB_H
#define EFB_H

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

/* ------------------------------------ */
/* - PE Format Structs (32 & 64 bit)  */
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

/* ------------------------------------ */
/* - ELF Format Structs (32 & 64 bit)   */
/* ------------------------------------ */
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

/* ------------------------------------ */
/* - MACH-O Format Structs (32 & 64 bit)*/
/* ------------------------------------ */

/* ------------------------------------ */
/* - EFB Model Structures               */
/* ------------------------------------ */
typedef enum efb_arch
{
  EFB_ARCH_I386,
  EFB_ARCH_X86_64,
  EFB_ARCH_AARCH64,
  EFB_ARCH_COUNT

} efb_arch;

typedef enum efb_format
{
  EFB_FORMAT_PE,
  EFB_FORMAT_ELF,
  EFB_FORMAT_MACHO,
  EFB_FORMAT_COUNT

} efb_format;

typedef struct efb_model
{
  efb_arch arch;                     /* Target architecture */
  efb_format format;                 /* Executable format */
  unsigned char *code;               /* Pointer to machine code */
  unsigned long code_size;           /* Size of machine code */
  unsigned char *out_binary;         /* Output buffer for executable */
  unsigned long out_binary_capacity; /* Capacity of output buffer */
  unsigned long out_binary_size;     /* Actual size of output */

} efb_model;

typedef int efb_bool;

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
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

EFB_API EFB_INLINE efb_bool efb_build_pe(efb_model *model)
{
  /* Constants */
  unsigned long file_align = 0x200;
  unsigned long section_align = 0x1000;
  unsigned long code_va = 0x1000;
  unsigned long entry_point_rva = code_va;

  /* Header sizes */
  long nt_headers_offset = 0x40;
  unsigned long raw_size = EFB_ALIGN_UP(model->code_size, file_align);
  unsigned long virtual_size = EFB_ALIGN_UP(model->code_size, section_align);
  unsigned long size_of_headers = EFB_ALIGN_UP(0x200, file_align);
  unsigned long size_of_image = EFB_ALIGN_UP(code_va + virtual_size, section_align);
  unsigned long file_size = size_of_headers + raw_size;

  EFB_PE_DOS_HEADER *dos;
  EFB_PE_IMAGE_NT_HEADERS64 *nt;
  EFB_PE_IMAGE_SECTION_HEADER *section;

  unsigned char *code_dest;
  unsigned long i;
  unsigned short machine_type;

  efb_bool is_64 = true;
  efb_bool ended = false;

  switch (model->arch)
  {
  case EFB_ARCH_I386:
    machine_type = EFB_PE_IMAGE_FILE_MACHINE_I386;
    is_64 = false;
    break;
  case EFB_ARCH_X86_64:
    machine_type = EFB_PE_IMAGE_FILE_MACHINE_AMD64;
    break;
  case EFB_ARCH_AARCH64:
    machine_type = EFB_PE_IMAGE_FILE_MACHINE_ARM64;
    break;
  default:
    return ended;
  }

  /* Fail if file_size exceeds static buffer*/
  if (file_size > model->out_binary_capacity)
  {
    return (ended);
  }

  efb_zero_memory(model->out_binary, file_size);
  model->out_binary_size = 0;

  /* === DOS Header === */
  dos = (EFB_PE_DOS_HEADER *)model->out_binary;
  dos->e_magic = 0x5A4D; /* 'MZ' */
  dos->e_lfanew = nt_headers_offset;

  if (is_64)
  {
    /* === NT Headers === */
    nt = (EFB_PE_IMAGE_NT_HEADERS64 *)(model->out_binary + nt_headers_offset);
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
    section->Misc.VirtualSize = model->code_size;
    section->VirtualAddress = code_va;
    section->SizeOfRawData = raw_size;
    section->PointerToRawData = size_of_headers;
    section->Characteristics = EFB_PE_IMAGE_SCN_CNT_CODE | EFB_PE_IMAGE_SCN_MEM_EXECUTE | EFB_PE_IMAGE_SCN_MEM_READ;
  }
  else
  {
    /* === NT Headers === */
    EFB_PE_IMAGE_NT_HEADERS32 *nt32 = (EFB_PE_IMAGE_NT_HEADERS32 *)(model->out_binary + nt_headers_offset);
    nt32->Signature = 0x00004550;

    nt32->FileHeader.Machine = machine_type;
    nt32->FileHeader.NumberOfSections = 1;
    nt32->FileHeader.SizeOfOptionalHeader = sizeof(EFB_PE_IMAGE_OPTIONAL_HEADER32);
    nt32->FileHeader.Characteristics = EFB_PE_IMAGE_FILE_EXECUTABLE_IMAGE | EFB_PE_IMAGE_FILE_RELOCS_STRIPPED;

    nt32->OptionalHeader.Magic = 0x10b; /* 32-bit */
    nt32->OptionalHeader.MajorLinkerVersion = 14;
    nt32->OptionalHeader.MinorLinkerVersion = 0;
    nt32->OptionalHeader.SizeOfCode = raw_size;
    nt32->OptionalHeader.AddressOfEntryPoint = entry_point_rva;
    nt32->OptionalHeader.BaseOfCode = code_va;
    nt32->OptionalHeader.BaseOfData = 0;
    nt32->OptionalHeader.ImageBase = 0x400000;
    nt32->OptionalHeader.SectionAlignment = section_align;
    nt32->OptionalHeader.FileAlignment = file_align;
    nt32->OptionalHeader.MajorOperatingSystemVersion = 6;
    nt32->OptionalHeader.MinorOperatingSystemVersion = 0;
    nt32->OptionalHeader.MajorSubsystemVersion = 6;
    nt32->OptionalHeader.MinorSubsystemVersion = 0;
    nt32->OptionalHeader.SizeOfImage = size_of_image;
    nt32->OptionalHeader.SizeOfHeaders = size_of_headers;
    nt32->OptionalHeader.Subsystem = EFB_PE_IMAGE_SUBSYSTEM_WINDOWS_CUI;
    nt32->OptionalHeader.NumberOfRvaAndSizes = EFB_PE_IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    section = (EFB_PE_IMAGE_SECTION_HEADER *)((unsigned char *)&nt32->OptionalHeader + nt32->FileHeader.SizeOfOptionalHeader);
    section->Name[0] = '.';
    section->Name[1] = 't';
    section->Name[2] = 'e';
    section->Name[3] = 'x';
    section->Name[4] = 't';
    section->Misc.VirtualSize = model->code_size;
    section->VirtualAddress = code_va;
    section->SizeOfRawData = raw_size;
    section->PointerToRawData = size_of_headers;
    section->Characteristics = EFB_PE_IMAGE_SCN_CNT_CODE | EFB_PE_IMAGE_SCN_MEM_EXECUTE | EFB_PE_IMAGE_SCN_MEM_READ;
  }

  /* === Write Code ===*/
  code_dest = model->out_binary + size_of_headers;
  for (i = 0; i < model->code_size; ++i)
  {
    code_dest[i] = model->code[i];
  }

  model->out_binary_size = file_size;

  return true;
}

EFB_API EFB_INLINE efb_bool efb_build_elf(efb_model *model)
{
  efb_bool ended = false;

  unsigned long i;
  unsigned char *code_dest;

  unsigned long code_offset = 0x80;
  unsigned long file_size = code_offset + model->code_size;

  unsigned short machine_type;
  efb_bool is_64 = true;

  switch (model->arch)
  {
  case EFB_ARCH_I386:
    machine_type = EFB_ELF_MACHINE_386;
    is_64 = false;
    break;
  case EFB_ARCH_X86_64:
    machine_type = EFB_ELF_MACHINE_X86_64;
    break;
  case EFB_ARCH_AARCH64:
    machine_type = EFB_ELF_MACHINE_AARCH64;
    break;
  default:
    return ended;
  }

  /* Fail if file_size exceeds static buffer*/
  if (file_size > model->out_binary_capacity)
  {
    return (ended);
  }

  efb_zero_memory(model->out_binary, file_size);
  model->out_binary_size = 0;

  if (is_64)
  {
    EFB_ELF64_EHDR *ehdr = (EFB_ELF64_EHDR *)model->out_binary;
    EFB_ELF64_PHDR *phdr = (EFB_ELF64_PHDR *)(model->out_binary + sizeof(EFB_ELF64_EHDR));

    efb_zero_memory((unsigned char *)ehdr, sizeof(EFB_ELF64_EHDR));
    efb_zero_memory((unsigned char *)phdr, sizeof(EFB_ELF64_PHDR));

    code_dest = model->out_binary + 0x80;

    ehdr->e_ident[0] = EFB_ELF_MAGIC0;
    ehdr->e_ident[1] = EFB_ELF_MAGIC1;
    ehdr->e_ident[2] = EFB_ELF_MAGIC2;
    ehdr->e_ident[3] = EFB_ELF_MAGIC3;
    ehdr->e_ident[4] = EFB_ELF_CLASS64;
    ehdr->e_ident[5] = EFB_ELF_DATA;
    ehdr->e_ident[6] = EFB_ELF_VERSION;
    ehdr->e_ident[7] = EFB_ELF_OSABI;

    ehdr->e_type = EFB_ELF_TYPE_EXEC;
    ehdr->e_machine = machine_type;
    ehdr->e_version = EFB_ELF_VERSION;
    ehdr->e_entry = EFB_ELF_CODE_VADDR;
    ehdr->e_phoff = sizeof(EFB_ELF64_EHDR);
    ehdr->e_ehsize = sizeof(EFB_ELF64_EHDR);
    ehdr->e_phentsize = sizeof(EFB_ELF64_PHDR);
    ehdr->e_phnum = 1;

    phdr->p_type = EFB_ELF_PT_LOAD;
    phdr->p_flags = EFB_ELF_PF_R | EFB_ELF_PF_X;
    phdr->p_offset = 0x0;
    phdr->p_vaddr = 0x400000;
    phdr->p_paddr = 0x400000;
    phdr->p_filesz = 0x80 + model->code_size;
    phdr->p_memsz = 0x80 + model->code_size;
    phdr->p_align = EFB_ELF_ALIGN;
  }
  else
  {
    EFB_ELF32_EHDR *ehdr = (EFB_ELF32_EHDR *)model->out_binary;
    EFB_ELF32_PHDR *phdr = (EFB_ELF32_PHDR *)(model->out_binary + sizeof(EFB_ELF32_EHDR));

    efb_zero_memory((unsigned char *)ehdr, sizeof(EFB_ELF32_EHDR));
    efb_zero_memory((unsigned char *)phdr, sizeof(EFB_ELF32_PHDR));

    ehdr->e_ident[0] = EFB_ELF_MAGIC0;
    ehdr->e_ident[1] = EFB_ELF_MAGIC1;
    ehdr->e_ident[2] = EFB_ELF_MAGIC2;
    ehdr->e_ident[3] = EFB_ELF_MAGIC3;
    ehdr->e_ident[4] = EFB_ELF_CLASS32;
    ehdr->e_ident[5] = EFB_ELF_DATA;
    ehdr->e_ident[6] = EFB_ELF_VERSION;
    ehdr->e_ident[7] = EFB_ELF_OSABI;

    ehdr->e_type = EFB_ELF_TYPE_EXEC;
    ehdr->e_machine = machine_type;
    ehdr->e_version = 1;
    ehdr->e_entry = EFB_ELF_CODE_VADDR;
    ehdr->e_phoff = sizeof(EFB_ELF32_EHDR);
    ehdr->e_ehsize = sizeof(EFB_ELF32_EHDR);
    ehdr->e_phentsize = sizeof(EFB_ELF32_PHDR);
    ehdr->e_phnum = 1;

    phdr->p_type = EFB_ELF_PT_LOAD;
    phdr->p_offset = (unsigned int)code_offset;
    phdr->p_vaddr = EFB_ELF_CODE_VADDR;
    phdr->p_paddr = EFB_ELF_CODE_VADDR;
    phdr->p_filesz = (unsigned int)model->code_size;
    phdr->p_memsz = (unsigned int)model->code_size;
    phdr->p_flags = EFB_ELF_PF_R | EFB_ELF_PF_X;
    phdr->p_align = EFB_ELF_ALIGN;
  }

  /* Write code */
  for (i = 0; i < model->code_size; ++i)
  {
    code_dest[i] = model->code[i];
  }

  model->out_binary_size = file_size;

  return true;
}

EFB_API EFB_INLINE efb_bool efb_build(efb_model *model)
{
  if (!model->code)
  {
    return false;
  }

  switch (model->format)
  {
  case EFB_FORMAT_PE:
    return efb_build_pe(model);
  case EFB_FORMAT_ELF:
    return efb_build_elf(model);
  default:
    break;
  }

  return false;
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
