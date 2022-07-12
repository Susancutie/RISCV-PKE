#ifndef _ELF_H_
#define _ELF_H_

#include "util/types.h"
#include "process.h"

#define MAX_CMDLINE_ARGS 64

// elf header structure
typedef struct elf_header_t {
  uint32 magic;
  uint8 elf[12];
  uint16 type;      /* Object file type */
  uint16 machine;   /* Architecture */
  uint32 version;   /* Object file version */
  uint64 entry;     /* Entry point virtual address */
  uint64 phoff;     /* Program header table file offset */
  uint64 shoff;     /* Section header table file offset */
  uint32 flags;     /* Processor-specific flags */
  uint16 ehsize;    /* ELF header size in bytes */
  uint16 phentsize; /* Program header table entry size */
  uint16 phnum;     /* Program header table entry count */
  uint16 shentsize; /* Section header table entry size */
  uint16 shnum;     /* Section header table entry count */
  uint16 shstrndx;  /* Section header string table index */
} elf_header;

// section header
typedef struct {
  uint32 sh_name;      /* Section name (string tbl index) */
  uint32 sh_type;      /* Section type */
  uint64 sh_flags;     /* Section flags */
  uint64 sh_addr;      /* Section virtual addr at execution */
  uint64 sh_offset;    /* Section file offset */
  uint64 sh_size;      /* Section size in bytes */
  uint32 sh_link;      /* Link to another section */
  uint32 sh_info;      /* Additional section information */
  uint64 sh_addralign; /* Section alignment */
  uint64 sh_entsize;   /* Entry size if section holds table */
} elf_section_header;

// Program segment header.
typedef struct elf_prog_header_t {
  uint32 type;   /* Segment type */
  uint32 flags;  /* Segment flags */
  uint64 off;    /* Segment file offset */
  uint64 vaddr;  /* Segment virtual address */
  uint64 paddr;  /* Segment physical address */
  uint64 filesz; /* Segment size in file */
  uint64 memsz;  /* Segment size in memory */
  uint64 align;  /* Segment alignment */
} elf_prog_header;

#define ELF_MAGIC 0x464C457FU  // "\x7FELF" in little endian
#define ELF_PROG_LOAD 1

// added for lab1_challenge1_backtrace.
// macros used to parse symbol table.
#define SHT_SYMTAB 2           /* Symbol table */
#define SHT_STRTAB 3           /* String table */
#define STT_FILE 4             /* Symbol's name is file name */
#define STT_FUNC 18            /* Symbol's name is function name*/

typedef enum elf_status_t {
  EL_OK = 0,

  EL_EIO,
  EL_ENOMEM,
  EL_NOTELF,
  EL_ERR,

} elf_status;

// added for lab1_challenge1_backtrace.
// the symbol table record, each record stores information of a symbol
typedef struct {
  // st_name is the offset in string table.
  uint32 st_name;         /* Symbol name (string tbl index) */
  unsigned char st_info;  /* Symbol type and binding */
  unsigned char st_other; /* Symbol visibility */
  uint16 st_shndx;        /* Section index */
  uint64 st_value;        /* Symbol value */
  uint64 st_size;         /* Symbol size */
} elf_symbol_rec;

typedef struct elf_ctx_t {
  void *info;
  elf_header ehdr;

  // following members are added for lab1_challenge1_backtrace.
  // string table in elf: a sequence of strings which begins with '\0' are split by '\0'
  // for example: '\0main\0f1\0f2\0'. we can access the string "main" with strtb[1].
  // we assume in this challenge that the length of all strings will not exceed 4096
  char strtb[4096];  

  // symbols: we assume that there are only 128 symbols at most.
  // that is, you can access symbol name with strtb[syms[i].st_name]
  elf_symbol_rec syms[128];   

  // actual count of the symbols in source code.
  uint64 syms_count; 
} elf_ctx;

elf_status elf_init(elf_ctx *ctx, void *info);
elf_status elf_load(elf_ctx *ctx);
// added for lab1_challenge1_backtrace.
// predeclaration of elf_load_symbol function.
elf_status elf_load_symbol(elf_ctx *ctx);

void load_bincode_from_host_elf(process *p);

#endif
