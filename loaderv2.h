#ifndef __LOADER_V2_H__
#define __LOADER_V2_H__

#include <elf.h>

// Elf64 format
//
// ------------------------
// |       ELF header     |
// ------------------------
// |       .text          |
// ------------------------
// |       .data          |
// ------------------------
// |       ...            |
// ------------------------
// |       .symtab        |
// ------------------------
// |       .strtab        |
// ------------------------
// |       .shstrtab      |
// ------------------------
// | section header table |
// ------------------------

typedef union object_hdr {
    const Elf64_Ehdr *elf64_hdr;
    const uint8_t *base;
} object_hdr;

typedef struct object {
    // The ELF header's e_shoff member gives the byte offset from the beginning
    // of the file to the section header table. e_shnum holds the number of
    // entries the section header table contains.
    object_hdr hdr;

    // The section header table is an array of or Elf64_Shdr structures.
    // A section header table index is a subscript into this array.
    //
    // This sh_name member specifies the name of the section. Its value
    // is an index into the section header string table section,
    // giving the location of a null-terminated string.
    const Elf64_Shdr *section_hdr_table;

    // .shstrtab section
    // This section holds section names.
    const char *shstrtab;

    // An object file's symbol table holds information needed to locate
    // and relocate a program's symbolic definitions and references. A
    // symbol table index is a subscript into this array.
    //
    // This st_name member holds an index into the object file's
    // string table, which holds character representations of the
    // symbol names. If the value is nonzero, it represents a
    // string table index that gives the symbol name. Otherwise,
    // the symbol has no name.
    const Elf64_Sym *symtab;

    // The sh_size member of section header holds the section's size in bytes.
    //
    // Some sections hold a table of fixed-sized entries, such as
    // a symbol table.  For such a section, the sh_entsize member of section header
    // gives the size in bytes for each entry.  This member contains zero
    // if the section does not hold a table of fixed-size
    // entries.
    int num_symbols;

    // String table sections hold null-terminated character sequences,
    // commonly called strings. The object file uses these strings to
    // represent symbol names.  One references a string as
    // an index into the string table section. The first byte, which is
    // index zero, is defined to hold a null byte ('\0').  Similarly, a
    // string table's last byte is defined to hold a null byte, ensuring
    // null termination for all strings.
    const char *strtab;

    // .text section
    uint8_t *text;

    // .data section
    uint8_t *data;

    // .rodata section
    uint8_t *rodata;
} object;

object load_obj(const char *obj_file_path);
void parse_obj(object *obj);

#endif
