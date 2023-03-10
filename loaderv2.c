#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>

#include "loaderv2.h"

object load_obj(const char *obj_file_path) {
    int fd;
    struct stat statbuf;
    object obj = {
        .hdr = {
            .base = NULL,
        },
        .rela_text = NULL,
        .num_rela_symbols = 0,
        .num_external_rela_symbols = 0,
        .section_hdr_table = NULL,
        .shstrtab = NULL,
        .symtab = NULL,
        .strtab = NULL,
        .num_symbols = 0,
        .text = NULL
    };

    fd = open(obj_file_path, O_RDONLY);
    if (fd < 0) {
        perror("open object file failed");
        return obj;
    }

    if (fstat(fd, &statbuf) < 0) {
        perror("get file info failed");
        goto out;
    }

    // MAP_PRIVATE
    //
    // Create a private copy-on-write mapping.  Updates to the mapping are not
    // visible to other processes mapping the same file, and are not carried
    // through to the underlying file.  It is unspecified  whether changes made
    // to the file after the mmap() call are visible in the mapped region.
    obj.hdr.base = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (obj.hdr.base == MAP_FAILED)
        perror("map object into process address space failed");

out:
    close(fd);
    return obj;
}

// external dependencies for obj.o
static int my_puts(const char *s)
{
    puts("my_puts executed");
    return puts(s);
}

static uint8_t *get_section_runtime_base(const object *obj,
                                         const Elf64_Shdr *section_hdr)
{
    const char *section_name = obj->shstrtab + section_hdr->sh_name;
    size_t section_name_len = strlen(section_name);

    if (strlen(".text") == section_name_len && !strcmp(".text", section_name))
        return obj->text;

    if (strlen(".data") == section_name_len && !strcmp(".data", section_name))
        return obj->data;

    if (strlen(".rodata") == section_name_len && !strcmp(".rodata", section_name))
        return obj->rodata;

    fprintf(stderr, "No runtime base address for section %s\n", section_name);

    return NULL;
}

static const Elf64_Shdr *lookup_section_hdr_by_name(object *obj, const char *name) {
    const Elf64_Ehdr *elf64_hdr = obj->hdr.elf64_hdr;
    const char *shstrtab = obj->shstrtab;
    const Elf64_Shdr *section_hdr = NULL;
    const char *section_name = NULL;
    size_t name_len = strlen(name);
    size_t section_name_len;

    // The ELF header's e_shnum member holds the number of entries
    // the section header table contains.
    for (Elf64_Half i = 0; i < elf64_hdr->e_shnum; i++) {
        // This section header's sh_name member specifies the name of the section.
        // Its value is an index into the section header string table section,
        // giving the location of a null-terminated string.
        section_hdr = obj->section_hdr_table + i;
        section_name = shstrtab + section_hdr->sh_name;
        section_name_len = strlen(section_name);

        if (name_len == section_name_len && !strcmp(name, section_name)) {
            // ignore section with size 0
            if (section_hdr->sh_size != 0)
                return section_hdr;
        }
    }

    return NULL;
}

static void *lookup_ext_function(const char *name)
{
    size_t name_len = strlen(name);
 
    if (name_len == strlen("puts") && !strcmp(name, "puts"))
        return my_puts;
 
    fprintf(stderr, "No address for function %s\n", name);
    exit(ENOENT);
}

static void do_text_relocations(object *obj)
{
    /* we actually cheat here - the name .rela.text is a convention, but not a
     * rule: to figure out which section should be patched by these relocations
     * we would need to examine the rela_text_section_hdr, but we skip it for simplicity
     */
    const Elf64_Rela *relocation = NULL;
    const Elf64_Rela *relocations = obj->rela_text;
    int num_relocations = obj->num_rela_symbols;
    int rela_index;
    int rela_type;
    uint8_t *rela_offset;
    const Elf64_Sym *symtab = obj->symtab;
    const Elf64_Sym *sym = NULL;
    int symtab_index;
    uint8_t *sym_address;

    for (rela_index = 0; rela_index < num_relocations; rela_index++) {
        relocation = relocations + rela_index;
        symtab_index = ELF64_R_SYM(relocation->r_info);
        rela_type = ELF64_R_TYPE(relocation->r_info);

        // where to patch .text
        rela_offset = obj->text + relocation->r_offset;

        // symbol, with respect to which the relocation is performed
        sym = symtab + symtab_index;

        // if this is an external symbol
        if (sym->st_shndx == SHN_UNDEF) {
            static int curr_jmp_idx = 0;
            struct ext_jump *jump_entry = obj->jumptable + curr_jmp_idx;

            // get external symbol/function address by name
            jump_entry->addr = lookup_ext_function(obj->strtab + sym->st_name);

            // x64 unconditional JMP with address stored at -14 bytes offset
            // will use the address stored in addr above
            jump_entry->instr[0] = 0xff;
            jump_entry->instr[1] = 0x25;
            jump_entry->instr[2] = 0xf2;
            jump_entry->instr[3] = 0xff;
            jump_entry->instr[4] = 0xff;
            jump_entry->instr[5] = 0xff;

            // resolve the relocation with respect to this unconditional JMP
            sym_address = (uint8_t *)(&(jump_entry->instr));
        } else {
            // ?????? symbol ????????? section ??????????????????????????????????????? section ?????????
            sym_address = get_section_runtime_base(obj, obj->section_hdr_table +
                            sym->st_shndx) + sym->st_value;
        }

        switch (rela_type)
        {
        case R_X86_64_PC32:
            /* S + A - P, 32 bit output, S == L here */
        case R_X86_64_PLT32:
            /* L + A - P, 32 bit output */
            *((uint32_t *)rela_offset) = sym_address + relocation->r_addend - rela_offset;
            printf("At %p relocate to 0x%08x\n", rela_offset, *((uint32_t *)rela_offset));
            break;
        }
    }
}

static uint64_t page_align(uint64_t size) {
    uint64_t page_size = sysconf(_SC_PAGESIZE);
    return (size + (page_size - 1)) & ~(page_size - 1);
}

void parse_obj(object *obj) {
    const uint8_t *base = obj->hdr.base;
    const Elf64_Ehdr *elf64_hdr = obj->hdr.elf64_hdr;
    const Elf64_Shdr *section_hdr;
    const Elf64_Shdr *text_section_hdr;
    const Elf64_Shdr *data_section_hdr;
    const Elf64_Shdr *rodata_section_hdr;
    const uint8_t *text = NULL;
    const uint8_t *data = NULL;
    const uint8_t *rodata = NULL;

    // The ELF header's e_shoff member gives the byte offset from the beginning
    // of the file to the section header table.
    obj->section_hdr_table = (const Elf64_Shdr *)(base + elf64_hdr->e_shoff);

    // The ELF header's e_shstrndx member holds the section header table index
    // of the entry associated with the section name string table.
    section_hdr = obj->section_hdr_table + elf64_hdr->e_shstrndx;
    obj->shstrtab = (const char *)(base + section_hdr->sh_offset);

    // get the .symtab section header in the section header table
    section_hdr = lookup_section_hdr_by_name(obj, ".symtab");
    if (!section_hdr) {
        fputs("Failed to find .symtab\n", stderr);
        exit(-1);
    }
    // get the .symtab section
    obj->symtab = (const Elf64_Sym *)(base + section_hdr->sh_offset);
    obj->num_symbols = section_hdr->sh_size / section_hdr->sh_entsize;

    // get the .strtab section header in the section header table
    section_hdr = lookup_section_hdr_by_name(obj, ".strtab");
    if (!section_hdr) {
        fputs("Failed to find .strtab\n", stderr);
        exit(-1);
    }
    // get the .strtab section
    obj->strtab = (const char *)(base + section_hdr->sh_offset);

    // get the .rela.text section header in the section header table
    section_hdr = lookup_section_hdr_by_name(obj, ".rela.text");
    if (!section_hdr) {
        fputs("Failed to find .rela.text\n", stderr);
        exit(-1);
    }
    // get the .rela.text section
    obj->rela_text = (const Elf64_Rela *)(base + section_hdr->sh_offset);
    obj->num_rela_symbols = section_hdr->sh_size / section_hdr->sh_entsize;
    for (int i = 0; i < obj->num_rela_symbols; i++) {
        int symbol_idx = ELF64_R_SYM((obj->rela_text + i)->r_info);
        if ((obj->symtab + symbol_idx)->st_shndx == SHN_UNDEF)
            obj->num_external_rela_symbols++;
    }

    // handle .text section
    text_section_hdr = lookup_section_hdr_by_name(obj, ".text");
    if (!text_section_hdr) {
        fputs("Failed to find .text\n", stderr);
        exit(-1);
    }
    text = (const uint8_t *)(base + text_section_hdr->sh_offset);

    data_section_hdr = lookup_section_hdr_by_name(obj, ".data");
    if (!data_section_hdr) {
        fputs("Failed to find .data\n", stderr);
        exit(-1);
    }
    data = (const uint8_t *)(base + data_section_hdr->sh_offset);

    rodata_section_hdr = lookup_section_hdr_by_name(obj, ".rodata");
    if (!rodata_section_hdr) {
        fputs("Failed to find .rodata\n", stderr);
        exit(-1);
    }
    rodata = (const uint8_t *)(base + rodata_section_hdr->sh_offset);

    obj->text = mmap(NULL, page_align(text_section_hdr->sh_size) +
                     page_align(data_section_hdr->sh_size) +
                     page_align(rodata_section_hdr->sh_size) +
                     page_align(sizeof(struct ext_jump) * obj->num_external_rela_symbols),
                     PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (obj->text == MAP_FAILED) {
        perror("Failed to allocate memory");
        exit(errno);
    }

    // .data will come right after .text
    obj->data = obj->text + page_align(text_section_hdr->sh_size);
    // .rodata will come after .data
    obj->rodata = obj->data + page_align(data_section_hdr->sh_size);
    // jumptable will come after .rodata
    obj->jumptable = (struct ext_jump *)(obj->rodata + page_align(rodata_section_hdr->sh_size));

    // copy the contents of .text section from the ELF file
    memcpy(obj->text, text, text_section_hdr->sh_size);
    // copy the contents of .data section from the ELF file
    memcpy(obj->data, data, data_section_hdr->sh_size);
    // copy the contents of .rodata section from the ELF file
    memcpy(obj->rodata, rodata, rodata_section_hdr->sh_size);

    do_text_relocations(obj);

    // make the .text copy readonly and executable
    if (mprotect(obj->text, page_align(section_hdr->sh_size), PROT_READ | PROT_EXEC)) {
        perror("Failed to make .text executable");
        exit(errno);
    }

    // we don't need to do anything with .data - it should remain read/write

    // make the `.rodata` copy readonly
    if (mprotect(obj->rodata, page_align(rodata_section_hdr->sh_size), PROT_READ)) {
        perror("Failed to make .rodata readonly");
        exit(errno);
    }

    // make the jumptable readonly and executable
    if (mprotect(obj->jumptable, page_align(sizeof(struct ext_jump) *
            obj->num_external_rela_symbols), PROT_READ | PROT_EXEC)) {
        perror("Failed to make the jumptable executable");
        exit(errno);
    }
}

static void *lookup_function_by_name(object *obj, const char *name) {
    const Elf64_Sym *symtab = obj->symtab;
    const Elf64_Sym *sym = NULL;
    const char *strtab = obj->strtab;
    size_t name_len = strlen(name);

    for (int i = 0; i < obj->num_symbols; i++) {
        sym = symtab + i;

        if (ELF64_ST_TYPE(sym->st_info) == STT_FUNC) {
            /* symbol table entry does not contain the string name of the symbol
             * instead, the `st_name` parameter is an offset in the `.strtab`
             * section, which points to a string name
             */
            const char *function_name = strtab + sym->st_name;
            size_t function_name_len = strlen(function_name);

            if (name_len == function_name_len && !strcmp(name, function_name)) {
                /* st_value is an offset in bytes of the function from the
                 * beginning of the `.text` section
                 */
                return obj->text + sym->st_value;
            }
        }
    }

    return NULL;
}

int main() {
    object obj;
    /* pointers to imported add5 and add10 functions */
    int (*add5)(int);
    int (*add10)(int);
    const char *(*get_hello)(void);
    int (*get_var)(void);
    void (*set_var)(int num);
    void (*say_hello)(void);

    obj = load_obj("./obj.o");
    parse_obj(&obj);

    add5 = lookup_function_by_name(&obj, "add5");
    if (!add5) {
        fputs("Failed to find add5 function\n", stderr);
        exit(ENOENT);
    }

    puts("Executing add5...");
    printf("add5(%d) = %d\n", 42, add5(42));

    add10 = lookup_function_by_name(&obj, "add10");
    if (!add10) {
        fputs("Failed to find add10 function\n", stderr);
        exit(ENOENT);
    }

    puts("Executing add10...");
    printf("add10(%d) = %d\n", 42, add10(42));

    get_hello = lookup_function_by_name(&obj, "get_hello");
    if (!get_hello) {
        fputs("Failed to find get_hello function\n", stderr);
        exit(ENOENT);
    }

    puts("Executing get_hello...");
    printf("get_hello() = %s\n", get_hello());

    get_var = lookup_function_by_name(&obj, "get_var");
    if (!get_var) {
        fputs("Failed to find get_var function\n", stderr);
        exit(ENOENT);
    }

    puts("Executing get_var...");
    printf("get_var() = %d\n", get_var());

    set_var = lookup_function_by_name(&obj, "set_var");
    if (!set_var) {
        fputs("Failed to find set_var function\n", stderr);
        exit(ENOENT);
    }

    puts("Executing set_var(42)...");
    set_var(42);

    puts("Executing get_var again...");
    printf("get_var() = %d\n", get_var());

    say_hello = lookup_function_by_name(&obj, "say_hello");
    if (!say_hello) {
        fputs("Failed to find say_hello function\n", stderr);
        exit(ENOENT);
    }

    puts("Executing say_hello...");
    say_hello();

    return 0;
}
