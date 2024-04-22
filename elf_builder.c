#include <stdio.h>
#include <string.h>

#include <unistd.h>

#include <elf.h>

#define STB_LOCAL	0		/* Symbol not visible outside obj */
#define STB_GLOBAL	1		/* Symbol visible outside obj */
#define STB_WEAK	2		/* Like globals, lower precedence */
#define STB_LOOS	10		/* OS-specific semantics */
#define STB_GNU_UNIQUE	10  /* Symbol is unique in namespace */
#define STB_HIOS	12		/* OS-specific semantics */
#define STB_LOPROC	13		/* Processor-specific semantics */
#define STB_HIPROC	15		/* Processor-specific semantics */

#define STT_NOTYPE	0		/* Symbol type is unspecified */
#define STT_OBJECT	1		/* Symbol is a data object */
#define STT_FUNC	2		/* Symbol is a code object */
#define STT_SECTION	3		/* Symbol associated with a section */
#define STT_FILE	4		/* Symbol gives a file name */
#define STT_COMMON	5		/* An uninitialised common block */
#define STT_TLS		6		/* Thread local data object */
#define STT_RELC	8		/* Complex relocation expression */
#define STT_SRELC	9		/* Signed Complex relocation expression */
#define STT_GNU_IFUNC	10		/* Symbol is an indirect code object */

#if defined(__LP64__)
#define ElfW(type)      Elf64_ ## type
#define ELFCLASS        ELFCLASS64
#define ELF_ST_INFO     ELF64_ST_INFO
#define ELF_ARCH        EM_X86_64
#else
#define ElfW(type)      Elf32_ ## type
#define ELFCLASS        ELFCLASS32
#define ELF_ST_INFO     ELF32_ST_INFO
#define ELF_ARCH        EM_386
#endif

#define COUNT_OF(x) (sizeof(x)/sizeof(x[0]))

/* 0x0 ELF header
0x1000 program headers
0x2000 section headers
0x20000 data */
char buff[0x100000];
#define DATA_OFFSET 0x20000
#define SEC_OFFSET  0x2000
size_t  dataoffset = 0x20000+0x64; // some sections has to have first bytes set to NULL


char *section_type_names[] = {
    "NULL","PROGBITS",
    "SYMTAB","STRTAB","RELA","HASH",
    "DYNAMIC","NOTE","NOBITS","REL",
    "SHLIB","DYNSYM","INIT_ARRAY","FINI_ARRAY",
    "PREINIT_ARRAY",/*"GROUP",*/"SYMTAB_SHNDX","RELR"};

int section_type_values[] = {
    SHT_NULL, SHT_PROGBITS,
    SHT_SYMTAB, SHT_STRTAB, SHT_RELA, SHT_HASH,
    SHT_DYNAMIC, SHT_NOTE, SHT_NOBITS,SHT_REL,
    SHT_SHLIB, SHT_DYNSYM, SHT_INIT_ARRAY, SHT_FINI_ARRAY,
    SHT_PREINIT_ARRAY, /*SHT_GROUP,*/ SHT_SYMTAB_SHNDX, SHT_RELR};

char *sym_type_names[] = {
    "STT_NOTYPE","STT_OBJECT","STT_FUNC",
    "STT_SECTION","STT_FILE","STT_COMMON",
    "STT_TLS","STT_RELC","STT_SRELC","STT_GNU_IFUNC","<invalid>"};

int sym_type_values[] = {
    STT_NOTYPE,STT_OBJECT,STT_FUNC,
    STT_SECTION,STT_FILE,STT_COMMON,
    STT_TLS,STT_RELC,STT_SRELC,STT_GNU_IFUNC,69};

char *sym_bind_names[] = {
    "STB_LOCAL","STB_GLOBAL",
    "STB_WEAK","STB_GNU_UNIQUE","<invalid>"};

int sym_bind_values[] = {
    STB_LOCAL,STB_GLOBAL,
    STB_WEAK,STB_GNU_UNIQUE,69};

static inline uintptr_t push_to_data_offset(void *ptr, size_t size, uintptr_t *offset) {
    uintptr_t ret = *offset;
    memcpy(buff+*offset, ptr, size);
    *offset += size;
    return ret;
}

static inline uintptr_t push_to_data(void *ptr, size_t size) {
    return push_to_data_offset(ptr, size, &dataoffset);
}

#define PUSH_HARDCODED_STR(str) push_to_data(str, sizeof(str))

int main(void) {
    ElfW(Ehdr) *hdr = (void *)buff;

    hdr->e_ident[EI_MAG0]       = ELFMAG0;
    hdr->e_ident[EI_MAG1]       = ELFMAG1;
    hdr->e_ident[EI_MAG2]       = ELFMAG2;
    hdr->e_ident[EI_MAG3]       = ELFMAG3;
    hdr->e_ident[EI_CLASS]      = ELFCLASS;
    hdr->e_ident[EI_DATA]       = ELFDATA2LSB;
    hdr->e_ident[EI_VERSION]    = EV_CURRENT;
    hdr->e_ident[EI_OSABI]      = ELFOSABI_LINUX;
    hdr->e_ident[EI_ABIVERSION] = 0;
    hdr->e_type                 = ET_NONE;
    hdr->e_machine              = ELF_ARCH;
    hdr->e_version              = EV_CURRENT;
    hdr->e_entry                = 0;
    hdr->e_phnum                = 0;
    hdr->e_phoff                = 0;
    hdr->e_phentsize            = sizeof(ElfW(Phdr));
    hdr->e_shnum                = 0;
    hdr->e_shoff                = SEC_OFFSET;
    hdr->e_shentsize            = sizeof(ElfW(Shdr));
    hdr->e_shstrndx             = 1;

    /* generate section headers */
    ElfW(Shdr) shdr = {0};
    ElfW(Shdr) shdr_template = {0};
    memcpy(buff+SEC_OFFSET, &shdr, sizeof(shdr));
    shdr.sh_offset  = DATA_OFFSET;
    shdr.sh_name    = PUSH_HARDCODED_STR(".shstrtab") - DATA_OFFSET;
    shdr.sh_type    = SHT_STRTAB;
    shdr.sh_size    = sizeof(buff) - DATA_OFFSET;
    shdr.sh_addr    = DATA_OFFSET;
    memcpy(buff+SEC_OFFSET+sizeof(shdr), &shdr, sizeof(shdr));
    memcpy(&shdr_template, &shdr, sizeof(shdr));

    sizeof(ElfW(Shdr));

    hdr->e_shnum = COUNT_OF(section_type_names) << 3;
    for (size_t i = 0; i < hdr->e_shnum; i++) {
        memcpy(&shdr, &shdr_template, sizeof(shdr));
        shdr.sh_flags   = i&((1<<3)-1);
        shdr.sh_type    = section_type_values[i>>3];
        
        char sect_name[255] = ".----";

        for (size_t y = 0; y < 3; y++) {
            if (shdr.sh_flags & (1 << y))
                sect_name[y+1] = "wax"[y];
        }
        memcpy(sect_name+5, section_type_names[i/(1<<3)], strlen(section_type_names[i/(1<<3)])+1);
        shdr.sh_name = push_to_data(sect_name, strlen(sect_name)+1) - DATA_OFFSET;

        if ((shdr.sh_flags & SHF_ALLOC) == 0)
            shdr.sh_size    = 0;
        
        if (
            shdr.sh_type == SHT_DYNSYM  ||
            shdr.sh_type == SHT_STRTAB  ||
            shdr.sh_type == SHT_REL     ||
            shdr.sh_type == SHT_RELA    ||
            shdr.sh_type == SHT_SYMTAB  ||
            shdr.sh_type == SHT_DYNAMIC ||
            shdr.sh_type == SHT_RELR    ||
            shdr.sh_type == SHT_NOTE) {
            switch (shdr.sh_type)
            {
                case SHT_REL:       shdr.sh_entsize = sizeof(ElfW(Rel)); break;
                case SHT_RELA:      shdr.sh_entsize = sizeof(ElfW(Rela)); break;
                case SHT_RELR:      shdr.sh_entsize = sizeof(ElfW(Relr)); break;
                case SHT_DYNAMIC:   shdr.sh_entsize = sizeof(ElfW(Dyn)); break;
                case SHT_SYMTAB:    shdr.sh_entsize = sizeof(ElfW(Sym)); break;
                case SHT_DYNSYM:    shdr.sh_entsize = sizeof(ElfW(Sym)); break;
                default:break;
            }
            shdr.sh_size    = 0;
        }

        if (shdr.sh_type == SHT_GROUP) {
            shdr.sh_offset = push_to_data((ElfW(Word)[]){0, i+2, i+1}, sizeof(ElfW(Word))*3);
            shdr.sh_entsize = sizeof(ElfW(Word));
            shdr.sh_size    = sizeof(ElfW(Word))*3;
        }

        if (shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNAMIC || shdr.sh_type == SHT_DYNSYM) {
            shdr.sh_link    = ((SHT_STRTAB << 3) | (i&((1<<3)-1)))   + 2;
        } else if (shdr.sh_type == SHT_HASH || shdr.sh_type == SHT_GROUP || shdr.sh_type == SHT_SYMTAB_SHNDX) {
            shdr.sh_link = ((SHT_SYMTAB << 3) | (i&((1<<3)-1)))  + 2;
        } else if (shdr.sh_type == SHT_REL || shdr.sh_type == SHT_RELA) {
            shdr.sh_link = ((SHT_SYMTAB << 3) | (i&((1<<3)-1)))  + 2;
            shdr.sh_info = ((SHT_PROGBITS << 3) | (i&((1<<3)-1))) + 2;
        }

        memcpy(buff+SEC_OFFSET+(sizeof(shdr)*(i+2)), &shdr, sizeof(shdr));
    }


    hdr->e_shnum += 2;

    /* generate symbols to see how nm behave to it */
    ElfW(Sym) sym = {0};

    uintptr_t   symtabptr = dataoffset;
    size_t      symtablen = COUNT_OF(sym_type_names) * COUNT_OF(sym_bind_names) * hdr->e_shnum;
    size_t      symname_offset = dataoffset + (symtablen * sizeof(sym));

    ElfW(Shdr)  *sec        = (void *)(buff + SEC_OFFSET);
    for (size_t i = 0; i < symtablen; i++) {
        int         sym_type    = i / hdr->e_shnum / COUNT_OF(sym_bind_names);
        int         sym_bind    = i / hdr->e_shnum % COUNT_OF(sym_bind_names);
        char        symname[64] = "";

        sym.st_size     = sprintf(symname, "%s-%s-%s", sym_type_names[sym_type], sym_bind_names[sym_bind], buff + sec[i % hdr->e_shnum].sh_name + DATA_OFFSET) + 1;
        sym.st_value    = push_to_data_offset(symname, sym.st_size, &symname_offset);
        sym.st_name     = sym.st_value - DATA_OFFSET;
        sym.st_shndx    = i % hdr->e_shnum;
        sym.st_info     = ELF_ST_INFO(sym_bind_values[sym_bind],sym_type_values[sym_type]);
        sym.st_value = 0x69;
        push_to_data(&sym, sizeof(sym));
    }

    for (size_t i = 0; i < hdr->e_shnum; i++) {
        if (sec[i].sh_type == SHT_SYMTAB) {
            sec[i].sh_offset    = symtabptr;
            sec[i].sh_addr      = symtabptr;
            sec[i].sh_entsize   = sizeof(sym);
            sec[i].sh_size      = symtablen * sizeof(sym);
            sec[i].sh_link      = 1;
        }
    }
    
    write(1, buff, sizeof(buff));
}