/*
 MIT License
 
 Copyright (c) 2024 SecNotes
 
 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:
 
 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
*/

#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>
#include "common.h"
#include "parse.h"
#include "lib/util.h"

enum HeaderLabel {
    E_IDENT,        /* Magic number and other info */
    E_TYPE,         /* Object file type */
    E_MACHINE,      /* Architecture */
    E_VERSION,      /* Object file version */
    E_ENTRY,        /* Entry point virtual address */
    E_PHOFF,        /* Program header table file offset */
    E_SHOFF,        /* Section header table file offset */
    E_FLAGS,        /* Processor-specific flags */
    E_EHSIZE,       /* ELF header size in bytes */
    E_PHENTSIZE,    /* Program header table entry size */
    E_PHNUM,        /* Program header table entry count */
    E_SHENTSIZE,    /* Section header table entry size */
    E_SHNUM,        /* Section header table entry count */
    E_SHSTRNDX,     /* Section header table entry count */
};

enum SectionLabel {
    S_NAME,         /* Section name (string tbl index) */
    S_TYPE,         /* Section type */
    S_FLAGS,        /* Section flags */
    S_ADDR,         /* Section virtual addr at execution */
    S_OFF,          /* Section file offset */
    S_SIZE,         /* Section size in bytes */
    S_LINK,         /* Link to another section */
    S_INFO,         /* Additional section information */
    S_ALIGN,        /* Section alignment */
    S_ENTSIZE,      /* Entry size if section holds table */
};

enum SegmentLabel {
    P_TYPE,         /* Segment type */
    P_FLAGS,        /* Segment flags */
    P_OFFSET,       /* Segment file offset */
    P_VADDR,        /* Segment virtual address */
    P_PADDR,        /* Segment physical address */
    P_FILESZ,       /* Segment size in file */
    P_MEMSZ,        /* Segment size in memory */
    P_ALIGN,        /* Segment alignment */
};

enum SymbolLabel {
    ST_NAME,        /* Symbol name (string tbl index) */
    ST_VALUE,       /* Symbol value */
    ST_SIZE,        /* Symbol size */
    ST_INFO,        /* Symbol type and binding */
    ST_TYPE,
    ST_BIND,
    ST_OTHER,       /* Symbol visibility */
    ST_SHNDX,       /* Section index */
};

enum RelocationLabel {
    R_OFFSET,       /* Address */
    R_INFO,         /* Relocation type and symbol index */
    R_TYPE,
    R_INDEX,
    R_ADDEND,       /* Addend */
};

enum DynamicLabel {
    D_TAG,
    D_VALUE,
};

/**
 * @brief Set the elf header information object
 * 
 * @param elf_name elf file name
 * @param value 
 * @param label readelf elf header column
 * @return error code {-1:error,0:sucess}
 */
static int set_header(char *elf_name, int value, enum HeaderLabel label) {
    int fd;
    struct stat st;
    uint8_t *elf_map;

    fd = open(elf_name, O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        perror("fstat");
        return -1;
    }

    elf_map = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (elf_map == MAP_FAILED) {
        perror("mmap");
        return -1;
    }
   
    /* 32bit */
    if (MODE == ELFCLASS32) {
        Elf32_Ehdr *ehdr;
        ehdr = (Elf32_Ehdr *)elf_map;

        switch (label)
        {
            case E_IDENT:
                break;

            case E_TYPE:
                printf("%x->%x\n", ehdr->e_type, value);
                ehdr->e_type = value;
                break;

            case E_MACHINE:
                printf("%x->%x\n", ehdr->e_machine, value);
                ehdr->e_machine = value;
                break;
            
            case E_VERSION:
                printf("%x->%x\n", ehdr->e_version, value);
                ehdr->e_version = value;
                break;

            case E_ENTRY:
                printf("%x->%x\n", ehdr->e_entry, value);
                ehdr->e_entry= value;
                break;

            case E_PHOFF:
                printf("%x->%x\n", ehdr->e_phoff, value);
                ehdr->e_phoff = value;
                break;

            case E_SHOFF:
                printf("%x->%x\n", ehdr->e_shoff, value);
                ehdr->e_shoff = value;
                break;

            case E_FLAGS:
                printf("%x->%x\n", ehdr->e_flags, value);
                ehdr->e_flags = value;
                break;

            case E_EHSIZE:
                printf("%x->%x\n", ehdr->e_ehsize, value);
                ehdr->e_ehsize = value;
                break;

            case E_PHENTSIZE:
                printf("%x->%x\n", ehdr->e_phentsize, value);
                ehdr->e_phentsize = value;
                break;

            case E_PHNUM:
                printf("%x->%x\n", ehdr->e_phnum, value);
                ehdr->e_phnum = value;
                break;

            case E_SHENTSIZE:
                printf("%x->%x\n", ehdr->e_shentsize, value);
                ehdr->e_shentsize = value;
                break;

            case E_SHNUM:
                printf("%x->%x\n", ehdr->e_shnum, value);
                ehdr->e_shnum = value;
                break;

            case E_SHSTRNDX:
                printf("%x->%x\n", ehdr->e_shstrndx, value);
                ehdr->e_shstrndx = value;
                break;
            
            default:
                break;
        }
    }

    /* 64bit */
    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        ehdr = (Elf64_Ehdr *)elf_map;

        switch (label)
        {
            case E_IDENT:
                break;

            case E_TYPE:
                printf("%x->%x\n", ehdr->e_type, value);
                ehdr->e_type = value;
                break;

            case E_MACHINE:
                printf("%x->%x\n", ehdr->e_machine, value);
                ehdr->e_machine = value;
                break;
            
            case E_VERSION:
                printf("%x->%x\n", ehdr->e_version, value);
                ehdr->e_version = value;
                break;

            case E_ENTRY:
                printf("%x->%x\n", ehdr->e_entry, value);
                ehdr->e_entry= value;
                break;

            case E_PHOFF:
                printf("%x->%x\n", ehdr->e_phoff, value);
                ehdr->e_phoff = value;
                break;

            case E_SHOFF:
                printf("%x->%x\n", ehdr->e_shoff, value);
                ehdr->e_shoff = value;
                break;

            case E_FLAGS:
                printf("%x->%x\n", ehdr->e_flags, value);
                ehdr->e_flags = value;
                break;

            case E_EHSIZE:
                printf("%x->%x\n", ehdr->e_ehsize, value);
                ehdr->e_ehsize = value;
                break;

            case E_PHENTSIZE:
                printf("%x->%x\n", ehdr->e_phentsize, value);
                ehdr->e_phentsize = value;
                break;

            case E_PHNUM:
                printf("%x->%x\n", ehdr->e_phnum, value);
                ehdr->e_phnum = value;
                break;

            case E_SHENTSIZE:
                printf("%x->%x\n", ehdr->e_shentsize, value);
                ehdr->e_shentsize = value;
                break;

            case E_SHNUM:
                printf("%x->%x\n", ehdr->e_shnum, value);
                ehdr->e_shnum = value;
                break;

            case E_SHSTRNDX:
                printf("%x->%x\n", ehdr->e_shstrndx, value);
                ehdr->e_shstrndx = value;
                break;
            
            default:
                break;
        }
    }

    close(fd);
    munmap(elf_map, st.st_size);
    return 0;
}

/**
 * @brief Set the section name
 * 
 * @param elf_name elf file name
 * @param value 
 * @return error code {-1:error,0:sucess}
 */
int set_header_type(char *elf_name, int value) {
    return set_header(elf_name, value, E_TYPE);
}

int set_header_machine(char *elf_name, int value) {
    return set_header(elf_name, value, E_MACHINE);
}

int set_header_version(char *elf_name, int value) {
    return set_header(elf_name, value, E_VERSION);
}

int set_header_entry(char *elf_name, int value) {
    return set_header(elf_name, value, E_ENTRY);
}

int set_header_phoff(char *elf_name, int value) {
    return set_header(elf_name, value, E_PHOFF);
}

int set_header_shoff(char *elf_name, int value) {
    return set_header(elf_name, value, E_SHOFF);
}

int set_header_flags(char *elf_name, int value) {
    return set_header(elf_name, value, E_FLAGS);
}

int set_header_ehsize(char *elf_name, int value) {
    return set_header(elf_name, value, E_EHSIZE);
}

int set_header_phentsize(char *elf_name, int value) {
    return set_header(elf_name, value, E_PHENTSIZE);
}

int set_header_phnum(char *elf_name, int value) {
    return set_header(elf_name, value, E_PHNUM);
}

int set_header_shentsize(char *elf_name, int value) {
    return set_header(elf_name, value, E_SHENTSIZE);
}

int set_header_shnum(char *elf_name, int value) {
    return set_header(elf_name, value, E_SHNUM);
}

int set_header_shstrndx(char *elf_name, int value) {
    return set_header(elf_name, value, E_SHSTRNDX);
}

/**
 * @brief Set the section information object
 * 
 * @param elf_name elf file name
 * @param index readelf section row
 * @param value 
 * @param label readelf section column
 * @return error code {-1:error,0:sucess}
 */
static int set_section(char *elf_name, int index, int value, enum SectionLabel label) {
    int fd;
    struct stat st;
    uint8_t *elf_map;

    fd = open(elf_name, O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        perror("fstat");
        return -1;
    }

    elf_map = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (elf_map == MAP_FAILED) {
        perror("mmap");
        return -1;
    }

    /* rwx -> xrw*/
    int section_flags = ((value & 1) << 2) | ((value & 2) >> 1) | ((value & 4) >> 1);
    
    /* 32bit */
    if (MODE == ELFCLASS32) {
        Elf32_Ehdr *ehdr;
        Elf32_Shdr *shdr;

        ehdr = (Elf32_Ehdr *)elf_map;
        shdr = (Elf32_Shdr *)&elf_map[ehdr->e_shoff];

        switch (label)
        {
            case S_NAME:
                printf("%x->%x\n", shdr[index].sh_name, value);
                shdr[index].sh_name = value;
                break;

            case S_TYPE:
                printf("%x->%x\n", shdr[index].sh_type, value);
                shdr[index].sh_type = value;
                break;

            case S_FLAGS:
                printf("%x->%x\n", shdr[index].sh_flags, value);
                shdr[index].sh_flags = section_flags;
                break;
            
            case S_ADDR:
                printf("%x->%x\n", shdr[index].sh_addr, value);
                shdr[index].sh_addr = value;
                break;

            case S_OFF:
                printf("%x->%x\n", shdr[index].sh_offset, value);
                shdr[index].sh_offset = value;
                break;

            case S_SIZE:
                printf("%x->%x\n", shdr[index].sh_size, value);
                shdr[index].sh_size = value;
                break;

            case S_LINK:
                printf("%x->%x\n", shdr[index].sh_link, value);
                shdr[index].sh_link = value;
                break;

            case S_INFO:
                printf("%x->%x\n", shdr[index].sh_info, value);
                shdr[index].sh_info = value;
                break;

            case S_ALIGN:
                printf("%x->%x\n", shdr[index].sh_addralign, value);
                shdr[index].sh_addralign = value;
                break;

            case S_ENTSIZE:
                printf("%x->%x\n", shdr[index].sh_entsize, value);
                shdr[index].sh_entsize = value;
                break;
            
            default:
                break;
        }
    }

    /* 64bit */
    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        Elf64_Shdr *shdr;

        ehdr = (Elf64_Ehdr *)elf_map;
        shdr = (Elf64_Shdr *)&elf_map[ehdr->e_shoff];

        switch (label)
        {
            case S_NAME:
                printf("%x->%x\n", shdr[index].sh_name, value);
                shdr[index].sh_name = value;
                break;

            case S_TYPE:
                printf("%x->%x\n", shdr[index].sh_type, value);
                shdr[index].sh_type = value;
                break;

            case S_FLAGS:
                printf("%x->%x\n", shdr[index].sh_flags, value);
                shdr[index].sh_flags = section_flags;
                break;
            
            case S_ADDR:
                printf("%x->%x\n", shdr[index].sh_addr, value);
                shdr[index].sh_addr = value;
                break;

            case S_OFF:
                printf("%x->%x\n", shdr[index].sh_offset, value);
                shdr[index].sh_offset = value;
                break;

            case S_SIZE:
                printf("%x->%x\n", shdr[index].sh_size, value);
                shdr[index].sh_size = value;
                break;

            case S_LINK:
                printf("%x->%x\n", shdr[index].sh_link, value);
                shdr[index].sh_link = value;
                break;

            case S_INFO:
                printf("%x->%x\n", shdr[index].sh_info, value);
                shdr[index].sh_info = value;
                break;

            case S_ALIGN:
                printf("%x->%x\n", shdr[index].sh_addralign, value);
                shdr[index].sh_addralign = value;
                break;

            case S_ENTSIZE:
                printf("%x->%x\n", shdr[index].sh_entsize, value);
                shdr[index].sh_entsize = value;
                break;
            
            default:
                break;
        }
    }

    close(fd);
    munmap(elf_map, st.st_size);
    return 0;
};

/**
 * @brief Set the section name
 * 
 * @param elf_name elf file name
 * @param index readelf section row
 * @param value 
 * @return error code {-1:error,0:sucess}
 */
int set_section_name(char *elf_name, int index, int value) {
    return set_section(elf_name, index, value, S_NAME);
}

int set_section_type(char *elf_name, int index, int value) {
    return set_section(elf_name, index, value, S_TYPE);
}

int set_section_flags(char *elf_name, int index, int value) {
    return set_section(elf_name, index, value, S_FLAGS);
}

int set_section_addr(char *elf_name, int index, int value) {
    return set_section(elf_name, index, value, S_ADDR);
}

int set_section_off(char *elf_name, int index, int value) {
    return set_section(elf_name, index, value, S_OFF);
}

int set_section_size(char *elf_name, int index, int value) {
    return set_section(elf_name, index, value, S_SIZE);
}

int set_section_link(char *elf_name, int index, int value) {
    return set_section(elf_name, index, value, S_LINK);
}

int set_section_info(char *elf_name, int index, int value) {
    return set_section(elf_name, index, value, S_INFO);
}

int set_section_align(char *elf_name, int index, int value) {
    return set_section(elf_name, index, value, S_ALIGN);
}

int set_section_entsize(char *elf_name, int index, int value) {
    return set_section(elf_name, index, value, S_ENTSIZE);
}

int set_section_name_by_str(char *elf_name, int index, char *value) {
    int fd;
    struct stat st;
    uint8_t *elf_map;
    uint8_t *sec_name;

    fd = open(elf_name, O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        perror("fstat");
        return -1;
    }

    elf_map = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (elf_map == MAP_FAILED) {
        perror("mmap");
        return -1;
    }
    
    /* 32bit */
    if (MODE == ELFCLASS32) {
        Elf32_Ehdr *ehdr;
        Elf32_Shdr *shdr;
        Elf32_Shdr shstrtab;
        ehdr = (Elf32_Ehdr *)elf_map;
        shdr = (Elf32_Shdr *)&elf_map[ehdr->e_shoff];

        shstrtab = shdr[ehdr->e_shstrndx];
        sec_name = elf_map + shstrtab.sh_offset + shdr[index].sh_name;
        if (validated_offset(sec_name, elf_map, elf_map + st.st_size)) {
            ERROR("Corrupt file format\n");
            goto ERR_EXIT;
        }
        if (validated_offset(sec_name + strlen(value), elf_map, elf_map + st.st_size)) {
            ERROR("The input string is too long\n");
            goto ERR_EXIT;
        }
        printf("%s->%s\n", sec_name, value);
        strcpy(sec_name, value);
    }

    /* 64bit */
    else if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        Elf64_Shdr *shdr;
        Elf64_Shdr shstrtab;
        ehdr = (Elf64_Ehdr *)elf_map;
        shdr = (Elf64_Shdr *)&elf_map[ehdr->e_shoff];
        
        shstrtab = shdr[ehdr->e_shstrndx];
        sec_name = elf_map + shstrtab.sh_offset + shdr[index].sh_name;
        if (validated_offset(sec_name, elf_map, elf_map + st.st_size)) {
            ERROR("Corrupt file format\n");
            goto ERR_EXIT;
        }
        if (validated_offset(sec_name + strlen(value), elf_map, elf_map + st.st_size)) {
            ERROR("The input string is too long\n");
            goto ERR_EXIT;
        }
        printf("%s->%s\n", sec_name, value);
        strcpy(sec_name, value);
    }

    else {
        ERROR("Invalid ELF class");
        goto ERR_EXIT;
    }

    close(fd);
    munmap(elf_map, st.st_size);
    return 0;

ERR_EXIT:
    close(fd);
    munmap(elf_map, st.st_size);
    return -1;
}

/**
 * @brief Set the segment information
 * 
 * @param elf_name elf file name
 * @param index readelf .segment row
 * @param value value to be edited
 * @param label readelf .segment column
 * @return error code {-1:error,0:sucess}
 */
static int set_segment(char *elf_name, int index, int value, enum SegmentLabel label) {
    int fd;
    struct stat st;
    uint8_t *elf_map;

    fd = open(elf_name, O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        perror("fstat");
        return -1;
    }

    elf_map = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (elf_map == MAP_FAILED) {
        perror("mmap");
        return -1;
    }
    
    /* 32bit */
    if (MODE == ELFCLASS32) {
        Elf32_Ehdr *ehdr;
        Elf32_Phdr *phdr;

        ehdr = (Elf32_Ehdr *)elf_map;
        phdr = (Elf32_Phdr *)&elf_map[ehdr->e_phoff];

        switch (label)
        {
            case P_TYPE:
                printf("%x->%x\n", phdr[index].p_type, value);
                phdr[index].p_type = value;
                break;
            
            case P_FLAGS:
                printf("%x->%x\n", phdr[index].p_flags, value);
                phdr[index].p_flags = value;
                break;

            case P_OFFSET:
                printf("%x->%x\n", phdr[index].p_offset, value);
                phdr[index].p_offset = value;
                break;

            case P_VADDR:
                printf("%x->%x\n", phdr[index].p_vaddr, value);
                phdr[index].p_vaddr = value;
                break;

            case P_PADDR:
                printf("%x->%x\n", phdr[index].p_paddr, value);
                phdr[index].p_paddr = value;
                break;

            case P_FILESZ:
                printf("%x->%x\n", phdr[index].p_filesz, value);
                phdr[index].p_filesz = value;
                break;

            case P_MEMSZ:
                printf("%x->%x\n", phdr[index].p_memsz, value);
                phdr[index].p_memsz = value;
                break;

            case P_ALIGN:
                printf("%x->%x\n", phdr[index].p_align, value);
                phdr[index].p_align = value;
                break;
            
            default:
                break;
        }
    }

    /* 64bit */
    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        Elf64_Phdr *phdr;

        ehdr = (Elf64_Ehdr *)elf_map;
        phdr = (Elf64_Phdr *)&elf_map[ehdr->e_phoff];

        switch (label)
        {
                        case P_TYPE:
                printf("%x->%x\n", phdr[index].p_type, value);
                phdr[index].p_type = value;
                break;
            
            case P_FLAGS:
                printf("%x->%x\n", phdr[index].p_flags, value);
                phdr[index].p_flags = value;
                break;

            case P_OFFSET:
                printf("%x->%x\n", phdr[index].p_offset, value);
                phdr[index].p_offset = value;
                break;

            case P_VADDR:
                printf("%x->%x\n", phdr[index].p_vaddr, value);
                phdr[index].p_vaddr = value;
                break;
            
            case P_PADDR:
                printf("%x->%x\n", phdr[index].p_paddr, value);
                phdr[index].p_paddr = value;
                break;

            case P_FILESZ:
                printf("%x->%x\n", phdr[index].p_filesz, value);
                phdr[index].p_filesz = value;
                break;

            case P_MEMSZ:
                printf("%x->%x\n", phdr[index].p_memsz, value);
                phdr[index].p_memsz = value;
                break;

            case P_ALIGN:
                printf("%x->%x\n", phdr[index].p_align, value);
                phdr[index].p_align = value;
                break;
        
            default:
                break;
        }
    }

    close(fd);
    munmap(elf_map, st.st_size);
    return 0;
};

/**
 * @brief Set the segment type
 * 
 * @param elf_name elf file name
 * @param index readelf segment row
 * @param value 
 * @return error code {-1:error,0:sucess}
 */
int set_segment_type(char *elf_name, int index, int value) {
    return set_segment(elf_name, index, value, P_TYPE);
}

/**
 * @brief Set the segment flags
 * 
 * @param elf_name elf file name
 * @param index readelf segment row
 * @param value 
 * @return error code {-1:error,0:sucess}
 */
int set_segment_flags(char *elf_name, int index, int value) {
    return set_segment(elf_name, index, value, P_FLAGS);
}

/**
 * @brief Set the segment offset
 * 
 * @param elf_name elf file name
 * @param index readelf segment row
 * @param value 
 * @return error code {-1:error,0:sucess}
 */
int set_segment_offset(char *elf_name, int index, int value) {
    return set_segment(elf_name, index, value, P_OFFSET);
}

/**
 * @brief Set the segment vaddr
 * 
 * @param elf_name elf file name
 * @param index readelf segment row
 * @param value 
 * @return error code {-1:error,0:sucess}
 */
int set_segment_vaddr(char *elf_name, int index, int value) {
    return set_segment(elf_name, index, value, P_VADDR);
}

/**
 * @brief Set the segment paddr
 * 
 * @param elf_name elf file name
 * @param index readelf segment row
 * @param value 
 * @return error code {-1:error,0:sucess}
 */
int set_segment_paddr(char *elf_name, int index, int value) {
    return set_segment(elf_name, index, value, P_PADDR);
}

/**
 * @brief Set the segment filesz
 * 
 * @param elf_name elf file name
 * @param index readelf segment row
 * @param value 
 * @return error code {-1:error,0:sucess}
 */
int set_segment_filesz(char *elf_name, int index, int value) {
    return set_segment(elf_name, index, value, P_FILESZ);
}

/**
 * @brief Set the segment memsz
 * 
 * @param elf_name elf file name
 * @param index readelf segment row
 * @param value 
 * @return error code {-1:error,0:sucess}
 */
int set_segment_memsz(char *elf_name, int index, int value) {
    return set_segment(elf_name, index, value, P_MEMSZ);
}

/**
 * @brief Set the segment align
 * 
 * @param elf_name elf file name
 * @param index readelf segment row
 * @param value 
 * @return error code {-1:error,0:sucess}
 */
int set_segment_align(char *elf_name, int index, int value) {
    return set_segment(elf_name, index, value, P_ALIGN);
}

/**
 * @brief Set the symbol information
 * 
 * @param elf_name elf file name
 * @param index readelf symbol row
 * @param value value to be edited
 * @param label readelf symbol column
 * @param section_name .dynsym or .symtab
 * @return error code {-1:error,0:sucess}
 */
static int set_symbol(char *elf_name, int index, int value, enum SymbolLabel label, char *section_name) {
    int fd;
    struct stat st;
    int type;
    int bind;
    uint8_t *elf_map;
    uint64_t sym_offset;

    fd = open(elf_name, O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        perror("fstat");
        return -1;
    }

    elf_map = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (elf_map == MAP_FAILED) {
        perror("mmap");
        return -1;
    }
    // get offset and update elf class
    sym_offset = get_section_offset(elf_name, section_name);
    if (!sym_offset) {
        goto ERR_EXIT;
    }

    /* 32bit */
    if (MODE == ELFCLASS32) {
        Elf32_Sym *sym = (Elf32_Sym *)(elf_map + sym_offset);
        switch (label)
        {
            case ST_NAME:
                printf("%x->%x\n", sym[index].st_name, value);
                sym[index].st_name = value;
                break;
            
            case ST_VALUE:
                printf("%x->%x\n", sym[index].st_value, value);
                sym[index].st_value = value;
                break;
            
            case ST_SIZE:
                printf("%x->%x\n", sym[index].st_size, value);
                sym[index].st_size = value;
                break;

            case ST_TYPE:
                type = ELF32_ST_TYPE(sym[index].st_info);
                bind = ELF32_ST_BIND(sym[index].st_info);
                printf("%x->%x\n", type, value);
                sym[index].st_info = ELF32_ST_INFO(bind, value);
                break;

            case ST_BIND:
                type = ELF32_ST_TYPE(sym[index].st_info);
                bind = ELF32_ST_BIND(sym[index].st_info);
                printf("%x->%x\n", bind, value);
                sym[index].st_info = ELF32_ST_INFO(value, type);
                break;

            case ST_OTHER:
                printf("%x->%x\n", sym[index].st_other, value);
                sym[index].st_other = value;
                break;

            case ST_SHNDX:
                printf("%x->%x\n", sym[index].st_shndx, value);
                sym[index].st_shndx = value;
                break;
            
            default:
                break;
        }
    }

    /* 64bit */
    else if (MODE == ELFCLASS64) {
        Elf64_Sym *sym = (Elf64_Sym *)(elf_map + sym_offset);
        switch (label)
        {
            case ST_NAME:
                printf("%x->%x\n", sym[index].st_name, value);
                sym[index].st_name = value;
                break;
            
            case ST_VALUE:
                printf("%x->%x\n", sym[index].st_value, value);
                sym[index].st_value = value;
                break;
            
            case ST_SIZE:
                printf("%x->%x\n", sym[index].st_size, value);
                sym[index].st_size = value;
                break;

            case ST_TYPE:
                type = ELF64_ST_TYPE(sym[index].st_info);
                bind = ELF64_ST_BIND(sym[index].st_info);
                printf("%x->%x\n", type, value);
                sym[index].st_info = ELF64_ST_INFO(bind, value);
                break;

            case ST_BIND:
                type = ELF64_ST_TYPE(sym[index].st_info);
                bind = ELF64_ST_BIND(sym[index].st_info);
                printf("%x->%x\n", bind, value);
                sym[index].st_info = ELF64_ST_INFO(value, type);
                break;

            case ST_OTHER:
                printf("%x->%x\n", sym[index].st_other, value);
                sym[index].st_other = value;
                break;

            case ST_SHNDX:
                printf("%x->%x\n", sym[index].st_shndx, value);
                sym[index].st_shndx = value;
                break;
            
            default:
                break;
        }
    }

    close(fd);
    munmap(elf_map, st.st_size);
    return 0;

ERR_EXIT:
    close(fd);
    munmap(elf_map, st.st_size);
    return -1;
};

/**
 * @brief Set the dynsym name object
 * 
 * @param elf_name elf file name
 * @param index elf file name
 * @param value value to be edited
 * @param section_name .dynsym or .symtab
 * @return error code {-1:error,0:sucess}
 */
int set_sym_name(char *elf_name, int index, int value, char *section_name) {
    return set_symbol(elf_name, index, value, ST_NAME, section_name);
}

/**
 * @brief Set the dynsym value object
 * 
 * @param elf_name elf file name
 * @param index readelf .dynsym row
 * @param value value to be edited
 * @param section_name .dynsym or .symtab
 * @return error code {-1:error,0:sucess}
 */
int set_sym_value(char *elf_name, int index, int value, char *section_name) {
    return set_symbol(elf_name, index, value, ST_VALUE, section_name);
}

/**
 * @brief Set the dynsym size object
 * 
 * @param elf_name elf file name
 * @param index readelf .dynsym row
 * @param value value to be edited
 * @param section_name .dynsym or .symtab
 * @return error code {-1:error,0:sucess}
 */
int set_sym_size(char *elf_name, int index, int value, char *section_name) {
    return set_symbol(elf_name, index, value, ST_SIZE, section_name);
}

/**
 * @brief Set the dynsym type object
 * 
 * @param elf_name elf file name
 * @param index readelf .dynsym row
 * @param value value to be edited
 * @param section_name .dynsym or .symtab
 * @return error code {-1:error,0:sucess}
 */
int set_sym_type(char *elf_name, int index, int value, char *section_name) {
    return set_symbol(elf_name, index, value, ST_TYPE, section_name);
}

/**
 * @brief Set the dynsym bind object
 * 
 * @param elf_name elf file name
 * @param index readelf .dynsym row
 * @param value value to be edited
 * @param section_name .dynsym or .symtab
 * @return error code {-1:error,0:sucess}
 */
int set_sym_bind(char *elf_name, int index, int value, char *section_name) {
    return set_symbol(elf_name, index, value, ST_BIND, section_name);
}

/**
 * @brief Set the dynsym other object
 * 
 * @param elf_name elf file name
 * @param index readelf .dynsym row
 * @param value value to be edited
 * @param section_name .dynsym or .symtab
 * @return error code {-1:error,0:sucess}
 */
int set_sym_other(char *elf_name, int index, int value, char *section_name) {
    return set_symbol(elf_name, index, value, ST_OTHER, section_name);
}

/**
 * @brief Set the dynsym shndx object
 * 
 * @param elf_name elf file name
 * @param index readelf .dynsym row
 * @param value value to be edited
 * @param section_name .dynsym or .symtab
 * @return error code {-1:error,0:sucess}
 */
int set_sym_shndx(char *elf_name, int index, int value, char *section_name) {
    return set_symbol(elf_name, index, value, ST_SHNDX, section_name);
}

int set_rel(char *elf_name, int index, int value, enum RelocationLabel label, char *section_name)  {
    int fd;
    struct stat st;
    int type;
    int bind;
    uint8_t *elf_map;
    uint8_t *tmp_sec_name;

    fd = open(elf_name, O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        perror("fstat");
        return -1;
    }

    elf_map = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (elf_map == MAP_FAILED) {
        perror("mmap");
        return -1;
    }
    
    /* 32bit */
    if (MODE == ELFCLASS32) {
        Elf32_Ehdr *ehdr;
        Elf32_Shdr *shdr;
        Elf32_Shdr shstrtab;
        Elf32_Rel *rel;

        ehdr = (Elf32_Ehdr *)elf_map;
        shdr = (Elf32_Shdr *)&elf_map[ehdr->e_shoff];
        shstrtab = shdr[ehdr->e_shstrndx];

        for (int i = 0; i < ehdr->e_shnum; i++) {
            tmp_sec_name = elf_map + shstrtab.sh_offset + shdr[i].sh_name;
            if (!strcmp(section_name, tmp_sec_name)) {
                int size = 0;
                /* security check start*/
                if (shdr[i].sh_entsize != 0)
                    size = shdr[i].sh_size / shdr[i].sh_entsize;
                else
                    return -1;
                if (index >= size)
                    return -1;
                /* security check end*/
                rel = (Elf32_Rel *)(elf_map + shdr[i].sh_offset);
                switch (label)
                {
                    case R_OFFSET:
                        printf("0x%x->0x%x\n", rel[index].r_offset, value);
                        rel[index].r_offset = value;
                        break;
                    
                    case R_INFO:
                        printf("0x%x->0x%x\n", rel[index].r_info, value);
                        rel[index].r_info = value;
                        break;

                    case R_TYPE:
                        printf("0x%x->0x%x\n", ELF32_R_TYPE(rel[index].r_info), value);
                        rel[index].r_info = ELF32_R_INFO(ELF32_R_SYM(rel[index].r_info), value);
                        break;

                    case R_INDEX:
                        printf("0x%x->0x%x\n", ELF32_R_SYM(rel[index].r_info), value);
                        rel[index].r_info = ELF32_R_INFO(value, ELF32_R_TYPE(rel[index].r_info));
                        break;
                    
                    default:
                        break;
                }
                break;
            }
        }
    }

    /* 64bit */
    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        Elf64_Shdr *shdr;
        Elf64_Shdr shstrtab;
        Elf64_Rel *rel;

        ehdr = (Elf64_Ehdr *)elf_map;
        shdr = (Elf64_Shdr *)&elf_map[ehdr->e_shoff];
        shstrtab = shdr[ehdr->e_shstrndx];

        for (int i = 0; i < ehdr->e_shnum; i++) {
            tmp_sec_name = elf_map + shstrtab.sh_offset + shdr[i].sh_name;
            if (!strcmp(section_name, tmp_sec_name)) {
                int size = 0;
                /* security check start*/
                if (shdr[i].sh_entsize != 0)
                    size = shdr[i].sh_size / shdr[i].sh_entsize;
                else
                    return -1;
                if (index >= size)
                    return -1;
                /* security check end*/
                rel = (Elf64_Rel *)(elf_map + shdr[i].sh_offset);
                switch (label)
                {
                    case R_OFFSET:
                        printf("0x%x->0x%x\n", rel[index].r_offset, value);
                        rel[index].r_offset = value;
                        break;
                    
                    case R_INFO:
                        printf("0x%x->0x%x\n", rel[index].r_info, value);
                        rel[index].r_info = value;
                        break;

                    case R_TYPE:
                        printf("0x%x->0x%x\n", ELF64_R_TYPE(rel[index].r_info), value);
                        rel[index].r_info = ELF64_R_INFO(ELF64_R_SYM(rel[index].r_info), value);
                        break;

                    case R_INDEX:
                        printf("0x%x->0x%x\n", ELF64_R_SYM(rel[index].r_info), value);
                        rel[index].r_info = ELF64_R_INFO(value, ELF64_R_TYPE(rel[index].r_info));
                        break;
                    
                    default:
                        break;
                }
                break;
            }
        }
    }

    close(fd);
    munmap(elf_map, st.st_size);
    return 0;
}

int set_rela(char *elf_name, int index, int value, enum RelocationLabel label, char *section_name)  {
    int fd;
    struct stat st;
    int type;
    int bind;
    uint8_t *elf_map;
    uint8_t *tmp_sec_name;

    fd = open(elf_name, O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        perror("fstat");
        return -1;
    }

    elf_map = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (elf_map == MAP_FAILED) {
        perror("mmap");
        return -1;
    }
    
    /* 32bit */
    if (MODE == ELFCLASS32) {
        Elf32_Ehdr *ehdr;
        Elf32_Shdr *shdr;
        Elf32_Shdr shstrtab;
        Elf32_Rela *rela;

        ehdr = (Elf32_Ehdr *)elf_map;
        shdr = (Elf32_Shdr *)&elf_map[ehdr->e_shoff];
        shstrtab = shdr[ehdr->e_shstrndx];

        for (int i = 0; i < ehdr->e_shnum; i++) {
            tmp_sec_name = elf_map + shstrtab.sh_offset + shdr[i].sh_name;
            if (!strcmp(section_name, tmp_sec_name)) {
                int size = 0;
                /* security check start*/
                if (shdr[i].sh_entsize != 0)
                    size = shdr[i].sh_size / shdr[i].sh_entsize;
                else
                    return -1;
                if (index >= size)
                    return -1;
                /* security check end*/
                rela = (Elf32_Rela *)(elf_map + shdr[i].sh_offset);
                switch (label)
                {
                    case R_OFFSET:
                        printf("0x%x->0x%x\n", rela[index].r_offset, value);
                        rela[index].r_offset = value;
                        break;
                    
                    case R_INFO:
                        printf("0x%x->0x%x\n", rela[index].r_info, value);
                        rela[index].r_info = value;
                        break;

                    case R_TYPE:
                        printf("0x%x->0x%x\n", ELF32_R_TYPE(rela[index].r_info), value);
                        rela[index].r_info = ELF32_R_INFO(ELF32_R_SYM(rela[index].r_info), value);
                        break;

                    case R_INDEX:
                        printf("0x%x->0x%x\n", ELF32_R_SYM(rela[index].r_info), value);
                        rela[index].r_info = ELF32_R_INFO(value, ELF32_R_TYPE(rela[index].r_info));
                        break;

                    case R_ADDEND:
                        printf("%d->%d\n", rela[index].r_addend, value);
                        rela[index].r_addend = value;
                    
                    default:
                        break;
                }
                break;
            }
        }
    }

    /* 64bit */
    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        Elf64_Shdr *shdr;
        Elf64_Shdr shstrtab;
        Elf64_Rela *rela;

        ehdr = (Elf64_Ehdr *)elf_map;
        shdr = (Elf64_Shdr *)&elf_map[ehdr->e_shoff];
        shstrtab = shdr[ehdr->e_shstrndx];

        for (int i = 0; i < ehdr->e_shnum; i++) {
            tmp_sec_name = elf_map + shstrtab.sh_offset + shdr[i].sh_name;
            if (!strcmp(section_name, tmp_sec_name)) {
                int size = 0;
                /* security check start*/
                if (shdr[i].sh_entsize != 0)
                    size = shdr[i].sh_size / shdr[i].sh_entsize;
                else
                    return -1;
                if (index >= size)
                    return -1;
                /* security check end*/
                rela = (Elf64_Rela *)(elf_map + shdr[i].sh_offset);
                switch (label)
                {
                    case R_OFFSET:
                        printf("0x%x->0x%x\n", rela[index].r_offset, value);
                        rela[index].r_offset = value;
                        break;
                    
                    case R_INFO:
                        printf("0x%x->0x%x\n", rela[index].r_info, value);
                        rela[index].r_info = value;
                        break;

                    case R_TYPE:
                        printf("0x%x->0x%x\n", ELF64_R_TYPE(rela[index].r_info), value);
                        rela[index].r_info = ELF64_R_INFO(ELF64_R_SYM(rela[index].r_info), value);
                        break;

                    case R_INDEX:
                        printf("0x%x->0x%x\n", ELF64_R_SYM(rela[index].r_info), value);
                        rela[index].r_info = ELF64_R_INFO(value, ELF64_R_TYPE(rela[index].r_info));
                        break;

                    case R_ADDEND:
                        printf("%d->%d\n", rela[index].r_addend, value);
                        rela[index].r_addend = value;
                    
                    default:
                        break;
                }
                break;
            }
        }
    }

    close(fd);
    munmap(elf_map, st.st_size);
    return 0;
}

/**
 * @brief Set the .rela section offset
 * 
 * @param elf_name elf file name
 * @param index readelf section row
 * @param value 
 * @return error code {-1:error,0:sucess}
 */
int set_rela_offset(char *elf_name, int index, int value, char *section_name) {
    return set_rela(elf_name, index, value, R_OFFSET, section_name);
}

int set_rela_info(char *elf_name, int index, int value, char *section_name) {
    return set_rela(elf_name, index, value, R_INFO, section_name);
}

int set_rela_type(char *elf_name, int index, int value, char *section_name) {
    return set_rela(elf_name, index, value, R_TYPE, section_name);
}

int set_rela_index(char *elf_name, int index, int value, char *section_name) {
    return set_rela(elf_name, index, value, R_INDEX, section_name);
}

int set_rela_addend(char *elf_name, int index, int value, char *section_name) {
    return set_rela(elf_name, index, value, R_ADDEND, section_name);
}

/* .rel.* */
int set_rel_offset(char *elf_name, int index, int value, char *section_name) {
    return set_rel(elf_name, index, value, R_OFFSET, section_name);
}

int set_rel_info(char *elf_name, int index, int value, char *section_name) {
    return set_rel(elf_name, index, value, R_INFO, section_name);
}

int set_rel_type(char *elf_name, int index, int value, char *section_name) {
    return set_rel(elf_name, index, value, R_TYPE, section_name);
}

int set_rel_index(char *elf_name, int index, int value, char *section_name) {
    return set_rel(elf_name, index, value, R_INDEX, section_name);
}

static int set_dyn(char *elf_name, int index, int value, enum DynamicLabel label)  {
    int fd;
    struct stat st;
    uint8_t *elf_map;
    uint8_t *tmp_sec_name;

    fd = open(elf_name, O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        perror("fstat");
        return -1;
    }

    elf_map = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (elf_map == MAP_FAILED) {
        perror("mmap");
        return -1;
    }

    /* 32bit */
    if (MODE == ELFCLASS32) {
        Elf32_Ehdr *ehdr;
        Elf32_Shdr *shdr;
        Elf32_Shdr shstrtab;
        Elf32_Dyn *dyn;

        ehdr = (Elf32_Ehdr *)elf_map;
        shdr = (Elf32_Shdr *)&elf_map[ehdr->e_shoff];
        shstrtab = shdr[ehdr->e_shstrndx];

        for (int i = 0; i < ehdr->e_shnum; i++) {
            tmp_sec_name = elf_map + shstrtab.sh_offset + shdr[i].sh_name;
            if (!strcmp(".dynamic", tmp_sec_name)) {
                int size = 0;
                /* security check start*/
                if (shdr[i].sh_entsize != 0)
                    size = shdr[i].sh_size / shdr[i].sh_entsize;
                else {
                    close(fd);
                    return -1;
                }
                if (index >= size) {
                    close(fd);
                    return -1;
                }
                /* security check end*/
                dyn = (Elf32_Dyn *)(elf_map + shdr[i].sh_offset);
                break;
            }
        }

        if (!dyn) {
            close(fd);
            WARNING("This file does not have %s\n", ".dynamic");
            return -1;
        }

        switch (label)
        {
            case D_TAG:
                printf("%d->%d\n", dyn[index].d_tag, value);
                dyn[index].d_tag = value;
                break;

            case D_VALUE:
                printf("0x%x->0x%x\n", dyn[index].d_un.d_val, value);
                dyn[index].d_un.d_val = value;
            
            default:
                break;
        }
    }

    /* 64bit */
    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        Elf64_Shdr *shdr;
        Elf64_Shdr shstrtab;
        Elf64_Dyn *dyn;

        ehdr = (Elf64_Ehdr *)elf_map;
        shdr = (Elf64_Shdr *)&elf_map[ehdr->e_shoff];
        shstrtab = shdr[ehdr->e_shstrndx];

        for (int i = 0; i < ehdr->e_shnum; i++) {
            tmp_sec_name = elf_map + shstrtab.sh_offset + shdr[i].sh_name;
            if (!strcmp(".dynamic", tmp_sec_name)) {
                int size = 0;
                /* security check start*/
                if (shdr[i].sh_entsize != 0)
                    size = shdr[i].sh_size / shdr[i].sh_entsize;
                else {
                    close(fd);
                    return -1;
                }
                if (index >= size) {
                    close(fd);
                    return -1;
                }
                /* security check end*/
                dyn = (Elf64_Dyn *)(elf_map + shdr[i].sh_offset);
                break;
            }
        }

        if (!dyn) {
            close(fd);
            WARNING("This file does not have %s\n", ".dynamic");
            return -1;
        }

        switch (label)
        {
            case D_TAG:
                printf("%d->%d\n", dyn[index].d_tag, value);
                dyn[index].d_tag = value;
                break;

            case D_VALUE:
                printf("0x%x->0x%x\n", dyn[index].d_un.d_val, value);
                dyn[index].d_un.d_val = value;
            
            default:
                break;
        }
    }

    close(fd);
    munmap(elf_map, st.st_size);
    return 0;
}

/**
 * @brief Set the .dynamic section offset
 * 
 * @param elf_name elf file name
 * @param index readelf section row
 * @param value 
 * @return error code {-1:error,0:sucess}
 */
int set_dyn_tag(char *elf_name, int index, int value) {
    return set_dyn(elf_name, index, value, D_TAG);
}

int set_dyn_value(char *elf_name, int index, int value) {
    return set_dyn(elf_name, index, value, D_VALUE);
}

/**
 * @brief Set the dynsym name by str object
 * 
 * @param elf_name elf file name
 * @param index elf file name
 * @param name string value to be edited
 * @param section_name .dynsym or .symtab
 * @param str_section_name .dynstr or .strtab
 * @return int error code {-1:error,0:sucess}
 */
int edit_sym_name_string(char *elf_name, int index, char *name, char *section_name, char *str_section_name) {
    int fd;
    struct stat st;
    uint64_t sym_offset, str_offset;
    size_t str_size;
    uint8_t *elf_map;
    uint8_t *tmp_sec_name;
    uint8_t *origin_name;        // origin dynamic item name

    fd = open(elf_name, O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        perror("fstat");
        return -1;
    }

    elf_map = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (elf_map == MAP_FAILED) {
        perror("mmap");
        return -1;
    }

    /* 32bit */
    if (MODE == ELFCLASS32) {
        Elf32_Ehdr *ehdr;
        Elf32_Shdr *shdr;
        Elf32_Shdr shstrtab;
        Elf32_Sym *sym;

        ehdr = (Elf32_Ehdr *)elf_map;
        shdr = (Elf32_Shdr *)&elf_map[ehdr->e_shoff];
        shstrtab = shdr[ehdr->e_shstrndx];

        for (int i = 0; i < ehdr->e_shnum; i++) {
            tmp_sec_name = elf_map + shstrtab.sh_offset + shdr[i].sh_name;
            if (!strcmp(section_name, tmp_sec_name)) {
                sym_offset = shdr[i].sh_offset;
            } else if (!strcmp(str_section_name, tmp_sec_name)) {
                str_offset = shdr[i].sh_offset;
                str_size = shdr[i].sh_size;
            }
        }
        sym = (Elf32_Sym *)(elf_map + sym_offset);
        origin_name = elf_map + str_offset + sym[index].st_name;
    }

    /* 64bit */
    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        Elf64_Shdr *shdr;
        Elf64_Shdr shstrtab;
        Elf64_Sym *sym;

        ehdr = (Elf64_Ehdr *)elf_map;
        shdr = (Elf64_Shdr *)&elf_map[ehdr->e_shoff];
        shstrtab = shdr[ehdr->e_shstrndx];

        for (int i = 0; i < ehdr->e_shnum; i++) {
            tmp_sec_name = elf_map + shstrtab.sh_offset + shdr[i].sh_name;
            if (!strcmp(section_name, tmp_sec_name)) {
                sym_offset = shdr[i].sh_offset;
            } else if (!strcmp(str_section_name, tmp_sec_name)) {
                str_offset = shdr[i].sh_offset;
                str_size = shdr[i].sh_size;
            }
        }
        sym = (Elf64_Sym *)(elf_map + sym_offset);
        origin_name = elf_map + str_offset + sym[index].st_name;
    }

    if (!sym_offset) {
        WARNING("This file does not have %s\n", section_name);
        close(fd);
        munmap(elf_map, st.st_size);
        return -1;
    }

    if (!str_offset) {
        WARNING("This file does not have %s\n", str_section_name);
        close(fd);
        munmap(elf_map, st.st_size);
        return -1;
    }

    printf("%s->%s\n", origin_name, name);

    // 1. copy name
    if (strlen(name) <= strlen(origin_name)) {
        memset(origin_name, 0, strlen(origin_name) + 1);
        strcpy(origin_name, name);
        close(fd);
        munmap(elf_map, st.st_size);
        return 0;
    } 
    // 2. if new name length > origin_name
    else {
        close(fd);
        munmap(elf_map, st.st_size);

        int result = -1;
        if (!strcmp(section_name, ".dynsym")) {
            VERBOSE("set sym name value: 0x%x\n", str_size);
            set_sym_name(elf_name, index, str_size, section_name);
            result = expand_dynstr_segment(elf_name, name);
        } 
        
        if (!strcmp(section_name, ".symtab")) {
            set_sym_name(elf_name, index, str_size, section_name);
            result = expand_strtab_section(elf_name, name);
        }

        if (result) {
            return -1;
        } else {
            return 0;
        }
    }
}

int edit_dyn_name_value(char *elf_name, int index, char *name) {
    int fd;
    struct stat st;
    uint64_t dynamic_offset, dynstr_offset;
    size_t dynstr_size;
    uint8_t *elf_map;
    uint8_t *tmp_sec_name;
    uint8_t *origin_name;        // origin dynamic item name

    fd = open(elf_name, O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        perror("fstat");
        return -1;
    }

    elf_map = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (elf_map == MAP_FAILED) {
        perror("mmap");
        return -1;
    }

    /* 32bit */
    if (MODE == ELFCLASS32) {
        Elf32_Ehdr *ehdr;
        Elf32_Shdr *shdr;
        Elf32_Shdr shstrtab;
        Elf32_Dyn *dyn;

        ehdr = (Elf32_Ehdr *)elf_map;
        shdr = (Elf32_Shdr *)&elf_map[ehdr->e_shoff];
        shstrtab = shdr[ehdr->e_shstrndx];

        for (int i = 0; i < ehdr->e_shnum; i++) {
            tmp_sec_name = elf_map + shstrtab.sh_offset + shdr[i].sh_name;
            if (!strcmp(".dynamic", tmp_sec_name)) {
                dynamic_offset = shdr[i].sh_offset;
            } else if (!strcmp(".dynstr", tmp_sec_name)) {
                dynstr_offset = shdr[i].sh_offset;
                dynstr_size = shdr[i].sh_size;
            }
        }
        dyn = (Elf32_Dyn *)(elf_map + dynamic_offset);
        origin_name = elf_map + dynstr_offset + dyn[index].d_un.d_val;
    }

    /* 64bit */
    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        Elf64_Shdr *shdr;
        Elf64_Shdr shstrtab;
        Elf64_Dyn *dyn;

        ehdr = (Elf64_Ehdr *)elf_map;
        shdr = (Elf64_Shdr *)&elf_map[ehdr->e_shoff];
        shstrtab = shdr[ehdr->e_shstrndx];

        for (int i = 0; i < ehdr->e_shnum; i++) {
            tmp_sec_name = elf_map + shstrtab.sh_offset + shdr[i].sh_name;
            if (!strcmp(".dynamic", tmp_sec_name)) {
                dynamic_offset = shdr[i].sh_offset;
            } else if (!strcmp(".dynstr", tmp_sec_name)) {
                dynstr_offset = shdr[i].sh_offset;
                dynstr_size = shdr[i].sh_size;
            }
        }
        dyn = (Elf64_Dyn *)(elf_map + dynamic_offset);
        origin_name = elf_map + dynstr_offset + dyn[index].d_un.d_val;
    }

    if (!dynamic_offset) {
        WARNING("This file does not have %s\n", ".dynamic");
        close(fd);
        munmap(elf_map, st.st_size);
        return -1;
    }

    if (!dynstr_offset) {
        WARNING("This file does not have %s\n", ".dynstr");
        close(fd);
        munmap(elf_map, st.st_size);
        return -1;
    }

    printf("%s->%s\n", origin_name, name);

    // 1. copy name
    if (strlen(name) <= strlen(origin_name)) {
        memset(origin_name, 0, strlen(origin_name) + 1);
        strcpy(origin_name, name);
        close(fd);
        munmap(elf_map, st.st_size);
        return 0;
    } 
    // 2. if new name length > origin_name
    else {
        close(fd);
        munmap(elf_map, st.st_size);
        //size_t size;
        //get_dynamic_value_by_tag(elf_name, DT_STRSZ, &size);
        set_dyn_value(elf_name, index, dynstr_size);
        int result = expand_dynstr_segment(elf_name, name);
        if (result) {
            return -1;
        } else {
            return 0;
        }
    }
}

/**
 * @brief 编辑某些节存储的指针
 * edit pointers stored in certain sections
 * @param elf_name elf file name
 * @param index item index
 * @param value new pointer
 * @param section_name section name, such as .init_array.
 * @return int error code {-1:error,0:sucess}
 */
int edit_pointer_value(char *elf_name, int index, uint64_t value, char *section_name) {
    int fd;
    struct stat st;
    int type;
    int bind;
    uint8_t *elf_map;
    uint64_t sec_offset, sec_size;

    {
        sec_offset = 0;
        sec_size = 0;
    }
    sec_offset = get_section_offset(elf_name, section_name);
    sec_size = get_section_size(elf_name, section_name);
    if (!sec_offset || !sec_size) {
        return -1;
    }

    fd = open(elf_name, O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        perror("fstat");
        return -1;
    }

    elf_map = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (elf_map == MAP_FAILED) {
        perror("mmap");
        return -1;
    }

    /* 32bit */
    if (MODE == ELFCLASS32) {
        uint32_t *sec = (uint32_t *)(elf_map + sec_offset);
        int count = sec_size / sizeof(uint32_t);
        if (index >= count) {
            goto ERR_EXIT;
        }
        printf("0x%x->0x%x\n", sec[index], value);
        sec[index] = value & 0xffff;    // avoid interger overflow
    }

    /* 64bit */
    else if (MODE == ELFCLASS64) {
        uint64_t *sec = (uint64_t *)(elf_map + sec_offset);
        int count = sec_size / sizeof(uint64_t);
        if (index >= count) {
            goto ERR_EXIT;
        }
        printf("0x%x->0x%x\n", sec[index], value);
        sec[index] = value;
    }

    close(fd);
    munmap(elf_map, st.st_size);
    return 0;

ERR_EXIT:
    close(fd);
    munmap(elf_map, st.st_size);
    return -1;
}

/**
 * @brief entry function
 * 
 * @param elf elf file name
 * @param po selection
 * @param section_name only for rela section
 * @return error code {-1:error,0:sucess} 
 */
int edit(char *elf, parser_opt_t *po, int row, int column, int value, char *section_name, char *str_name) {
    int error_code = 0;

    /* edit ELF header information */
    if (!get_option(po, HEADERS)) {
        switch (row)
        {
            case 0:
                error_code = set_header_type(elf, value);
                break;

            case 1:
                error_code = set_header_machine(elf, value);
                break;

            case 2:
                error_code = set_header_version(elf, value);
                break;

            case 3:
                error_code = set_header_entry(elf, value);
                break;

            case 4:
                error_code = set_header_phoff(elf, value);
                break;

            case 5:
                error_code = set_header_shoff(elf, value);
                break;

            case 6:
                error_code = set_header_flags(elf, value);
                break;

            case 7:
                error_code = set_header_ehsize(elf, value);
                break;

            case 8:
                error_code = set_header_phentsize(elf, value);
                break;

            case 9:
                error_code = set_header_phnum(elf, value);
                break;

            case 10:
                error_code = set_header_shentsize(elf, value);
                break;
            
            case 11:
                error_code = set_header_shnum(elf, value);
                break;
            
            case 12:
                error_code = set_header_shstrndx(elf, value);
                break;
            
            default:
                break;
        }
    }

    /* edit section informtion */
    if (!get_option(po, SECTIONS)) {
        switch (column)
        {
            case 0:
                if (!strlen(str_name)) {
                    error_code = set_section_name(elf, row, value);
                } else {
                    error_code = set_section_name_by_str(elf, row, str_name);
                }
                break;

            case 1:
                error_code = set_section_type(elf, row, value);
                break;

            case 2:
                error_code = set_section_addr(elf, row, value);
                break;

            case 3:
                error_code = set_section_off(elf, row, value);
                break;

            case 4:
                error_code = set_section_size(elf, row, value);
                break;

            case 5:
                error_code = set_section_entsize(elf, row, value);
                break;

            case 6:
                error_code = set_section_flags(elf, row, value);
                break;

            case 7:
                error_code = set_section_link(elf, row, value);
                break;

            case 8:
                error_code = set_section_info(elf, row, value);
                break;

            case 9:
                error_code = set_section_align(elf, row, value);
                break;
            
            default:
                break;
        }
    }
    
    /* edit segment information */
    if (!get_option(po, SEGMENTS)) {
        switch (column)
        {
            case 0:
                error_code = set_segment_type(elf, row, value);
                break;

            case 1:
                error_code = set_segment_offset(elf, row, value);
                break;

            case 2:
                error_code = set_segment_vaddr(elf, row, value);
                break;

            case 3:
                error_code = set_segment_paddr(elf, row, value);
                break;

            case 4:
                error_code = set_segment_filesz(elf, row, value);
                break;

            case 5:
                error_code = set_segment_memsz(elf, row, value);
                break;

            case 6:
                error_code = set_segment_flags(elf, row, value);
                break;

            case 7:
                error_code = set_segment_align(elf, row, value);
                break;
            
            default:
                break;
        }
    }

    /* edit .dynsym informtion */
    if (!get_option(po, DYNSYM)) {
        switch (column)
        {
            case 0:
                error_code = set_sym_value(elf, row, value, ".dynsym");
                break;

            case 1:
                error_code = set_sym_size(elf, row, value, ".dynsym");
                break;

            case 2:
                error_code = set_sym_type(elf, row, value, ".dynsym");
                break;

            case 3:
                error_code = set_sym_bind(elf, row, value, ".dynsym");
                break;

            case 4:
                error_code = set_sym_other(elf, row, value, ".dynsym");
                break;

            case 5:
                error_code = set_sym_shndx(elf, row, value, ".dynsym");
                break;

            case 6:
                if (!strlen(str_name)) {
                    error_code = set_sym_name(elf, row, value, ".dynsym");
                } else {
                    error_code = edit_sym_name_string(elf, row, str_name, ".dynsym", ".dynstr");
                }
                break;
            
            default:
                break;
        }
    }

    /* edit .symtab informtion */
    if (!get_option(po, SYMTAB)) {
        switch (column)
        {
            case 0:
                error_code = set_sym_value(elf, row, value, ".symtab");
                break;

            case 1:
                error_code = set_sym_size(elf, row, value, ".symtab");
                break;

            case 2:
                error_code = set_sym_type(elf, row, value, ".symtab");
                break;

            case 3:
                error_code = set_sym_bind(elf, row, value, ".symtab");
                break;

            case 4:
                error_code = set_sym_other(elf, row, value, ".symtab");
                break;

            case 5:
                error_code = set_sym_shndx(elf, row, value, ".symtab");
                break;

            case 6:
                if (!strlen(str_name)) {
                    error_code = set_sym_name(elf, row, value, ".symtab");
                } else {
                    error_code = edit_sym_name_string(elf, row, str_name, ".symtab", ".strtab");
                }
            
            default:
                break;
        }
    }

    /* edit .rel and .rela informtion */
    if (!get_option(po, RELA)) {
        if (compare_firstN_chars(section_name, ".rel.", 5)) {
            switch (column)
            {
                case 0:
                    error_code = set_rel_offset(elf, row, value, section_name);
                    break;

                case 1:
                    error_code = set_rel_info(elf, row, value, section_name);
                    break;

                case 2:
                    error_code = set_rel_type(elf, row, value, section_name);
                    break;

                case 3:
                    error_code = set_rel_index(elf, row, value, section_name);
                    break;
                
                default:
                    break;
            }
        }
        if (compare_firstN_chars(section_name, ".rela", 5)) {
            switch (column)
            {
                case 0:
                    error_code = set_rela_offset(elf, row, value, section_name);
                    break;

                case 1:
                    error_code = set_rela_info(elf, row, value, section_name);
                    break;

                case 2:
                    error_code = set_rela_type(elf, row, value, section_name);
                    break;

                case 3:
                    error_code = set_rela_index(elf, row, value, section_name);
                    break;

                case 4:
                    error_code = set_rela_addend(elf, row, value, section_name);
                    break;
                
                default:
                    break;
            }
        }

    }

    /* edit .dynamic informtion */
    if (!get_option(po, LINK)) {
        switch (column)
        {
            case 0:
                error_code = set_dyn_tag(elf, row, value);
                break;

            case 1:
                error_code = set_dyn_tag(elf, row, value);
                break;

            case 2:
                if (!strlen(str_name)) {
                    error_code = set_dyn_value(elf, row, value);
                } else {
                    error_code = edit_dyn_name_value(elf, row, str_name);
                }
                break;
            
            default:
                break;
        }
    }

    /* edit pointer information */
    if (!get_option(po, POINTER)) {
        switch (column)
        {
            case 0:
                error_code = edit_pointer_value(elf, row, value, section_name);
                break;

            case 1:
                INFO("You can edit symbol by option '-B' instead of '-I'\n");
                break;
            
            default:
                break;
        }
    }

    return error_code;
}
