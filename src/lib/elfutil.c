#define _GNU_SOURCE
#include <stddef.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>
#include "elfutil.h"
#include "section_manager.h"

/**
 * @brief 初始化elf文件，将elf文件转化为elf结构体
 * initialize the elf file and convert it into an elf structure
 * @param elf elf file name
 * @return error code
 */
int init(char *elf_name, Elf *elf) {
    int fd = -1;
    struct stat st;
    uint8_t *elf_map = NULL;

    fd = open(elf_name, O_RDWR);
    if (fd < 0) {
        perror("open");
        return FALSE;
    }

    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return FALSE;
    }

    elf_map = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (elf_map == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return FALSE;
    }

    unsigned char *ident = (unsigned char *)elf_map;
    elf->class = ident[EI_CLASS];
    elf->fd = fd;
    elf->mem = elf_map;
    elf->size = st.st_size;

    /* 32bit */
    if (elf->class == ELFCLASS32) {
        elf->data.elf32.ehdr = (Elf32_Ehdr *)elf->mem;
        elf->data.elf32.shdr = (Elf32_Shdr *)&elf->mem[elf->data.elf32.ehdr->e_shoff];
        elf->data.elf32.phdr = (Elf32_Phdr *)&elf->mem[elf->data.elf32.ehdr->e_phoff];
        elf->data.elf32.shstrtab = (Elf32_Shdr *)&elf->data.elf32.shdr[elf->data.elf32.ehdr->e_shstrndx];
        elf->data.elf32.dynstrtab = NULL;
        elf->data.elf32.strtab = NULL;
        elf->data.elf32.dynsym = NULL;
        elf->data.elf32.dynsym_entry = NULL;
        for (int i = 0; i < elf->data.elf32.ehdr->e_shnum; i++) {
            char *section_name = elf->mem + elf->data.elf32.shstrtab->sh_offset + elf->data.elf32.shdr[i].sh_name;
            if (!strcmp(section_name, ".dynstr")) {
                elf->data.elf32.dynstrtab = (Elf32_Shdr *)&elf->data.elf32.shdr[i];
            }
            if (!strcmp(section_name, ".strtab")) {
                elf->data.elf32.strtab = (Elf32_Shdr *)&elf->data.elf32.shdr[i];
            }
            if (!strcmp(section_name, ".dynsym")) {
                elf->data.elf32.dynsym = (Elf32_Shdr *)&elf->data.elf32.shdr[i];
                elf->data.elf32.dynsym_entry = (Elf32_Sym *)&elf->mem[elf->data.elf32.dynsym->sh_offset];
            }
            if (!strcmp(section_name, ".symtab")) {
                elf->data.elf32.sym = (Elf32_Shdr *)&elf->data.elf32.shdr[i];
                elf->data.elf32.sym_entry = (Elf32_Sym *)&elf->mem[elf->data.elf32.sym->sh_offset];
            }
        }

        elf->data.elf32.dyn_segment_entry = NULL;
        elf->data.elf32.dyn_segment_count = 0;
        for (int i = 0; i < elf->data.elf32.ehdr->e_phnum; i++) {
            if (elf->data.elf32.phdr[i].p_type == PT_DYNAMIC) {
                elf->data.elf32.dyn_segment_entry = (Elf32_Dyn *)&elf->mem[elf->data.elf32.phdr[i].p_offset];
                elf->data.elf32.dyn_segment_count = elf->data.elf32.phdr[i].p_filesz / sizeof(Elf32_Dyn);
            }
        }
    }

    /* 64bit */
    if (elf->class == ELFCLASS64) {
        elf->data.elf64.ehdr = (Elf64_Ehdr *)elf->mem;
        elf->data.elf64.shdr = (Elf64_Shdr *)&elf->mem[elf->data.elf64.ehdr->e_shoff];
        elf->data.elf64.phdr = (Elf64_Phdr *)&elf->mem[elf->data.elf64.ehdr->e_phoff];
        elf->data.elf64.shstrtab = (Elf64_Shdr *)&elf->data.elf64.shdr[elf->data.elf64.ehdr->e_shstrndx];
        elf->data.elf64.dynstrtab = NULL;
        elf->data.elf64.strtab = NULL;
        elf->data.elf64.dynsym = NULL;
        elf->data.elf64.dynsym_entry = NULL;
        for (int i = 0; i < elf->data.elf64.ehdr->e_shnum; i++) {
            char *section_name = elf->mem + elf->data.elf64.shstrtab->sh_offset + elf->data.elf64.shdr[i].sh_name;
            if (!strcmp(section_name, ".dynstr")) {
                elf->data.elf64.dynstrtab = (Elf64_Shdr *)&elf->data.elf64.shdr[i];
            }
            if (!strcmp(section_name, ".strtab")) {
                elf->data.elf64.strtab = (Elf64_Shdr *)&elf->data.elf64.shdr[i];
            }
            if (!strcmp(section_name, ".dynsym")) {
                elf->data.elf64.dynsym = (Elf64_Shdr *)&elf->data.elf64.shdr[i];
                elf->data.elf64.dynsym_entry = (Elf64_Sym *)&elf->mem[elf->data.elf64.dynsym->sh_offset];
            }
            if (!strcmp(section_name, ".symtab")) {
                elf->data.elf64.sym = (Elf64_Shdr *)&elf->data.elf64.shdr[i];
                elf->data.elf64.sym_entry = (Elf64_Sym *)&elf->mem[elf->data.elf64.sym->sh_offset];
            }
        }

        elf->data.elf64.dyn_segment_entry = NULL;
        elf->data.elf64.dyn_segment_count = 0;
        for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
            if (elf->data.elf64.phdr[i].p_type == PT_DYNAMIC) {
                elf->data.elf64.dyn_segment_entry = (Elf64_Dyn *)&elf->mem[elf->data.elf64.phdr[i].p_offset];
                elf->data.elf64.dyn_segment_count = elf->data.elf64.phdr[i].p_filesz / sizeof(Elf64_Dyn);
            }
        }
    }

    return TRUE;
}

int finit(Elf *elf) {
    close(elf->fd);
    munmap(elf->mem, elf->size);
}

/**
 * @brief 根据节的名称，获取节的下标
 * Obtain the index of the section based on its name.
 * @param elf Elf custom structure
 * @param name Elf section name
 * @return section index
 */
int get_section_index_by_name(Elf *elf, char *name) {
    int ret = FALSE;
    if (elf->class == ELFCLASS32) {
        for (int i = 0; i < elf->data.elf32.ehdr->e_shnum; i++) {
            char *section_name = elf->mem + elf->data.elf32.shstrtab->sh_offset + elf->data.elf32.shdr[i].sh_name;
            if (!strcmp(name, section_name)) {
                ret = i;
                break;
            }
        }
    }
    else if (elf->class == ELFCLASS64) {
        for (int i = 0; i < elf->data.elf64.ehdr->e_shnum; i++) {
            char *section_name = elf->mem + elf->data.elf64.shstrtab->sh_offset + elf->data.elf64.shdr[i].sh_name;
            if (!strcmp(name, section_name)) {
                ret = i;
                break;
            }
        }
    }
    return ret;
}

/**
 * @brief 根据节的名称，获取节的虚拟地址
 * Obtain the virtual address of the section based on its name.
 * @param elf Elf custom structure
 * @param name Elf section name
 * @return section virtual address
 */
int get_section_addr_by_name(Elf *elf, char *name) {
    int index = get_section_index_by_name(elf, name);
    if (index != FALSE) {
        if (elf->class == ELFCLASS32) {
            return elf->data.elf32.shdr[index].sh_addr;
        } else if (elf->class == ELFCLASS64) {
            return elf->data.elf64.shdr[index].sh_addr;
        }
        else {
            return FALSE;
        }
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据节的名称，获取节的偏移地址
 * Obtain the section offset based on its name.
 * @param elf Elf custom structure
 * @param name Elf section name
 * @return section offset
 */
int get_section_offset_by_name(Elf *elf, char *name) {
    int index = get_section_index_by_name(elf, name);
    if (index != FALSE) {
        if (elf->class == ELFCLASS32) {
            return elf->data.elf32.shdr[index].sh_offset;
        } else if (elf->class == ELFCLASS64) {
            return elf->data.elf64.shdr[index].sh_offset;
        }
        else {
            return FALSE;
        }
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据节的名称，获取节类型
 * Obtain the section type based on its name.
 * @param elf Elf custom structure
 * @param name Elf section name
 * @return section type
 */
int get_section_type_by_name(Elf *elf, char *name) {
    int index = get_section_index_by_name(elf, name);
    if (index != FALSE) {
        if (elf->class == ELFCLASS32) {
            return elf->data.elf32.shdr[index].sh_type;
        } else if (elf->class == ELFCLASS64) {
            return elf->data.elf64.shdr[index].sh_type;
        }
        else {
            return FALSE;
        }
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据节的名称，获取节大小
 * Obtain the section size based on its name.
 * @param elf Elf custom structure
 * @param name Elf section name
 * @return section size
 */
int get_section_size_by_name(Elf *elf, char *name) {
    int index = get_section_index_by_name(elf, name);
    if (index != FALSE) {
        if (elf->class == ELFCLASS32) {
            return elf->data.elf32.shdr[index].sh_size;
        } else if (elf->class == ELFCLASS64) {
            return elf->data.elf64.shdr[index].sh_size;
        }
        else {
            return FALSE;
        }
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 若该section是一个table, table中每个项目的大小是多大
 * Obtain the section entry size based on its name.
 * @param elf Elf custom structure
 * @param name Elf section name
 * @return section entry size
 */
int get_section_entsize_by_name(Elf *elf, char *name) {
    int index = get_section_index_by_name(elf, name);
    if (index != FALSE) {
        if (elf->class == ELFCLASS32) {
            return elf->data.elf32.shdr[index].sh_entsize;
        } else if (elf->class == ELFCLASS64) {
            return elf->data.elf64.shdr[index].sh_entsize;
        }
        else {
            return FALSE;
        }
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 获取节的对齐方式
 * Obtain the section alignment based on its name.
 * @param elf Elf custom structure
 * @param name Elf section name
 * @return section alignment
 */
int get_section_addralign_by_name(Elf *elf, char *name) {
    int index = get_section_index_by_name(elf, name);
    if (index != FALSE) {
        if (elf->class == ELFCLASS32) {
            return elf->data.elf32.shdr[index].sh_addralign;
        } else if (elf->class == ELFCLASS64) {
            return elf->data.elf64.shdr[index].sh_addralign;
        }
        else {
            return FALSE;
        }
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 获取节的标志
 * Obtain the section flags based on its name.
 * @param elf Elf custom structure
 * @param name Elf section name
 * @return section flags
 */
int get_section_flags_by_name(Elf *elf, char *name) {
    int index = get_section_index_by_name(elf, name);
    if (index != FALSE) {
        if (elf->class == ELFCLASS32) {
            return elf->data.elf32.shdr[index].sh_flags;
        } else if (elf->class == ELFCLASS64) {
            return elf->data.elf64.shdr[index].sh_flags;
        }
        else {
            return FALSE;
        }
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 获取节的链接，即链接到另外一个节
 * Obtain the section link based on its name.
 * @param elf Elf custom structure
 * @param name Elf section name
 * @return section link
 */
int get_section_link_by_name(Elf *elf, char *name) {
    int index = get_section_index_by_name(elf, name);
    if (index != FALSE) {
        if (elf->class == ELFCLASS32) {
            return elf->data.elf32.shdr[index].sh_link;
        } else if (elf->class == ELFCLASS64) {
            return elf->data.elf64.shdr[index].sh_link;
        }
        else {
            return FALSE;
        }
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 获取节的额外信息
 * Obtain the section additional information based on its name.
 * @param elf Elf custom structure
 * @param name Elf section name
 * @return section additional information
 */
int get_section_info_by_name(Elf *elf, char *name) {
    int index = get_section_index_by_name(elf, name);
    if (index != FALSE) {
        if (elf->class == ELFCLASS32) {
            return elf->data.elf32.shdr[index].sh_info;
        } else if (elf->class == ELFCLASS64) {
            return elf->data.elf64.shdr[index].sh_info;
        }
        else {
            return FALSE;
        }
    }
    else {
        return FALSE;
    }
}


/**
 * @brief 根据节的名称，设置节的虚拟地址
 * Set the virtual address of the section based on its name.
 * @param elf Elf custom structure
 * @param name Elf section name
 * @param addr the values that need to be set
 * @return error code
 */
int set_section_addr_by_name(Elf *elf, char *name, uint64_t addr) {
    int index = get_section_index_by_name(elf, name);
    if (index != FALSE) {
        if (elf->class == ELFCLASS32) {
            elf->data.elf32.shdr[index].sh_addr = addr;
        } else if (elf->class == ELFCLASS64) {
            elf->data.elf64.shdr[index].sh_addr = addr;
        }
        else {
            return FALSE;
        }
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据节的名称，设置节的偏移地址
 * Set the section offset based on its name.
 * @param elf Elf custom structure
 * @param name Elf section name
 * @param offset the values that need to be set
 * @return error code
 */
int set_section_offset_by_name(Elf *elf, char *name, uint64_t offset) {
    int index = get_section_index_by_name(elf, name);
    if (index != FALSE) {
        if (elf->class == ELFCLASS32) {
            elf->data.elf32.shdr[index].sh_offset = offset;
        } else if (elf->class == ELFCLASS64) {
            elf->data.elf64.shdr[index].sh_offset = offset;
        }
        else {
            return FALSE;
        }
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据节的名称，设置节的类型
 * Set the section type based on its name.
 * @param elf Elf custom structure
 * @param name Elf section name
 * @param type the values that need to be set
 * @return error code
 */
int set_section_type_by_name(Elf *elf, char *name, uint64_t type) {
    int index = get_section_index_by_name(elf, name);
    if (index != FALSE) {
        if (elf->class == ELFCLASS32) {
            elf->data.elf32.shdr[index].sh_type = type;
        } else if (elf->class == ELFCLASS64) {
            elf->data.elf64.shdr[index].sh_type = type;
        }
        else {
            return FALSE;
        }
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据节的名称，设置节的大小
 * Set the section size based on its name.
 * @param elf Elf custom structure
 * @param name Elf section name
 * @param size the values that need to be set
 * @return error code
 */
int set_section_size_by_name(Elf *elf, char *name, uint64_t size) {
    int index = get_section_index_by_name(elf, name);
    if (index != FALSE) {
        if (elf->class == ELFCLASS32) {
            elf->data.elf32.shdr[index].sh_size = size;
        } else if (elf->class == ELFCLASS64) {
            elf->data.elf64.shdr[index].sh_size = size;
        }
        else {
            return FALSE;
        }
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据节的名称，设置节的表格每个条目的长度
 * Set the section entsize based on its name.
 * @param elf Elf custom structure
 * @param name Elf section name
 * @param addr the values that need to be set
 * @return error code
 */
int set_section_entsize_by_name(Elf *elf, char *name, uint64_t entsize) {
    int index = get_section_index_by_name(elf, name);
    if (index != FALSE) {
        if (elf->class == ELFCLASS32) {
            elf->data.elf32.shdr[index].sh_entsize = entsize;
        } else if (elf->class == ELFCLASS64) {
            elf->data.elf64.shdr[index].sh_entsize = entsize;
        }
        else {
            return FALSE;
        }
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据节的名称，设置节的对齐方式
 * Set the section addralign based on its name.
 * @param elf Elf custom structure
 * @param name Elf section name
 * @param addr the values that need to be set
 * @return error code
 */
int set_section_addralign_by_name(Elf *elf, char *name, uint64_t addralign) {
    int index = get_section_index_by_name(elf, name);
    if (index != FALSE) {
        if (elf->class == ELFCLASS32) {
            elf->data.elf32.shdr[index].sh_addralign = addralign;
        } else if (elf->class == ELFCLASS64) {
            elf->data.elf64.shdr[index].sh_addralign = addralign;
        }
        else {
            return FALSE;
        }
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据节的名称，设置节的标志
 * Set the section flags based on its name.
 * @param elf Elf custom structure
 * @param name Elf section name
 * @param addr the values that need to be set
 * @return error code
 */
int set_section_flags_by_name(Elf *elf, char *name, uint64_t flags) {
    int index = get_section_index_by_name(elf, name);
    if (index != FALSE) {
        if (elf->class == ELFCLASS32) {
            elf->data.elf32.shdr[index].sh_flags = flags;
        } else if (elf->class == ELFCLASS64) {
            elf->data.elf64.shdr[index].sh_flags = flags;
        }
        else {
            return FALSE;
        }
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据节的名称，设置节的指向下一个section的链接
 * Set the section link based on its name.
 * @param elf Elf custom structure
 * @param name Elf section name
 * @param addr the values that need to be set
 * @return error code
 */
int set_section_link_by_name(Elf *elf, char *name, uint64_t link) {
    int index = get_section_index_by_name(elf, name);
    if (index != FALSE) {
        if (elf->class == ELFCLASS32) {
            elf->data.elf32.shdr[index].sh_link = link;
        } else if (elf->class == ELFCLASS64) {
            elf->data.elf64.shdr[index].sh_link = link;
        }
        else {
            return FALSE;
        }
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据节的名称，设置节的额外信息
 * Set the section additional information based on its name.
 * @param elf Elf custom structure
 * @param name Elf section name
 * @param addr the values that need to be set
 * @return error code
 */
int set_section_info_by_name(Elf *elf, char *name, uint64_t info) {
    int index = get_section_index_by_name(elf, name);
    if (index != FALSE) {
        if (elf->class == ELFCLASS32) {
            elf->data.elf32.shdr[index].sh_info = info;
        } else if (elf->class == ELFCLASS64) {
            elf->data.elf64.shdr[index].sh_info = info;
        }
        else {
            return FALSE;
        }
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据段的下标,获取段的对齐方式
 * Get the segment alignment based on its index.
 * @param elf Elf custom structure
 * @param index Elf segment index
 * @return error code
 */
int get_segment_align_by_index(Elf *elf, int index) {
    if (elf->class == ELFCLASS32) {
        return elf->data.elf32.phdr[index].p_align;
    } else if (elf->class == ELFCLASS64) {
        return elf->data.elf64.phdr[index].p_align;
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据段的下标,获取段的大小
 * Get the segment size based on its index.
 * @param elf Elf custom structure
 * @param index Elf segment index
 * @return error code
 */
int get_segment_filesz_by_index(Elf *elf, int index) {
    if (elf->class == ELFCLASS32) {
        return elf->data.elf32.phdr[index].p_filesz;
    } else if (elf->class == ELFCLASS64) {
        return elf->data.elf64.phdr[index].p_filesz;
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据段的下标,获取段的标志
 * Get the segment flags based on its index.
 * @param elf Elf custom structure
 * @param index Elf segment index
 * @return error code
 */
int get_segment_flags_by_index(Elf *elf, int index) {
    if (elf->class == ELFCLASS32) {
        return elf->data.elf32.phdr[index].p_flags;
    } else if (elf->class == ELFCLASS64) {
        return elf->data.elf64.phdr[index].p_flags;
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据段的下标,获取段的虚拟内存大小
 * Get the segment memory size based on its index.
 * @param elf Elf custom structure
 * @param index Elf segment index
 * @return error code
 */
int get_segment_memsz_by_index(Elf *elf, int index) {
    if (elf->class == ELFCLASS32) {
        return elf->data.elf32.phdr[index].p_memsz;
    } else if (elf->class == ELFCLASS64) {
        return elf->data.elf64.phdr[index].p_memsz;
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据段的下标,获取段的文件偏移
 * Get the segment offset based on its index.
 * @param elf Elf custom structure
 * @param index Elf segment index
 * @return error code
 */
int get_segment_offset_by_index(Elf *elf, int index) {
    if (elf->class == ELFCLASS32) {
        return elf->data.elf32.phdr[index].p_offset;
    } else if (elf->class == ELFCLASS64) {
        return elf->data.elf64.phdr[index].p_offset;
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据段的下标,获取段的物理地址
 * Get the segment physical address based on its index.
 * @param elf Elf custom structure
 * @param index Elf segment index
 * @return error code
 */
int get_segment_paddr_by_index(Elf *elf, int index) {
    if (elf->class == ELFCLASS32) {
        return elf->data.elf32.phdr[index].p_paddr;
    } else if (elf->class == ELFCLASS64) {
        return elf->data.elf64.phdr[index].p_paddr;
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据段的下标,获取段的类型
 * Get the segment type based on its index.
 * @param elf Elf custom structure
 * @param index Elf segment index
 * @return error code
 */
int get_segment_type_by_index(Elf *elf, int index) {
    if (elf->class == ELFCLASS32) {
        return elf->data.elf32.phdr[index].p_type;
    } else if (elf->class == ELFCLASS64) {
        return elf->data.elf64.phdr[index].p_type;
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据段的下标,获取段的虚拟地址
 * Get the segment virtual address based on its index.
 * @param elf Elf custom structure
 * @param index Elf segment index
 * @return error code
 */
int get_segment_vaddr_by_index(Elf *elf, int index) {
    if (elf->class == ELFCLASS32) {
        return elf->data.elf32.phdr[index].p_vaddr;
    } else if (elf->class == ELFCLASS64) {
        return elf->data.elf64.phdr[index].p_vaddr;
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据段的类型,获取段的下标
 * Get the segment index based on its type.
 * @param elf Elf custom structure
 * @param index Elf segment type
 * @return index
 */
static int get_segment_index_by_type(Elf *elf, int type) {
    if (elf->class == ELFCLASS32) {
        for (int i = 0; i < elf->data.elf32.ehdr->e_phnum; i++) {
            if (elf->data.elf32.phdr[i].p_type == type) {
                return i;
            }
        }
    } else if (elf->class == ELFCLASS64) {
        for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
            if (elf->data.elf64.phdr[i].p_type == type) {
                return i;
            }
        }
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据动态链接段的类型,获取段的下标
 * Get the dynamic segment index based on its type.
 * @param elf Elf custom structure
 * @param index Elf segment type
 * @return index
 */
int get_dynseg_index_by_type(Elf *elf, int type) {
    if (elf->class == ELFCLASS32) {
        for (int i = 0; i < elf->data.elf32.dyn_segment_count; i++) {
            if (elf->data.elf32.dyn_segment_entry[i].d_tag == type) {
                return i;
            }
        }
    } else if (elf->class == ELFCLASS64) {
        for (int i = 0; i < elf->data.elf64.dyn_segment_count; i++) {
            printf("count=%d\n", elf->data.elf64.dyn_segment_count);
            if (elf->data.elf64.dyn_segment_entry[i].d_tag == type) {
                return i;
            }
        }
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据段的下标,设置段的对齐方式
 * Set the segment alignment based on its index.
 * @param elf Elf custom structure
 * @param index Elf segment index
 * @return error code
 */
int set_segment_align_by_index(Elf *elf, int index, uint64_t align) {
    if (elf->class == ELFCLASS32) {
        elf->data.elf32.phdr[index].p_align = align;
    } else if (elf->class == ELFCLASS64) {
        elf->data.elf64.phdr[index].p_align = align;
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据段的下标,设置段的大小
 * Set the segment file size based on its index.
 * @param elf Elf custom structure
 * @param index Elf segment index
 * @return error code
 */
int set_segment_filesz_by_index(Elf *elf, int index, uint64_t filesz) {
    if (elf->class == ELFCLASS32) {
        elf->data.elf32.phdr[index].p_filesz = filesz;
    } else if (elf->class == ELFCLASS64) {
        elf->data.elf64.phdr[index].p_filesz = filesz;
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据段的下标,设置段的标志
 * Set the segment flags based on its index.
 * @param elf Elf custom structure
 * @param index Elf segment index
 * @return error code
 */
int set_segment_flags_by_index(Elf *elf, int index, uint64_t flags) {
    if (elf->class == ELFCLASS32) {
        elf->data.elf32.phdr[index].p_flags = flags;
    } else if (elf->class == ELFCLASS64) {
        elf->data.elf64.phdr[index].p_flags = flags;
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据段的下标,设置段的虚拟内存大小
 * Set the segment memory size based on its index.
 * @param elf Elf custom structure
 * @param index Elf segment index
 * @return error code
 */
int set_segment_memsz_by_index(Elf *elf, int index, uint64_t memsz) {
    if (elf->class == ELFCLASS32) {
        elf->data.elf32.phdr[index].p_memsz = memsz;
    } else if (elf->class == ELFCLASS64) {
        elf->data.elf64.phdr[index].p_memsz = memsz;
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据段的下标,设置段的文件偏移
 * Set the segment offset based on its index.
 * @param elf Elf custom structure
 * @param index Elf segment index
 * @return error code
 */
int set_segment_offset_by_index(Elf *elf, int index, uint64_t offset) {
    if (elf->class == ELFCLASS32) {
        elf->data.elf32.phdr[index].p_offset = offset;
    } else if (elf->class == ELFCLASS64) {
        elf->data.elf64.phdr[index].p_offset = offset;
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据段的下标,设置段的物理地址
 * Set the segment physical address based on its index.
 * @param elf Elf custom structure
 * @param index Elf segment index
 * @return error code
 */
int set_segment_paddr_by_index(Elf *elf, int index, uint64_t paddr) {
    if (elf->class == ELFCLASS32) {
        elf->data.elf32.phdr[index].p_paddr = paddr;
    } else if (elf->class == ELFCLASS64) {
        elf->data.elf64.phdr[index].p_paddr = paddr;
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据段的下标,设置段的类型
 * Set the segment type based on its index.
 * @param elf Elf custom structure
 * @param index Elf segment index
 * @return error code
 */
int set_segment_type_by_index(Elf *elf, int index, uint64_t type) {
    if (elf->class == ELFCLASS32) {
        elf->data.elf32.phdr[index].p_type = type;
    } else if (elf->class == ELFCLASS64) {
        elf->data.elf64.phdr[index].p_type = type;
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据段的下标,设置段的虚拟地址
 * Set the segment virtual address based on its index.
 * @param elf Elf custom structure
 * @param index Elf segment index
 * @return error code
 */
int set_segment_vaddr_by_index(Elf *elf, int index, uint64_t vaddr) {
    if (elf->class == ELFCLASS32) {
        elf->data.elf32.phdr[index].p_vaddr = vaddr;
    } else if (elf->class == ELFCLASS64) {
        elf->data.elf64.phdr[index].p_vaddr = vaddr;
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据节的名字，获取该节对应的段的下标.请注意，一个节可能属于多个段！
 * Obtain the subscript of the segment corresponding to the section based on its name.
 * Please note that a section may belong to multiple segments!
 * @param elf Elf custom structure
 * @param name Elf section name
 * @param out_index Elf segment index
 * @param max_size Elf segment index count
 * @return error code
 */
int get_section_index_in_segment(Elf *elf, char *name, int out_index[], int max_size) {
    int ret = FALSE;
    int count = 0;
    int addr = get_section_addr_by_name(elf, name);
    int size = get_section_size_by_name(elf, name);
    if (elf->class == ELFCLASS32) {
        for (int i = 0; i < elf->data.elf32.ehdr->e_phnum; i++) {
            if (addr >= elf->data.elf32.phdr[i].p_vaddr && addr+size <= elf->data.elf32.phdr[i].p_vaddr+elf->data.elf32.phdr[i].p_memsz) {
                if (count < max_size) {
                    out_index[count++] = i;
                    ret = count;
                } else 
                    break;
            }
        }
    } else if (elf->class == ELFCLASS64) {
        for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
            if (addr >= elf->data.elf64.phdr[i].p_vaddr && addr+size <= elf->data.elf64.phdr[i].p_vaddr+elf->data.elf64.phdr[i].p_memsz) {
                if (count < max_size) {
                    out_index[count++] = i;
                    ret = count;
                } else 
                    break;
            }
        }
    }
    return ret;
}


/**
 * @brief 根据符号表的名称，获取符号表的下标
 * Obtain the index of the dynamic symbol based on its name.
 * @param elf Elf custom structure
 * @param name Elf section name
 * @return section index
 */
int get_dynsym_index_by_name(Elf *elf, char *name) {
    int ret = FALSE;
    if (elf->class == ELFCLASS32) {
        int count = elf->data.elf32.dynsym->sh_size / sizeof(Elf32_Sym);
        char *tmp_name = NULL;
        for (int i = 0; i < count; i++) {
            tmp_name = elf->mem + elf->data.elf32.dynstrtab->sh_offset + elf->data.elf32.dynsym_entry[i].st_name;
            if (!strcmp(tmp_name, name)) {
                ret = i;
                break;
            }
        }
    }
    else if (elf->class == ELFCLASS64) {
        int count = elf->data.elf64.dynsym->sh_size / sizeof(Elf64_Sym);
        char *tmp_name = NULL;
        for (int i = 0; i < count; i++) {
            tmp_name = elf->mem + elf->data.elf64.dynstrtab->sh_offset + elf->data.elf64.dynsym_entry[i].st_name;
            if (!strcmp(tmp_name, name)) {
                ret = i;
                break;
            }
        }
    }
    return ret;
}

/**
 * @brief 根据符号表的名称，获取符号表的下标
 * Obtain the index of the symbol based on its name.
 * @param elf Elf custom structure
 * @param name Elf section name
 * @return section index
 */
int get_sym_index_by_name(Elf *elf, char *name) {
    int ret = FALSE;
    if (elf->class == ELFCLASS32) {
        int count = elf->data.elf32.sym->sh_size / sizeof(Elf32_Sym);
        char *tmp_name = NULL;
        for (int i = 0; i < count; i++) {
            tmp_name = elf->mem + elf->data.elf32.strtab->sh_offset + elf->data.elf32.sym_entry[i].st_name;
            if (!strcmp(tmp_name, name)) {
                ret = i;
                break;
            }
        }
    }
    else if (elf->class == ELFCLASS64) {
        int count = elf->data.elf64.sym->sh_size / sizeof(Elf64_Sym);
        char *tmp_name = NULL;
        for (int i = 0; i < count; i++) {
            tmp_name = elf->mem + elf->data.elf64.strtab->sh_offset + elf->data.elf64.sym_entry[i].st_name;
            if (!strcmp(tmp_name, name)) {
                ret = i;
                break;
            }
        }
    }
    return ret;
}


static int copy_data(void *src, void *dst, size_t size) {
    void *m = malloc(size);
    if (m == NULL) {
        perror("copy_data");
        return FALSE;
    }
    memcpy(m, src, size);
    memcpy(dst, m, size);
    free(m);
    return TRUE;
}

static void reinit(Elf *elf) {
    /* 32bit */
    if (elf->class == ELFCLASS32) {
        elf->data.elf32.ehdr = (Elf32_Ehdr *)elf->mem;
        elf->data.elf32.shdr = (Elf32_Shdr *)&elf->mem[elf->data.elf32.ehdr->e_shoff];
        elf->data.elf32.phdr = (Elf32_Phdr *)&elf->mem[elf->data.elf32.ehdr->e_phoff];
        elf->data.elf32.shstrtab = (Elf32_Shdr *)&elf->data.elf32.shdr[elf->data.elf32.ehdr->e_shstrndx];
        elf->data.elf32.dynstrtab = NULL;
        elf->data.elf32.strtab = NULL;
        elf->data.elf32.dynsym = NULL;
        elf->data.elf32.dynsym_entry = NULL;
        for (int i = 0; i < elf->data.elf32.ehdr->e_shnum; i++) {
            char *section_name = elf->mem + elf->data.elf32.shstrtab->sh_offset + elf->data.elf32.shdr[i].sh_name;
            if (!strcmp(section_name, ".dynstr")) {
                elf->data.elf32.dynstrtab = (Elf32_Shdr *)&elf->data.elf32.shdr[i];
            }
            if (!strcmp(section_name, ".strtab")) {
                elf->data.elf32.strtab = (Elf32_Shdr *)&elf->data.elf32.shdr[i];
            }
            if (!strcmp(section_name, ".dynsym")) {
                elf->data.elf32.dynsym = (Elf32_Shdr *)&elf->data.elf32.shdr[i];
                elf->data.elf32.dynsym_entry = (Elf32_Sym *)&elf->mem[elf->data.elf32.dynsym->sh_offset];
            }
            if (!strcmp(section_name, ".symtab")) {
                elf->data.elf32.sym = (Elf32_Shdr *)&elf->data.elf32.shdr[i];
                elf->data.elf32.sym_entry = (Elf32_Sym *)&elf->mem[elf->data.elf32.sym->sh_offset];
            }
        }

        elf->data.elf32.dyn_segment_entry = NULL;
        elf->data.elf32.dyn_segment_count = 0;
        for (int i = 0; i < elf->data.elf32.ehdr->e_phnum; i++) {
            if (elf->data.elf32.phdr[i].p_type == PT_DYNAMIC) {
                elf->data.elf32.dyn_segment_entry = (Elf32_Dyn *)&elf->mem[elf->data.elf32.phdr[i].p_offset];
                elf->data.elf32.dyn_segment_count = elf->data.elf32.phdr[i].p_filesz / sizeof(Elf32_Dyn);
            }
        }
    }

    /* 64bit */
    if (elf->class == ELFCLASS64) {
        elf->data.elf64.ehdr = (Elf64_Ehdr *)elf->mem;
        elf->data.elf64.shdr = (Elf64_Shdr *)&elf->mem[elf->data.elf64.ehdr->e_shoff];
        elf->data.elf64.phdr = (Elf64_Phdr *)&elf->mem[elf->data.elf64.ehdr->e_phoff];
        elf->data.elf64.shstrtab = (Elf64_Shdr *)&elf->data.elf64.shdr[elf->data.elf64.ehdr->e_shstrndx];
        elf->data.elf64.dynstrtab = NULL;
        elf->data.elf64.strtab = NULL;
        elf->data.elf64.dynsym = NULL;
        elf->data.elf64.dynsym_entry = NULL;
        for (int i = 0; i < elf->data.elf64.ehdr->e_shnum; i++) {
            char *section_name = elf->mem + elf->data.elf64.shstrtab->sh_offset + elf->data.elf64.shdr[i].sh_name;
            if (!strcmp(section_name, ".dynstr")) {
                elf->data.elf64.dynstrtab = (Elf64_Shdr *)&elf->data.elf64.shdr[i];
            }
            if (!strcmp(section_name, ".strtab")) {
                elf->data.elf64.strtab = (Elf64_Shdr *)&elf->data.elf64.shdr[i];
            }
            if (!strcmp(section_name, ".dynsym")) {
                elf->data.elf64.dynsym = (Elf64_Shdr *)&elf->data.elf64.shdr[i];
                elf->data.elf64.dynsym_entry = (Elf64_Sym *)&elf->mem[elf->data.elf64.dynsym->sh_offset];
            }
            if (!strcmp(section_name, ".symtab")) {
                elf->data.elf64.sym = (Elf64_Shdr *)&elf->data.elf64.shdr[i];
                elf->data.elf64.sym_entry = (Elf64_Sym *)&elf->mem[elf->data.elf64.sym->sh_offset];
            }
        }

        elf->data.elf64.dyn_segment_entry = NULL;
        elf->data.elf64.dyn_segment_count = 0;
        for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
            if (elf->data.elf64.phdr[i].p_type == PT_DYNAMIC) {
                elf->data.elf64.dyn_segment_entry = (Elf64_Dyn *)&elf->mem[elf->data.elf64.phdr[i].p_offset];
                elf->data.elf64.dyn_segment_count = elf->data.elf64.phdr[i].p_filesz / sizeof(Elf64_Dyn);
            }
        }
    }
}

// 请注意，调用该函数后，如果引用了elf结构体中的变量，则需要刷新这些变量!
// Please note that after calling this function, if variables in the elf struct are referenced, 
// these variables need to be refreshed!
/**
 * @brief 扩充一个段，默认只扩充最后一个类型为PT_LOAD的段
 * Expand a segment, default to only expanding the last segment of type PT_LOAD
 * @param elf Elf custom structure
 * @return start offset
 */
int expand_segment_t(Elf *elf, size_t size) {
    int index = 0;
    int ret_offset = 0;
    if (elf->class == ELFCLASS32) {
    for (int i = 0; i < elf->data.elf32.ehdr->e_phnum; i++) {
        if (elf->data.elf32.phdr[i].p_type == PT_LOAD) {
                index = i;
            }
        }
        // expand last PT_LOAD segment
        ret_offset = elf->data.elf32.phdr[index].p_offset + elf->data.elf32.phdr[index].p_filesz;
        elf->data.elf32.phdr[index].p_filesz += size;
        elf->data.elf32.phdr[index].p_memsz += size;

        // expand file
        size_t new_size = elf->size + size;
        ftruncate(elf->fd, new_size);
        void* new_map = mremap(elf->mem, elf->size, new_size, MREMAP_MAYMOVE);
        if (new_map == MAP_FAILED) {
            perror("mremap");
            return FALSE;
        } else {
            // reinit custom elf structure
            elf->mem = new_map;
            elf->size = new_size;
            reinit(elf);
        }
        
        // mov section header table
        if (elf->data.elf32.ehdr->e_shoff > elf->data.elf32.phdr[index].p_offset) {
            void *src = (void *)elf->mem + elf->data.elf32.ehdr->e_shoff;
            void *dst = (void *)elf->mem + elf->data.elf32.ehdr->e_shoff + size;
            size_t src_len = elf->data.elf32.ehdr->e_shnum * elf->data.elf32.ehdr->e_shentsize;
            if (copy_data(src, dst, src_len) == TRUE) {
                elf->data.elf32.ehdr->e_shoff += size;
                // reinit custom elf structure after move!
                reinit(elf);
            } else {
                printf("error: mov section header\n");
                return FALSE;
            }
        }

        /* 按节偏移降序排序 */
        /* Sort by section offset in descending order */
        SectionManager *manager = section_manager_create();
        if (!manager) {
            printf("Failed to create section manager\n");
            return FALSE;
        }

        for (int i = 0; i < elf->data.elf32.ehdr->e_shnum; i++) {
            if (elf->data.elf32.shdr[i].sh_addr == 0 && elf->data.elf32.shdr[i].sh_offset != 0 && elf->data.elf32.shdr[i].sh_offset >= ret_offset) {
                section_manager_add_32bit(manager, &elf->data.elf32.shdr[i], i);
            }
        }

        section_manager_sort_by_offset_desc(manager);

        /* 我们只移动节, 不移动段, 注意顺序，从大到小 */
        /* we only move sections, not segments. */
        SectionNode *current = manager->head;
        int link_index = 0;
        while (current) {
            void *src = (void *)elf->mem + current->shdr32->sh_offset;
            void *dst = (void *)elf->mem + current->shdr32->sh_offset + size;
            if (copy_data(src, dst, current->shdr32->sh_size) == TRUE) {
                current->shdr32->sh_offset += size;
            } else {
                printf("error: mov section\n");
                return FALSE;
            }  
            current = current->next;
            link_index++;
        }
        section_manager_destroy(manager);
        memset(elf->mem + ret_offset, 0, size);
    } else if (elf->class == ELFCLASS64) {
        for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
            if (elf->data.elf64.phdr[i].p_type == PT_LOAD) {
                index = i;
            }
        }
        // expand last PT_LOAD segment
        ret_offset = elf->data.elf64.phdr[index].p_offset + elf->data.elf64.phdr[index].p_filesz;
        elf->data.elf64.phdr[index].p_filesz += size;
        elf->data.elf64.phdr[index].p_memsz += size;

        // expand file
        size_t new_size = elf->size + size;
        ftruncate(elf->fd, new_size);
        void* new_map = mremap(elf->mem, elf->size, new_size, MREMAP_MAYMOVE);
        if (new_map == MAP_FAILED) {
            perror("mremap");
            return FALSE;
        } else {
            // reinit custom elf structure
            elf->mem = new_map;
            elf->size = new_size;
            reinit(elf);
        }
        
        // mov section header table
        if (elf->data.elf64.ehdr->e_shoff > elf->data.elf64.phdr[index].p_offset) {
            void *src = (void *)elf->mem + elf->data.elf64.ehdr->e_shoff;
            void *dst = (void *)elf->mem + elf->data.elf64.ehdr->e_shoff + size;
            size_t src_len = elf->data.elf64.ehdr->e_shnum * elf->data.elf64.ehdr->e_shentsize;
            if (copy_data(src, dst, src_len) == TRUE) {
                elf->data.elf64.ehdr->e_shoff += size;
                // reinit custom elf structure after move!
                reinit(elf);
            } else {
                printf("error: mov section header\n");
                return FALSE;
            }
        }

        /* 按节偏移降序排序 */
        /* Sort by section offset in descending order */
        SectionManager *manager = section_manager_create();
        if (!manager) {
            printf("Failed to create section manager\n");
            return FALSE;
        }

        for (int i = 0; i < elf->data.elf64.ehdr->e_shnum; i++) {
            if (elf->data.elf64.shdr[i].sh_addr == 0 && elf->data.elf64.shdr[i].sh_offset != 0 && elf->data.elf64.shdr[i].sh_offset >= ret_offset) {
                section_manager_add_64bit(manager, &elf->data.elf64.shdr[i], i);
            }
        }

        section_manager_sort_by_offset_desc(manager);

        /* 我们只移动节, 不移动段, 注意顺序，从大到小 */
        /* we only move sections, not segments. */
        SectionNode *current = manager->head;
        int link_index = 0;
        while (current) {
            void *src = (void *)elf->mem + current->shdr64->sh_offset;
            void *dst = (void *)elf->mem + current->shdr64->sh_offset + size;
            if (copy_data(src, dst, current->shdr64->sh_size) == TRUE) {
                current->shdr64->sh_offset += size;
            } else {
                printf("error: mov section\n");
                return FALSE;
            }  
            current = current->next;
            link_index++;
        }
        section_manager_destroy(manager);
        memset(elf->mem + ret_offset, 0, size);
    }
    
    reinit(elf);
    return ret_offset;
}

/**
 * @brief 设置新的节名
 * Set a new section name
 * @param elf Elf custom structure
 * @param src_name original section name
 * @param dst_name new section name
 * @return error code
 */
int set_section_name_t(Elf *elf, char *src_name, char *dst_name) {
    int index = get_section_index_by_name(elf, src_name);
    if (index == FALSE) {
        printf("%s section not found!\n", src_name);
        return FALSE;
    }
    if (elf->class == ELFCLASS32) {
        if (strlen(dst_name) <= strlen(src_name)) {
            char *section_name = elf->mem + elf->data.elf32.shstrtab->sh_offset + elf->data.elf32.shdr[index].sh_name;
            memset(section_name, 0, strlen(section_name));
            strcpy(section_name, dst_name);
            return TRUE;
        } else {
            size_t src_len = elf->data.elf32.shstrtab->sh_size;
            size_t dst_len = src_len + strlen(dst_name) + 1;
            // string end: 00
            int expand_start = expand_segment_t(elf, dst_len);
            if (expand_start == FALSE) {
                return FALSE;
            }
            void *src = (void *)elf->mem + elf->data.elf32.shstrtab->sh_offset;
            void *dst = (void *)elf->mem + expand_start;

            if (copy_data(src, dst, src_len) == TRUE) {
                // new section shstrtab
                elf->data.elf32.shstrtab->sh_offset = expand_start;
                elf->data.elf32.shstrtab->sh_size = dst_len;
                // string end: 00
                memset(dst + src_len, 0, strlen(dst_name) + 1);
                strcpy(dst + src_len, dst_name);
                // new section name offset
                elf->data.elf32.shdr[index].sh_name = src_len;
                return TRUE;
            } else {
                printf("error: mov section\n");
                return FALSE;
            }
        }
    } else if (elf->class == ELFCLASS64) {
        if (strlen(dst_name) <= strlen(src_name)) {
            char *section_name = elf->mem + elf->data.elf64.shstrtab->sh_offset + elf->data.elf64.shdr[index].sh_name;
            memset(section_name, 0, strlen(section_name));
            strcpy(section_name, dst_name);
            return TRUE;
        } else {
            size_t src_len = elf->data.elf64.shstrtab->sh_size;
            size_t dst_len = src_len + strlen(dst_name) + 1;
            // string end: 00
            int expand_start = expand_segment_t(elf, dst_len);
            if (expand_start == FALSE) {
                return FALSE;
            }
            void *src = (void *)elf->mem + elf->data.elf64.shstrtab->sh_offset;
            void *dst = (void *)elf->mem + expand_start;

            if (copy_data(src, dst, src_len) == TRUE) {
                // new section shstrtab
                elf->data.elf64.shstrtab->sh_offset = expand_start;
                elf->data.elf64.shstrtab->sh_size = dst_len;
                // string end: 00
                memset(dst + src_len, 0, strlen(dst_name) + 1);
                strcpy(dst + src_len, dst_name);
                // new section name offset
                elf->data.elf64.shdr[index].sh_name = src_len;
                return TRUE;
            } else {
                printf("error: mov section\n");
                return FALSE;
            }
        }
    }
}

/**
 * @brief 设置符号表的名字
 * Set a new dynamic symbol name
 * @param elf Elf custom structure
 * @param src_name original symbole name
 * @param dst_name new symbole name
 * @return error code
 */
int set_dynsym_name_t(Elf *elf, char *src_name, char *dst_name) {
    int index = get_dynsym_index_by_name(elf, src_name);
    if (index == FALSE) {
        printf("%s section not found!\n", src_name);
        return FALSE;
    }
    if (elf->class == ELFCLASS32) {
        size_t src_len = elf->data.elf32.dynstrtab->sh_size;
        size_t dst_len = src_len + strlen(dst_name) + 1;
        // string end: 00
        int expand_start = expand_segment_t(elf, dst_len);
        if (expand_start == FALSE) {
            return FALSE;
        }
        void *src = (void *)elf->mem + elf->data.elf32.dynstrtab->sh_offset;
        void *dst = (void *)elf->mem + expand_start;

        if (copy_data(src, dst, src_len) == TRUE) {
            // new section dynstr table
            elf->data.elf32.dynstrtab->sh_offset = expand_start;
            elf->data.elf32.dynstrtab->sh_size = dst_len;
            // map to segment
            int strtab_i = get_dynseg_index_by_type(elf, DT_STRTAB);
            int strsz_i = get_dynseg_index_by_type(elf, DT_STRSZ);
            elf->data.elf32.dyn_segment_entry[strtab_i].d_un.d_val = expand_start;
            elf->data.elf32.dyn_segment_entry[strsz_i].d_un.d_val = dst_len;
            // string end: 00
            memset(dst + src_len, 0, strlen(dst_name) + 1);
            strcpy(dst + src_len, dst_name);
            // new section name offset
            elf->data.elf32.dynsym_entry[index].st_name = src_len;
            return TRUE;
        } else {
            printf("error: mov section\n");
            return FALSE;
        }
    } else if (elf->class == ELFCLASS64) {
        if (strlen(dst_name) <= strlen(src_name)) {
            char *name = elf->mem + elf->data.elf64.dynstrtab->sh_offset + elf->data.elf64.dynsym_entry[index].st_name;
            memset(name, 0, strlen(name));
            strcpy(name, dst_name);
            return TRUE;
        } else {
            size_t src_len = elf->data.elf64.dynstrtab->sh_size;
            size_t dst_len = src_len + strlen(dst_name) + 1;
            // string end: 00
            int expand_start = expand_segment_t(elf, dst_len);
            if (expand_start == FALSE) {
                return FALSE;
            }
            void *src = (void *)elf->mem + elf->data.elf64.dynstrtab->sh_offset;
            void *dst = (void *)elf->mem + expand_start;

            if (copy_data(src, dst, src_len) == TRUE) {
                // new section dynstr table
                elf->data.elf64.dynstrtab->sh_offset = expand_start;
                elf->data.elf64.dynstrtab->sh_size = dst_len;
                // map to segment
                int strtab_i = get_dynseg_index_by_type(elf, DT_STRTAB);
                int strsz_i = get_dynseg_index_by_type(elf, DT_STRSZ);
                elf->data.elf64.dyn_segment_entry[strtab_i].d_un.d_val = expand_start;
                elf->data.elf64.dyn_segment_entry[strsz_i].d_un.d_val = dst_len;
                // string end: 00
                memset(dst + src_len, 0, strlen(dst_name) + 1);
                strcpy(dst + src_len, dst_name);
                // new section name offset
                elf->data.elf64.dynsym_entry[index].st_name = src_len;
                return TRUE;
            } else {
                printf("error: mov section\n");
                return FALSE;
            }
        }
    }
}

/**
 * @brief 设置符号表的名字
 * Set a new symbol name
 * @param elf Elf custom structure
 * @param src_name original symbole name
 * @param dst_name new symbole name
 * @return error code
 */
int set_sym_name_t(Elf *elf, char *src_name, char *dst_name) {
    int index = get_sym_index_by_name(elf, src_name);
    if (index == FALSE) {
        printf("%s section not found!\n", src_name);
        return FALSE;
    }
    if (elf->class == ELFCLASS32) {
        size_t src_len = elf->data.elf32.dynstrtab->sh_size;
        size_t dst_len = src_len + strlen(dst_name) + 1;
        // string end: 00
        int expand_start = expand_segment_t(elf, dst_len);
        if (expand_start == FALSE) {
            return FALSE;
        }
        void *src = (void *)elf->mem + elf->data.elf32.dynstrtab->sh_offset;
        void *dst = (void *)elf->mem + expand_start;

        if (copy_data(src, dst, src_len) == TRUE) {
            // new section dynstr table
            elf->data.elf32.dynstrtab->sh_offset = expand_start;
            elf->data.elf32.dynstrtab->sh_size = dst_len;
            // map to segment
            int strtab_i = get_dynseg_index_by_type(elf, DT_STRTAB);
            int strsz_i = get_dynseg_index_by_type(elf, DT_STRSZ);
            elf->data.elf32.dyn_segment_entry[strtab_i].d_un.d_val = expand_start;
            elf->data.elf32.dyn_segment_entry[strsz_i].d_un.d_val = dst_len;
            // string end: 00
            memset(dst + src_len, 0, strlen(dst_name) + 1);
            strcpy(dst + src_len, dst_name);
            // new section name offset
            elf->data.elf32.dynsym_entry[index].st_name = src_len;
            return TRUE;
        } else {
            printf("error: mov section\n");
            return FALSE;
        }
    } else if (elf->class == ELFCLASS64) {
        if (strlen(dst_name) <= strlen(src_name)) {
            char *name = elf->mem + elf->data.elf64.strtab->sh_offset + elf->data.elf64.sym_entry[index].st_name;
            memset(name, 0, strlen(name));
            strcpy(name, dst_name);
            return TRUE;
        } else {
            size_t src_len = elf->data.elf64.strtab->sh_size;
            size_t dst_len = src_len + strlen(dst_name) + 1;
            // string end: 00
            int expand_start = expand_segment_t(elf, dst_len);
            if (expand_start == FALSE) {
                return FALSE;
            }
            void *src = (void *)elf->mem + elf->data.elf64.strtab->sh_offset;
            void *dst = (void *)elf->mem + expand_start;

            if (copy_data(src, dst, src_len) == TRUE) {
                // new section dynstr table
                elf->data.elf64.strtab->sh_offset = expand_start;
                elf->data.elf64.strtab->sh_size = dst_len;
                // string end: 00
                memset(dst + src_len, 0, strlen(dst_name) + 1);
                strcpy(dst + src_len, dst_name);
                // new section name offset
                elf->data.elf64.sym_entry[index].st_name = src_len;
                return TRUE;
            } else {
                printf("error: mov section\n");
                return FALSE;
            }
        }
    }
}