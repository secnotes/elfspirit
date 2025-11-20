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
#include "manager.h"
#include "util.h"

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

    elf->type = get_file_type(elf);

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

/****************************************/
/* dynamic segmentation */
/**
 * @brief 根据dynamic段的tag,获取段的下标
 * Get the dynamic segment index based on its tag.
 * @param elf Elf custom structure
 * @param tag Elf dynamic segment tag
 * @return index
 */
int get_dynseg_index_by_tag(Elf *elf, int tag) {
    if (elf->class == ELFCLASS32) {
        for (int i = 0; i < elf->data.elf32.dyn_segment_count; i++) {
            if (elf->data.elf32.dyn_segment_entry[i].d_tag == tag) {
                return i;
            }
        }
    } else if (elf->class == ELFCLASS64) {
        for (int i = 0; i < elf->data.elf64.dyn_segment_count; i++) {
            if (elf->data.elf64.dyn_segment_entry[i].d_tag == tag) {
                return i;
            }
        }
    }
    else {
        return FALSE;
    }
}

/**
 * @brief 根据dynamic段的tag，得到值
 * get dynamic segment value by tag
 * @param elfname 
 * @param tag dynamic segment tag
 * @return value
 */
int get_dynseg_value_by_tag(Elf *elf, int tag) {
    int index = get_dynseg_index_by_tag(elf, tag);
    if (index != FALSE) {
        if (elf->class == ELFCLASS32)
            return elf->data.elf32.dyn_segment_entry[index].d_un.d_val;
        if (elf->class == ELFCLASS64)
            return elf->data.elf64.dyn_segment_entry[index].d_un.d_val;
    } else
        return FALSE;
}

/**
 * @brief 根据dynamic段的tag，设置tag
 * set dynamic segment tag by tag
 * @param elfname 
 * @param tag dynamic segment tag
 * @param value dynamic segment value
 * @return value
 */
int set_dynseg_tag_by_tag(Elf *elf, int tag, uint64_t new_tag) {
    int index = get_dynseg_index_by_tag(elf, tag);
    if (index != FALSE) {
        if (elf->class == ELFCLASS32)
            elf->data.elf32.dyn_segment_entry[index].d_tag = new_tag;
        if (elf->class == ELFCLASS64)
            elf->data.elf64.dyn_segment_entry[index].d_tag = new_tag;
        else
            return FALSE;
    } else
        return FALSE;
}

/**
 * @brief 根据dynamic段的tag，设置值
 * set dynamic segment value by tag
 * @param elfname 
 * @param tag dynamic segment tag
 * @param value dynamic segment value
 * @return value
 */
int set_dynseg_value_by_tag(Elf *elf, int tag, uint64_t value) {
    int index = get_dynseg_index_by_tag(elf, tag);
    if (index != FALSE) {
        if (elf->class == ELFCLASS32)
            elf->data.elf32.dyn_segment_entry[index].d_un.d_val = value;
        if (elf->class == ELFCLASS64)
            elf->data.elf64.dyn_segment_entry[index].d_un.d_val = value;
        else
            return FALSE;
    } else
        return FALSE;
}
/* dynamic segmentation */
/****************************************/

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
            int strtab_i = get_dynseg_index_by_tag(elf, DT_STRTAB);
            int strsz_i = get_dynseg_index_by_tag(elf, DT_STRSZ);
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
                int strtab_i = get_dynseg_index_by_tag(elf, DT_STRTAB);
                int strsz_i = get_dynseg_index_by_tag(elf, DT_STRSZ);
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
            int strtab_i = get_dynseg_index_by_tag(elf, DT_STRTAB);
            int strsz_i = get_dynseg_index_by_tag(elf, DT_STRSZ);
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

static int mov_last_sections(Elf *elf, uint64_t expand_offset, size_t size) {
    // mov section header table
    void *src = (void *)elf->mem + elf->data.elf64.ehdr->e_shoff;
    void *dst = (void *)elf->mem + elf->data.elf64.ehdr->e_shoff + size;
    size_t src_len = elf->data.elf64.ehdr->e_shnum * elf->data.elf64.ehdr->e_shentsize;
    if (copy_data(src, dst, src_len) == TRUE) {
        elf->data.elf64.ehdr->e_shoff += size;
        reinit(elf);
    } else {
        printf("error: mov section header\n");
        return FALSE;
    }

    /* 按节偏移降序排序 */
    /* Sort by section offset in descending order */
    SectionManager *manager = section_manager_create();
    if (!manager) {
        printf("Failed to create section manager\n");
        return FALSE;
    }

    for (int i = 0; i < elf->data.elf64.ehdr->e_shnum; i++) {
        if (elf->data.elf64.shdr[i].sh_addr == 0 && elf->data.elf64.shdr[i].sh_offset != 0 && elf->data.elf64.shdr[i].sh_offset >= expand_offset) {
            section_manager_add_64bit(manager, &elf->data.elf64.shdr[i], i);
        }
    }

    section_manager_sort_by_offset_desc(manager);

    /* 我们只移动节, 不移动段, 注意顺序，从大到小 */
    /* we only move sections, not segments. */
    SectionNode *cur_sec = manager->head;
    int link_index = 0;
    while (cur_sec) {
        void *src = (void *)elf->mem + cur_sec->shdr64->sh_offset;
        void *dst = (void *)elf->mem + cur_sec->shdr64->sh_offset + size;
        if (copy_data(src, dst, cur_sec->shdr64->sh_size) == TRUE) {
            cur_sec->shdr64->sh_offset += size;
        } else {
            printf("error: mov section\n");
            return FALSE;
        }  
        cur_sec = cur_sec->next;
        link_index++;
    }
    section_manager_destroy(manager);
}

static void mapp_load(Elf *elf, MappingList *mapping_list) {
    for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
        if (elf->data.elf64.phdr[i].p_type == PT_LOAD) {
            uint64_t start = elf->data.elf64.phdr[i].p_offset;
            uint64_t end = elf->data.elf64.phdr[i].p_offset + elf->data.elf64.phdr[i].p_filesz;
            IndexMapping* mapping = create_mapping(i);
            for (int j = 0; j < elf->data.elf64.ehdr->e_phnum; j++) {  
                if (elf->data.elf64.phdr[j].p_type != PT_GNU_STACK && j != i && elf->data.elf64.phdr[j].p_offset >= start && elf->data.elf64.phdr[j].p_offset < end) {
                    add_subseg(mapping, j);
                }
            }

            for (int j = 0; j < elf->data.elf64.ehdr->e_shnum; j++) {
                if (elf->data.elf64.shdr[j].sh_type != SHT_NULL && elf->data.elf64.shdr[j].sh_offset >= start && elf->data.elf64.shdr[j].sh_offset < end) {
                    add_subsec(mapping, j);
                } 
                // .bss
                else if (elf->data.elf64.shdr[j].sh_addr >= elf->data.elf64.phdr[i].p_vaddr && elf->data.elf64.shdr[j].sh_addr < elf->data.elf64.phdr[i].p_vaddr + elf->data.elf64.phdr[i].p_memsz) {
                    add_subsec(mapping, j);
                }
            }
            
            add_mapping_to_list(mapping_list, mapping);
        }
    }
}

// 请注意，调用该函数后，如果引用了elf结构体中的变量，则需要刷新这些变量!
// Please note that after calling this function, if variables in the elf struct are referenced, 
// these variables need to be refreshed!
/**
 * @brief 扩充一个段
 * Expand a segment by its index
 * @param elf Elf custom structure
 * @param index segment index
 * @param size expand size
 * @param added_offset return start offset
 * @param added_vaddr return start virtual address
 * @return error code
 */
int expand_segment_load(Elf *elf, uint64_t index, size_t size, uint64_t *added_offset, uint64_t *added_vaddr) {
    MappingList *mapping_list = create_mapping_list();
    mapp_load(elf, mapping_list);
    IndexMapping* found = find_mapping(mapping_list, index);
    if (found == NULL) {
        free_mapping_list(mapping_list);
        return FALSE;
    }

    *added_offset = elf->data.elf64.phdr[index].p_offset + elf->data.elf64.phdr[index].p_filesz;
    *added_vaddr = elf->data.elf64.phdr[index].p_vaddr + elf->data.elf64.phdr[index].p_memsz;
    
    size_t free_space = 0;
    // last load segment
    if (elf->data.elf64.phdr[index+1].p_type == PT_LOAD)
        free_space = elf->data.elf64.phdr[index+1].p_offset - elf->data.elf64.phdr[index].p_offset - elf->data.elf64.phdr[index].p_filesz;
    // printf("free_space = %x\n", free_space);
    if (size <= free_space) {
        elf->data.elf64.phdr[index].p_filesz += size;
        elf->data.elf64.phdr[index].p_memsz += size;
        
        // the end sub section
        ListNode* current = found->sec_head;
        while (current != NULL) {
            if (current->next == NULL) {
                elf->data.elf64.shdr[current->index].sh_size += size;
            } 
            current = current->next;
        }
    } else {
        size_t added_size = align_page(size);
        elf->data.elf64.phdr[index].p_filesz += size;
        elf->data.elf64.phdr[index].p_memsz += size;

        // the end sub section
        ListNode* current = found->sec_head;
        while (current != NULL) {
            if (current->next == NULL) {
                elf->data.elf64.shdr[current->index].sh_size += size;
            } 
            current = current->next;
        }

        /* ----------------------------0.expand file---------------------------- */
        size_t new_size = elf->size + added_size;
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

        /* ----------------------------1.mov section---------------------------- */
        mov_last_sections(elf, *added_offset, added_size);
        
        // 2. mov segment after target segment
        /* ----------------------------2.mov segment---------------------------- */
        for (int i = elf->data.elf64.ehdr->e_phnum - 1; i > index; i--) {
            if (elf->data.elf64.phdr[i].p_type == PT_LOAD) {
                void *src = (void *)elf->mem + elf->data.elf64.phdr[i].p_offset;
                void *dst = src + added_size;
                if (copy_data(src, dst, elf->data.elf64.phdr[i].p_filesz) == TRUE) {
                    elf->data.elf64.phdr[i].p_offset += added_size;
                    elf->data.elf64.phdr[i].p_vaddr += added_size;
                    elf->data.elf64.phdr[i].p_paddr += added_size;
                } else {
                    printf("error: mov segment\n");
                    return FALSE;
                }

                // set sub segment offset and address
                IndexMapping* found_seg = find_mapping(mapping_list, i);
                ListNode* cur_seg = found_seg->seg_head;
                while (cur_seg != NULL) {
                    elf->data.elf64.phdr[cur_seg->index].p_offset += added_size;
                    elf->data.elf64.phdr[cur_seg->index].p_vaddr += added_size;
                    elf->data.elf64.phdr[cur_seg->index].p_paddr += added_size; 
                    cur_seg = cur_seg->next;
                }

                // set sub section offset and address
                IndexMapping* found_sec = find_mapping(mapping_list, i);
                ListNode* cur_sec = found_sec->sec_head;
                while (cur_sec != NULL) {
                    elf->data.elf64.shdr[cur_sec->index].sh_offset += added_size;
                    elf->data.elf64.shdr[cur_sec->index].sh_addr += added_size;
                    cur_sec = cur_sec->next;
                }

                // set elf file entry
                if (elf->data.elf64.phdr[i].p_flags & PF_X) {
                    elf->data.elf64.ehdr->e_entry += added_size;
                }
            }
        }

        reinit(elf);
        // 3. change dynamic segment entry value
        for (int i = 0; i < elf->data.elf64.dyn_segment_count; i++) {
            uint64_t value = elf->data.elf64.dyn_segment_entry[i].d_un.d_ptr;
            uint64_t tag = elf->data.elf64.dyn_segment_entry[i].d_tag;
            if (value >= *added_vaddr) {
                switch (tag)
                {
                    case DT_INIT:
                    case DT_FINI:
                    case DT_INIT_ARRAY:
                    case DT_FINI_ARRAY:
                    case DT_GNU_HASH:
                    case DT_STRTAB:
                    case DT_SYMTAB:
                    case DT_PLTGOT:
                    case DT_JMPREL:
                    case DT_RELA:
                    case DT_VERNEED:
                    case DT_VERSYM:
                        elf->data.elf64.dyn_segment_entry[i].d_un.d_ptr += added_size;
                        break;
                    
                    default:
                        break;
                }
            }
        }
    }

    free_mapping_list(mapping_list);
    return TRUE;
}

/**
 * @brief 增加一个段
 * Add a segment
 * @param elf Elf custom structure
 * @param size segment size
 * @param added_index segment index
 * @return error code
 */
int add_segment_common(Elf *elf, size_t size, uint64_t mov_pht, uint64_t *added_index) {
    int is_break = 0;
    uint64_t last_load = 0;
    size_t added_size = align_page(size);
    uint64_t start_offset = 0;
    uint64_t start_addr = 0;
    uint64_t actual_offset = 0;
    uint64_t actual_addr = 0;
    uint64_t actual_size = 0;
    uint64_t actual_diff = 0;
    
    size_t pht_dst_size = 0;
    size_t pht_src_size = 0;
    uint64_t pht_offset = 0;
    uint64_t pht_addr = 0;

    if (elf->class == ELFCLASS32) {
       ;
    } else if (elf->class == ELFCLASS64) {
        for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
            switch (elf->data.elf64.phdr[i].p_type)
            {
                case PT_NOTE:
                case PT_NULL:
                    *added_index = i;
                    is_break = 1;
                    break;

                case PT_LOAD:
                    last_load = i;
                
                default:
                    break;
            }
            if (is_break) break;
        }
        
        if (!is_break) {
            return ERR_SEG;
        }

        start_offset = elf->data.elf64.phdr[last_load].p_offset + elf->data.elf64.phdr[last_load].p_filesz;
        start_addr = elf->data.elf64.phdr[last_load].p_vaddr + elf->data.elf64.phdr[last_load].p_memsz;
        /**
         * 对于ELF的PIE可执行程序，在最后一个PT_LOAD段（rw权限）后，添加一个PT_LOAD（r权限），ELF可执行程序能够正常运行。
         * 但是，在ELF动态链接库中，进行相同的操作，即在最后一个PT_LOAD段后，添加一个段（r权限），这个动态链接库并不能被正确加载。当我把添加的段的权限改为rwx，这个动态链接库又可以正常被其他可执行程序引用了
         * 添加的所有段偏移地址都遵循页对齐
         */
        if (elf->type == ET_EXEC) {
            actual_addr = start_addr;
            actual_offset = align_offset(start_offset, actual_addr);
        } else if (elf->type == ET_DYN) {
            actual_addr = align_page(start_addr);
            actual_offset = align_offset(start_offset, actual_addr);
        } else {
            return ERR_TYPE;
        }

        actual_size = align_page(size);
        if (mov_pht) {
            pht_dst_size = (elf->data.elf64.ehdr->e_phnum + 1) * elf->data.elf64.ehdr->e_phentsize;
            pht_src_size = elf->data.elf64.ehdr->e_phnum * elf->data.elf64.ehdr->e_phentsize;
            pht_offset = actual_offset + align_page(size);
            pht_addr = actual_addr + align_page(size);
            actual_size = align_page(size) + align_page(pht_dst_size);
            *added_index = elf->data.elf64.ehdr->e_phnum;
        }
        
        actual_diff = actual_offset - start_offset + actual_size;

        /* ----------------------------0.expand file---------------------------- */
        size_t new_size = elf->size + actual_diff;
        ftruncate(elf->fd, new_size);
        void* new_map = mremap(elf->mem, elf->size, new_size, MREMAP_MAYMOVE);
        if (new_map == MAP_FAILED) {
            perror("mremap");
            return ERR_MMAP;
        } else {
            // reinit custom elf structure
            elf->mem = new_map;
            elf->size = new_size;
            reinit(elf);
        }

        /* ----------------------------1.mov section---------------------------- */
        mov_last_sections(elf, start_offset, actual_diff);
        reinit(elf);

        /* ----------------------------2.change dynamic segment entry value---------------------------- */
        for (int i = 0; i < elf->data.elf64.dyn_segment_count; i++) {
            uint64_t value = elf->data.elf64.dyn_segment_entry[i].d_un.d_ptr;
            uint64_t tag = elf->data.elf64.dyn_segment_entry[i].d_tag;
            if (value >= start_addr) {
                switch (tag)
                {
                    case DT_INIT:
                    case DT_FINI:
                    case DT_INIT_ARRAY:
                    case DT_FINI_ARRAY:
                    case DT_GNU_HASH:
                    case DT_STRTAB:
                    case DT_SYMTAB:
                    case DT_PLTGOT:
                    case DT_JMPREL:
                    case DT_RELA:
                    case DT_VERNEED:
                    case DT_VERSYM:
                        elf->data.elf64.dyn_segment_entry[i].d_un.d_ptr += actual_size;
                        break;
                    
                    default:
                        break;
                }
            }
        }

        /* mov program header table */
        if (mov_pht) {
            void *src = elf->mem + elf->data.elf64.ehdr->e_phoff;
            void *dst = elf->mem + pht_offset;
            if (copy_data(src, dst, pht_src_size) == TRUE) {
                elf->data.elf64.ehdr->e_phnum++;
                elf->data.elf64.ehdr->e_phoff = pht_offset;
                reinit(elf);
                for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
                    if (elf->data.elf64.phdr[i].p_type = PT_PHDR) {
                        printf("i=%d , offset=%x, dst_offset=%x\n", i, elf->data.elf64.phdr[i].p_offset, pht_offset);
                        elf->data.elf64.phdr[i].p_offset = pht_offset;
                        elf->data.elf64.phdr[i].p_vaddr = pht_addr;
                        elf->data.elf64.phdr[i].p_paddr = pht_addr;
                        elf->data.elf64.phdr[i].p_filesz = pht_dst_size;
                        elf->data.elf64.phdr[i].p_memsz = pht_dst_size;
                        break;
                    }
                }

            } else {
                return ERR_COPY;
            }
        }

        elf->data.elf64.phdr[*added_index].p_offset = actual_offset;
        elf->data.elf64.phdr[*added_index].p_vaddr = actual_addr;
        elf->data.elf64.phdr[*added_index].p_paddr = actual_addr;
        elf->data.elf64.phdr[*added_index].p_filesz = actual_size;
        elf->data.elf64.phdr[*added_index].p_memsz = actual_size;
        elf->data.elf64.phdr[*added_index].p_type = PT_LOAD;
        elf->data.elf64.phdr[*added_index].p_align = ONE_PAGE;
        elf->data.elf64.phdr[*added_index].p_flags = PF_R;
    } else {
        return ERR_CLASS;
    }
}

/**
 * @brief 增加一个段，但是不在PHT增加新条目。我们可以通过修改不重要的段条目，比如类型为PT_NOTE、PT_NULL的段，实现这一功能。
 * Add a segment, but do not add a new entry in PHT. 
 * We can achieve this function by modifying unimportant segment entries, such as segments of type PT_NOTE or PT_NULL.
 * @param elf Elf custom structure
 * @param size segment size
 * @param added_index segment index
 * @return error code
 */
int add_segment_easy(Elf *elf, size_t size, uint64_t *added_index) {
    return add_segment_common(elf, size, 0, added_index);
}


/*
**                         
  LOAD ───► ┌──────────┐ 
            │ use free │ 
  PHT  ───► ├──────────┼ 
            │   pht    │ 
            └──────────┘ 
*/
/**
 * @brief 增加一个段，但是不在PHT增加新条目。增加一个段，但是不修改已有的PHT新条目。为了不修改已有的PT_LOAD段的地址，我们只能搬迁PHT
 * Add a segment, but do not modify the existing PHT new entry. 
 * In order not to modify the address of the existing PT_LOAD segment, we can only relocate PHT.
 * @param elf Elf custom structure
 * @param size segment size
 * @param added_index segment index
 * @return error code
 */
int add_segment_difficult(Elf *elf, size_t size, uint64_t *added_index) {
    return add_segment_common(elf, size, 1, added_index);
}

/**
 * @brief 获取ELF文件的类型
 * Retrieve the type of ELF file 
 * @param elf Elf custom structure
 * @return error code
 */
int get_file_type(Elf *elf) {
    if (elf->class == ELFCLASS32) {
        switch (elf->data.elf32.ehdr->e_type)
        {
            case ET_REL:
                return ET_REL;
                break;
            
            case ET_EXEC:
                return ET_EXEC;
                break;

            case ET_DYN:
                if (!elf->data.elf32.ehdr->e_entry)
                    return ET_DYN;
                else
                    return ET_EXEC;
                break;

            case ET_CORE:
                return ET_CORE;
                break;
            
            default:
                return ET_NONE;
                break;
        }
    } else if (elf->class == ELFCLASS64) {
        switch (elf->data.elf64.ehdr->e_type)
        {
            case ET_REL:
                return ET_REL;
                break;
            
            case ET_EXEC:
                return ET_EXEC;
                break;

            case ET_DYN:
                if (!elf->data.elf64.ehdr->e_entry)
                    return ET_DYN;
                else
                    return ET_EXEC;
                break;

            case ET_CORE:
                return ET_CORE;
                break;
            
            default:
                return ET_NONE;
                break;
        }
    } else {
        return ERR_CLASS;
    }
} 