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
#include "stdbool.h"
#include "elfutil.h"
#include "manager.h"
#include "util.h"

/**
 * @brief 打印错误信息
 * print error message
 * @param code error code
 */
void print_error(enum ErrorCode code) {
    if (code >= 0 ) {
        PRINT_INFO("success\n");
        return ;
    }
    switch (code) {
        case ERR_OUT_OF_BOUNDS:
            PRINT_ERROR("error: some variables may overflow\n");
            break;
        case ERR_NOTFOUND:
            PRINT_ERROR("error: unable to find specific object\n");
            break;
        case ERR_DYN_NOTFOUND:
            PRINT_ERROR("error: cannot find dynamic section\n");
            break;
        case ERR_SEC_NOTFOUND:
            PRINT_ERROR("error: cannot find section\n");
            break;
        case ERR_SEG_NOTFOUND:
            PRINT_ERROR("error: cannot find segment\n");
            break;
        case ERR_ELF_TYPE:
            PRINT_ERROR("error: ELF type error\n");
            break;
        case ERR_ELF_CLASS:
            PRINT_ERROR("error: ELF Class error\n");
            break;
        case ERR_ARGS:
            PRINT_ERROR("error: function arrgument error\n");
            break;
        case ERR_FILE_OPEN:
            PRINT_ERROR("error: file open error\n");
            break;
        case ERR_MEM:
            PRINT_ERROR("error: memory mapping or malloc error\n");
            break;
        case ERR_COPY:
            PRINT_ERROR("error: memory copy error\n");
            break;
        case ERR_MOVE:
            PRINT_ERROR("error: memory move error\n");
            break;
        case ERR_EXPAND_SEG:
            PRINT_ERROR("error: expand segment error\n");
            break;
        case ERR_ADD_SEG:
            PRINT_ERROR("error: add segment error\n");
            break;
        case NO_ERR:
        case TRUE:
            PRINT_INFO("success\n");
            break;
        default:
            PRINT_ERROR("error: unknown error\n");
            break;
    }
}

/**
 * @brief 初始化elf文件，将elf文件转化为elf结构体
 * initialize the elf file and convert it into an elf structure
 * @param elf_name elf file name
 * @param elf elf file custom structure
 * @param ro if modify elf
 * @return error code
 */
int init(char *elf_name, Elf *elf, bool ro) {
    int fd = -1;
    struct stat st;
    uint8_t *elf_map = NULL;

    fd = ro?open(elf_name, O_RDONLY): open(elf_name, O_RDWR);
    if (fd < 0) {
        return ERR_FILE_OPEN;
    }

    if (fstat(fd, &st) < 0) {
        close(fd);
        return ERR_FILE_STAT;
    }
    elf_map = ro? mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0):
                mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (elf_map == MAP_FAILED) {
        close(fd);
        return ERR_MEM;
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
        elf->data.elf32.dyn_count = 0;
        elf->data.elf32.sym_count = 0;
        elf->data.elf32.dynsym_count = 0;
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
                elf->data.elf32.dynsym_count = elf->data.elf32.dynsym->sh_size / sizeof(Elf32_Sym);
            }
            if (!strcmp(section_name, ".symtab")) {
                elf->data.elf32.sym = (Elf32_Shdr *)&elf->data.elf32.shdr[i];
                elf->data.elf32.sym_entry = (Elf32_Sym *)&elf->mem[elf->data.elf32.sym->sh_offset];
                elf->data.elf32.sym_count = elf->data.elf32.sym->sh_size / sizeof(Elf32_Sym);
            }
        }

        elf->data.elf32.dyn = NULL;
        elf->data.elf32.dyn_count = 0;
        for (int i = 0; i < elf->data.elf32.ehdr->e_phnum; i++) {
            if (elf->data.elf32.phdr[i].p_type == PT_DYNAMIC) {
                elf->data.elf32.dyn = (Elf32_Dyn *)&elf->mem[elf->data.elf32.phdr[i].p_offset];
                elf->data.elf32.dyn_count = elf->data.elf32.phdr[i].p_filesz / sizeof(Elf32_Dyn);
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
        elf->data.elf64.dyn_count = 0;
        elf->data.elf64.sym_count = 0;
        elf->data.elf64.dynsym_count = 0;
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
                elf->data.elf64.dynsym_count = elf->data.elf64.dynsym->sh_size / sizeof(Elf64_Sym);
            }
            if (!strcmp(section_name, ".symtab")) {
                elf->data.elf64.sym = (Elf64_Shdr *)&elf->data.elf64.shdr[i];
                elf->data.elf64.sym_entry = (Elf64_Sym *)&elf->mem[elf->data.elf64.sym->sh_offset];
                elf->data.elf64.sym_count = elf->data.elf64.sym->sh_size / sizeof(Elf64_Sym);
            }
        }

        elf->data.elf64.dyn = NULL;
        elf->data.elf64.dyn_count = 0;
        for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
            if (elf->data.elf64.phdr[i].p_type == PT_DYNAMIC) {
                elf->data.elf64.dyn = (Elf64_Dyn *)&elf->mem[elf->data.elf64.phdr[i].p_offset];
                elf->data.elf64.dyn_count = elf->data.elf64.phdr[i].p_filesz / sizeof(Elf64_Dyn);
            }
        }
    }

    elf->type = get_file_type(elf);

    return NO_ERR;
}

int finit(Elf *elf) {
    close(elf->fd);
    munmap(elf->mem, elf->size);
    return NO_ERR;
}

/**
 * @brief 根据节的名称，获取节的下标
 * Obtain the index of the section based on its name.
 * @param elf Elf custom structure
 * @param name Elf section name
 * @return section index
 */
int get_section_index_by_name(Elf *elf, char *name) {
    int ret = ERR_SEC_NOTFOUND;
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
    else { 
        return ERR_ELF_CLASS;
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
    if (index < 0) {
        return index;
    }

    if (elf->class == ELFCLASS32) {
        return elf->data.elf32.shdr[index].sh_addr;
    } else if (elf->class == ELFCLASS64) {
        return elf->data.elf64.shdr[index].sh_addr;
    } else {
        return ERR_ELF_CLASS;
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
    if (index < 0) {
        return index;
    }

    if (elf->class == ELFCLASS32) {
        return elf->data.elf32.shdr[index].sh_offset;
    } else if (elf->class == ELFCLASS64) {
        return elf->data.elf64.shdr[index].sh_offset;
    } else {
        return ERR_ELF_CLASS;
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
    if (index < 0) {
        return index;
    }

    if (elf->class == ELFCLASS32) {
        return elf->data.elf32.shdr[index].sh_type;
    } else if (elf->class == ELFCLASS64) {
        return elf->data.elf64.shdr[index].sh_type;
    } else {
        return ERR_ELF_CLASS;
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
    if (index < 0) {
        return index;
    }

    if (elf->class == ELFCLASS32) {
        return elf->data.elf32.shdr[index].sh_size;
    } else if (elf->class == ELFCLASS64) {
        return elf->data.elf64.shdr[index].sh_size;
    } else {
        return ERR_ELF_CLASS;
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
    if (index < 0) {
        return index;
    }

    if (elf->class == ELFCLASS32) {
        return elf->data.elf32.shdr[index].sh_entsize;
    } else if (elf->class == ELFCLASS64) {
        return elf->data.elf64.shdr[index].sh_entsize;
    } else {
        return ERR_ELF_CLASS;
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
    if (index < 0) {
        return index;
    }

    if (elf->class == ELFCLASS32) {
        return elf->data.elf32.shdr[index].sh_addralign;
    } else if (elf->class == ELFCLASS64) {
        return elf->data.elf64.shdr[index].sh_addralign;
    } else {
        return ERR_ELF_CLASS;
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
    if (index < 0) {
        return index;
    }

    if (elf->class == ELFCLASS32) {
        return elf->data.elf32.shdr[index].sh_flags;
    } else if (elf->class == ELFCLASS64) {
        return elf->data.elf64.shdr[index].sh_flags;
    } else {
        return ERR_ELF_CLASS;
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
    if (index < 0) {
        return index;
    }

    if (elf->class == ELFCLASS32) {
        return elf->data.elf32.shdr[index].sh_link;
    } else if (elf->class == ELFCLASS64) {
        return elf->data.elf64.shdr[index].sh_link;
    } else {
        return ERR_ELF_CLASS;
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
    if (index < 0) {
        return index;
    }

    if (elf->class == ELFCLASS32) {
        return elf->data.elf32.shdr[index].sh_info;
    } else if (elf->class == ELFCLASS64) {
        return elf->data.elf64.shdr[index].sh_info;
    } else {
        return ERR_ELF_CLASS;
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
 * @brief 根据段的下标,获取节的名称
 * Get the section name based on its index.
 * @param elf Elf custom structure
 * @param index Elf section index
 * @return section name
 */
char *get_section_name(Elf *elf, int index) {
    if (elf->class == ELFCLASS32) {
        return (char *)&elf->mem[elf->data.elf32.shstrtab->sh_offset + elf->data.elf32.shdr[index].sh_name];
    } else if (elf->class == ELFCLASS64) {
        return (char *)&elf->mem[elf->data.elf64.shstrtab->sh_offset + elf->data.elf64.shdr[index].sh_name];
    }
    else {
        return NULL;
    }
}

/**
 * @brief 根据段的类型，获取段的下标
 * get the segment index based on its type.
 * @param elf Elf custom structure
 * @param type Elf segment type
 * @param index Elf segment type
 * @return error code
 */
int get_segment_index_by_type(Elf *elf, int type, size_t *index) {
    if (elf->class == ELFCLASS32) {
        for (size_t i = 0; i < elf->data.elf32.ehdr->e_phnum; i++) {
            if (elf->data.elf32.phdr[i].p_type == type) {
                *index = i;
                return NO_ERR;
            }
        }
    } else if (elf->class == ELFCLASS64) {
        for (size_t i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
            if (elf->data.elf64.phdr[i].p_type == type) {
                *index = i;
                return NO_ERR;
            }
        }
    } else {
        return ERR_ELF_CLASS;
    }

    return ERR_SEG_NOTFOUND;
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
    } else {
        return ERR_ELF_CLASS;
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
    } else {
        return ERR_ELF_CLASS;
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
    } else {
        return ERR_ELF_CLASS;
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
    } else {
        return ERR_ELF_CLASS;
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
    } else {
        return ERR_ELF_CLASS;
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
    } else {
        return ERR_ELF_CLASS;
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
    } else {
        return ERR_ELF_CLASS;
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
    } else {
        return ERR_ELF_CLASS;
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
        for (int i = 0; i < elf->data.elf32.dyn_count; i++) {
            if (elf->data.elf32.dyn[i].d_tag == tag) {
                return i;
            }
        }
    } else if (elf->class == ELFCLASS64) {
        for (int i = 0; i < elf->data.elf64.dyn_count; i++) {
            if (elf->data.elf64.dyn[i].d_tag == tag) {
                return i;
            }
        }
    } else {
        return ERR_ELF_CLASS;
    }

    return ERR_DYN_NOTFOUND;
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
    if (index >= 0) {
        if (elf->class == ELFCLASS32)
            return elf->data.elf32.dyn[index].d_un.d_val;
        if (elf->class == ELFCLASS64)
            return elf->data.elf64.dyn[index].d_un.d_val;
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
    if (index >= 0) {
        if (elf->class == ELFCLASS32)
            elf->data.elf32.dyn[index].d_tag = new_tag;
        if (elf->class == ELFCLASS64)
            elf->data.elf64.dyn[index].d_tag = new_tag;
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
    if (index < 0) {
        return index;
    }
    if (elf->class == ELFCLASS32)
        elf->data.elf32.dyn[index].d_un.d_val = value;
    else if (elf->class == ELFCLASS64)
        elf->data.elf64.dyn[index].d_un.d_val = value;
    else
        return ERR_ELF_CLASS;
    return NO_ERR;
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
    } else {
        return ERR_ELF_CLASS;
    }

    return NO_ERR;
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
 * @brief 根据节的名字，判断该节是否是一个孤立节，即不属于任何段
 * Determine whether the section is an isolated section based on its name, that is, it does not belong to any segment.
 * @param elf Elf custom structure
 * @param name Elf section name
 * @param result true or false
 * @return error code
 */
int is_isolated_section_by_name(Elf *elf, char *name, bool *result) {
    int index = get_section_index_by_name(elf, name);
    if (index < 0) {
        PRINT_ERROR("err: get_section_index_by_name\n");
        return index;
    }
    bool flag;
    int err = is_isolated_section_by_index(elf, index, &flag);
    if (err != NO_ERR) {
        PRINT_ERROR("err: is_isolated_section_by_index\n");
        return err;
    }

    *result = flag;
    return NO_ERR;
}

/**
 * @brief 根据节的下标，判断该节是否是一个孤立节，即不属于任何段
 * Determine whether the section is an isolated section based on its index, that is, it does not belong to any segment.
 * @param elf Elf custom structure
 * @param index Elf section index
 * @param result true or false
 * @return error code
 */
int is_isolated_section_by_index(Elf *elf, int index, bool *result) {
    if (elf->class == ELFCLASS32) {
        int addr = elf->data.elf32.shdr[index].sh_addr;
        int size = elf->data.elf32.shdr[index].sh_size;
        if (addr == 0) {
            for (int i = 0; i < elf->data.elf32.ehdr->e_phnum; i++) {
                if (addr+size > elf->data.elf32.phdr[i].p_vaddr+elf->data.elf32.phdr[i].p_memsz) {
                    *result = true;
                    return NO_ERR;
                }
            }
        }
    } else if (elf->class == ELFCLASS64) {
        int addr = elf->data.elf64.shdr[index].sh_addr;
        int size = elf->data.elf64.shdr[index].sh_size;
        if (addr == 0) {
            for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
                if (addr+size > elf->data.elf64.phdr[i].p_vaddr+elf->data.elf64.phdr[i].p_memsz) {
                    *result = true;
                    return NO_ERR;
                }
            }
        }
    } else {
        return ERR_ELF_CLASS;
    }

    *result = false;
    return NO_ERR;
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

/**
 * @brief 修改文件大小，并重新映射
 * Change the file size and remap it
 * @param elf Elf custom structure
 * @param new_size new file size
 * @return error code
 */
static int change_file_size(Elf *elf, size_t new_size) {
    ftruncate(elf->fd, new_size);
    void* new_map = mremap(elf->mem, elf->size, new_size, MREMAP_MAYMOVE);
    if (new_map == MAP_FAILED) {
        return ERR_MEM;
    } else {
        // reinit custom elf structure
        elf->mem = new_map;
        elf->size = new_size;
        reinit(elf);
    }
    return NO_ERR;
}

void reinit(Elf *elf) {
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
        elf->data.elf32.dyn_count = 0;
        elf->data.elf32.sym_count = 0;
        elf->data.elf32.dynsym_count = 0;
        if (elf->data.elf32.ehdr->e_shstrndx == 0) {
            return;
        }
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
                elf->data.elf32.dynsym_count = elf->data.elf32.dynsym->sh_size / sizeof(Elf32_Sym);
            }
            if (!strcmp(section_name, ".symtab")) {
                elf->data.elf32.sym = (Elf32_Shdr *)&elf->data.elf32.shdr[i];
                elf->data.elf32.sym_entry = (Elf32_Sym *)&elf->mem[elf->data.elf32.sym->sh_offset];
                elf->data.elf32.sym_count = elf->data.elf32.sym->sh_size / sizeof(Elf32_Sym);
            }
        }

        elf->data.elf32.dyn = NULL;
        elf->data.elf32.dyn_count = 0;
        for (int i = 0; i < elf->data.elf32.ehdr->e_phnum; i++) {
            if (elf->data.elf32.phdr[i].p_type == PT_DYNAMIC) {
                elf->data.elf32.dyn = (Elf32_Dyn *)&elf->mem[elf->data.elf32.phdr[i].p_offset];
                elf->data.elf32.dyn_count = elf->data.elf32.phdr[i].p_filesz / sizeof(Elf32_Dyn);
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
        elf->data.elf64.dyn_count = 0;
        elf->data.elf64.sym_count = 0;
        elf->data.elf64.dynsym_count = 0;
        if (elf->data.elf64.ehdr->e_shstrndx == 0) {
            return;
        }
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
                elf->data.elf64.dynsym_count = elf->data.elf64.dynsym->sh_size / sizeof(Elf64_Sym);
            }
            if (!strcmp(section_name, ".symtab")) {
                elf->data.elf64.sym = (Elf64_Shdr *)&elf->data.elf64.shdr[i];
                elf->data.elf64.sym_entry = (Elf64_Sym *)&elf->mem[elf->data.elf64.sym->sh_offset];
                elf->data.elf64.sym_count = elf->data.elf64.sym->sh_size / sizeof(Elf64_Sym);
            }
        }

        elf->data.elf64.dyn = NULL;
        elf->data.elf64.dyn_count = 0;
        for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
            if (elf->data.elf64.phdr[i].p_type == PT_DYNAMIC) {
                elf->data.elf64.dyn = (Elf64_Dyn *)&elf->mem[elf->data.elf64.phdr[i].p_offset];
                elf->data.elf64.dyn_count = elf->data.elf64.phdr[i].p_filesz / sizeof(Elf64_Dyn);
            }
        }
    }
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
        PRINT_ERROR("%s section not found!\n", src_name);
        return FALSE;
    }
    if (elf->class == ELFCLASS32) {
        if (strlen(dst_name) <= strlen(src_name)) {
            char *section_name = elf->mem + elf->data.elf32.shstrtab->sh_offset + elf->data.elf32.shdr[index].sh_name;
            memset(section_name, 0, strlen(section_name));
            strcpy(section_name, dst_name);
            return NO_ERR;
        } else {
            size_t src_len = elf->data.elf32.shstrtab->sh_size;
            size_t dst_len = src_len + strlen(dst_name) + 1;
            // string end: 00
            size_t expand_start = 0;
            int err = expand_segment_test(elf, dst_len, &expand_start);
            if (err != NO_ERR) {
                PRINT_ERROR("error: expand_segment_test");
                return err;
            }
            void *src = (void *)elf->mem + elf->data.elf32.shstrtab->sh_offset;
            void *dst = (void *)elf->mem + expand_start;

            if (copy_data(src, dst, src_len) == NO_ERR) {
                // new section shstrtab
                elf->data.elf32.shstrtab->sh_offset = expand_start;
                elf->data.elf32.shstrtab->sh_size = dst_len;
                // string end: 00
                memset(dst + src_len, 0, strlen(dst_name) + 1);
                strcpy(dst + src_len, dst_name);
                // new section name offset
                elf->data.elf32.shdr[index].sh_name = src_len;
                return NO_ERR;
            } else {
                PRINT_ERROR("error: mov section\n");
                return ERR_MOVE;
            }
        }
    } else if (elf->class == ELFCLASS64) {
        if (strlen(dst_name) <= strlen(src_name)) {
            char *section_name = elf->mem + elf->data.elf64.shstrtab->sh_offset + elf->data.elf64.shdr[index].sh_name;
            memset(section_name, 0, strlen(section_name));
            strcpy(section_name, dst_name);
            return NO_ERR;
        } else {
            size_t src_len = elf->data.elf64.shstrtab->sh_size;
            size_t dst_len = src_len + strlen(dst_name) + 1;
            // string end: 00
            size_t expand_start = 0;
            int err = expand_segment_test(elf, dst_len, &expand_start);
            if (err != NO_ERR) {
                PRINT_ERROR("error: expand_segment_test");
                return err;
            }
            void *src = (void *)elf->mem + elf->data.elf64.shstrtab->sh_offset;
            void *dst = (void *)elf->mem + expand_start;

            if (copy_data(src, dst, src_len) == NO_ERR) {
                // new section shstrtab
                elf->data.elf64.shstrtab->sh_offset = expand_start;
                elf->data.elf64.shstrtab->sh_size = dst_len;
                // string end: 00
                memset(dst + src_len, 0, strlen(dst_name) + 1);
                strcpy(dst + src_len, dst_name);
                // new section name offset
                elf->data.elf64.shdr[index].sh_name = src_len;
                return NO_ERR;
            } else {
                PRINT_ERROR("error: mov section\n");
                return ERR_MOVE;
            }
        }
    }
}

static int is_isolated_dynstr(Elf *elf) {
    // uint64_t addr = get_section_addr_by_name(elf, ".dynstr");
    uint64_t addr = get_dynseg_value_by_tag(elf, DT_STRTAB);
    for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
        if (elf->data.elf64.phdr[i].p_type == PT_LOAD) {
            if (addr == elf->data.elf64.phdr[i].p_vaddr) {
                return i;
            }
        }
    }
    return FALSE;
}

static int is_isolated_dynamic(Elf *elf) {
    size_t index = 0;
    get_segment_index_by_type(elf, PT_DYNAMIC, &index);
    for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
        if (elf->data.elf64.phdr[i].p_type == PT_LOAD) {
            if (elf->data.elf64.phdr[index].p_vaddr == elf->data.elf64.phdr[i].p_vaddr) {
                return i;
            }
        }
    }
    return FALSE;
}

static int is_isolated_shstr(Elf *elf) {
    uint64_t offset = get_section_offset_by_name(elf, ".shstrtab");
    for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
        if (elf->data.elf64.phdr[i].p_type == PT_LOAD) {
            if (offset == elf->data.elf64.phdr[i].p_offset) {
                return i;
            }
        }
    }
    return FALSE;
}

static int is_isolated_seg(Elf *elf, uint64_t offset) {
    for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
        if (elf->data.elf64.phdr[i].p_type == PT_LOAD) {
            if (offset == elf->data.elf64.phdr[i].p_offset) {
                return i;
            }
        }
    }
    return FALSE;
}

/**
 * @brief 设置符号表的名字
 * Set a new dynamic symbol name
 * @param elf Elf custom structure
 * @param src_name original symbol name
 * @param dst_name new symbole name
 * @return error code
 */
int set_dynstr_name(Elf *elf, char *src_name, char *dst_name) {
    int sym_i = get_dynsym_index_by_name(elf, src_name);
    uint64_t offset = 0;    // for expand_segment_load
    uint64_t addr = 0;      // for expand_segment_load
    uint64_t seg_i = 0;
    if (index == FALSE) {
        return ERR_SEC_NOTFOUND;
    }
    if (elf->class == ELFCLASS32) {
        if (strlen(dst_name) <= strlen(src_name)) {
            char *name = elf->mem + elf->data.elf32.dynstrtab->sh_offset + elf->data.elf32.dynsym_entry[sym_i].st_name;
            memset(name, 0, strlen(name));
            strcpy(name, dst_name);
            return NO_ERR;
        } else {
            /* Determine whether dynstr is within an independent PT_LOAD segment */
            /* 判断dynstr是否在一个独立的PT_LOAD段内 */
            seg_i = is_isolated_dynstr(elf);
            if (seg_i != FALSE) {
                PRINT_VERBOSE("dynstr is in an isolated PT_LOAD segment, expand a segment\n");
                int strsz_i = get_dynseg_index_by_tag(elf, DT_STRSZ);
                /* Determine if PT_LOAD has extra space */
                /* 判断PT_LOAD是否有多余空间 */
                if (elf->data.elf32.phdr[seg_i].p_filesz - elf->data.elf32.dynstrtab->sh_size >= strlen(dst_name) + 1) {
                    // enough space
                    memset((void *)elf->mem + elf->data.elf32.dynstrtab->sh_offset + elf->data.elf32.dynstrtab->sh_size, 0, strlen(dst_name) + 1);
                    strcpy((char *)elf->mem + elf->data.elf32.dynstrtab->sh_offset + elf->data.elf32.dynstrtab->sh_size, dst_name);
                    elf->data.elf32.dynsym_entry[sym_i].st_name = elf->data.elf32.dynstrtab->sh_size;
                    elf->data.elf32.dynstrtab->sh_size += strlen(dst_name) + 1;
                    elf->data.elf32.dyn[strsz_i].d_un.d_val += strlen(dst_name) + 1;
                } else if (expand_segment_load(elf, seg_i, strlen(dst_name) + 1, &offset, &addr) == NO_ERR) {
                    memset((void *)elf->mem + elf->data.elf32.dynstrtab->sh_offset + elf->data.elf32.dynstrtab->sh_size, 0, strlen(dst_name) + 1);
                    strcpy((char *)elf->mem + elf->data.elf32.dynstrtab->sh_offset + elf->data.elf32.dynstrtab->sh_size, dst_name);
                    elf->data.elf32.dyn[strsz_i].d_un.d_val += strlen(dst_name) + 1;
                    elf->data.elf32.dynstrtab->sh_size += strlen(dst_name) + 1;
                    elf->data.elf32.dynsym_entry[sym_i].st_name = elf->data.elf32.dynstrtab->sh_size - (strlen(dst_name) + 1);
                } else {
                    return ERR_EXPAND_SEG;
                }

                return NO_ERR;
            }
            PRINT_VERBOSE("dynstr is not in an isolated PT_LOAD segment, add a new segment\n");
            size_t src_len = elf->data.elf32.dynstrtab->sh_size;
            size_t dst_len = src_len + strlen(dst_name) + 1;
            if (add_segment_easy(elf, dst_len, &seg_i) != NO_ERR) {
                return ERR_ADD_SEG;
            }

            uint32_t dst_offset = elf->data.elf32.phdr[seg_i].p_offset;
            uint32_t dst_addr = elf->data.elf32.phdr[seg_i].p_vaddr;
            void *src = (void *)elf->mem + elf->data.elf32.dynstrtab->sh_offset;
            void *dst = (void *)elf->mem + dst_offset;

            if (copy_data(src, dst, src_len) == NO_ERR) {
                // new section dynstr table
                elf->data.elf32.dynstrtab->sh_offset = dst_offset;
                elf->data.elf32.dynstrtab->sh_addr = dst_addr;
                elf->data.elf32.dynstrtab->sh_size = dst_len;
                // map to segment
                int strtab_i = get_dynseg_index_by_tag(elf, DT_STRTAB);
                int strsz_i = get_dynseg_index_by_tag(elf, DT_STRSZ);
                elf->data.elf32.dyn[strtab_i].d_un.d_val = dst_addr;
                elf->data.elf32.dyn[strsz_i].d_un.d_val = dst_len;
                memset(dst + src_len, 0, strlen(dst_name) + 1);
                strcpy(dst + src_len, dst_name);
                // new section name offset
                elf->data.elf32.dynsym_entry[sym_i].st_name = src_len;
                return NO_ERR;
            } else {
                return ERR_COPY;
            }
        }
    } else if (elf->class == ELFCLASS64) {
        if (strlen(dst_name) <= strlen(src_name)) {
            char *name = elf->mem + elf->data.elf64.dynstrtab->sh_offset + elf->data.elf64.dynsym_entry[sym_i].st_name;
            memset(name, 0, strlen(name));
            strcpy(name, dst_name);
            return NO_ERR;
        } else {
            /* Determine whether dynstr is within an independent PT_LOAD segment */
            /* 判断dynstr是否在一个独立的PT_LOAD段内 */
            seg_i = is_isolated_dynstr(elf);
            if (seg_i != FALSE) {
                PRINT_VERBOSE("dynstr is in an isolated PT_LOAD segment, expand a segment\n");
                int strsz_i = get_dynseg_index_by_tag(elf, DT_STRSZ);
                /* Determine if PT_LOAD has extra space */
                /* 判断PT_LOAD是否有多余空间 */
                if (elf->data.elf64.phdr[seg_i].p_filesz - elf->data.elf64.dynstrtab->sh_size >= strlen(dst_name) + 1) {
                    // enough space
                    memset((void *)elf->mem + elf->data.elf64.dynstrtab->sh_offset + elf->data.elf64.dynstrtab->sh_size, 0, strlen(dst_name) + 1);
                    strcpy((char *)elf->mem + elf->data.elf64.dynstrtab->sh_offset + elf->data.elf64.dynstrtab->sh_size, dst_name);
                    elf->data.elf64.dynsym_entry[sym_i].st_name = elf->data.elf64.dynstrtab->sh_size;
                    elf->data.elf64.dynstrtab->sh_size += strlen(dst_name) + 1;
                    elf->data.elf64.dyn[strsz_i].d_un.d_val += strlen(dst_name) + 1;
                } else if (expand_segment_load(elf, seg_i, strlen(dst_name) + 1, &offset, &addr) == NO_ERR) {
                    memset((void *)elf->mem + elf->data.elf64.dynstrtab->sh_offset + elf->data.elf64.dynstrtab->sh_size, 0, strlen(dst_name) + 1);
                    strcpy((char *)elf->mem + elf->data.elf64.dynstrtab->sh_offset + elf->data.elf64.dynstrtab->sh_size, dst_name);
                    elf->data.elf64.dyn[strsz_i].d_un.d_val += strlen(dst_name) + 1;
                    elf->data.elf64.dynstrtab->sh_size += strlen(dst_name) + 1;
                    elf->data.elf64.dynsym_entry[sym_i].st_name = elf->data.elf64.dynstrtab->sh_size - (strlen(dst_name) + 1);
                } else {
                    return ERR_EXPAND_SEG;
                }

                return NO_ERR;
            }
            PRINT_VERBOSE("dynstr is not in an isolated PT_LOAD segment, add a new segment\n");
            size_t src_len = elf->data.elf64.dynstrtab->sh_size;
            size_t dst_len = src_len + strlen(dst_name) + 1;
            if (add_segment_easy(elf, dst_len, &seg_i) != NO_ERR) {
                return ERR_ADD_SEG;
            }

            uint64_t dst_offset = elf->data.elf64.phdr[seg_i].p_offset;
            uint64_t dst_addr = elf->data.elf64.phdr[seg_i].p_vaddr;
            void *src = (void *)elf->mem + elf->data.elf64.dynstrtab->sh_offset;
            void *dst = (void *)elf->mem + dst_offset;

            if (copy_data(src, dst, src_len) == NO_ERR) {
                // new section dynstr table
                elf->data.elf64.dynstrtab->sh_offset = dst_offset;
                elf->data.elf64.dynstrtab->sh_addr = dst_addr;
                elf->data.elf64.dynstrtab->sh_size = dst_len;
                // map to segment
                int strtab_i = get_dynseg_index_by_tag(elf, DT_STRTAB);
                int strsz_i = get_dynseg_index_by_tag(elf, DT_STRSZ);
                elf->data.elf64.dyn[strtab_i].d_un.d_val = dst_addr;
                elf->data.elf64.dyn[strsz_i].d_un.d_val = dst_len;
                memset(dst + src_len, 0, strlen(dst_name) + 1);
                strcpy(dst + src_len, dst_name);
                // new section name offset
                elf->data.elf64.dynsym_entry[sym_i].st_name = src_len;
                return NO_ERR;
            } else {
                return ERR_COPY;
            }
        }
    } else {
        return ERR_ELF_CLASS;
    }
    return NO_ERR;
}

/**
 * @brief 添加符号名字
 * Add a new dynamic symbol name
 * @param elf Elf custom structure
 * @param name new symbole name
 * @param name_offset offset of new symbol name in dynstr table
 * @return error code
 */
int add_dynstr_name(Elf *elf, char *name, uint64_t *name_offset) {
    uint64_t src_offset = get_section_offset_by_name(elf, ".dynstr");
    uint64_t src_size = get_section_size_by_name(elf, ".dynstr");
    int dst_index = 0;
    int err = 0;
    if (index == FALSE) {
        return ERR_SEC_NOTFOUND;
    }
    if (elf->class == ELFCLASS32) {
        dst_index = expand_segment_content(elf, src_offset, src_size, name, strlen(name) + 1);
        if (dst_index < 0) {
            PRINT_ERROR("expand_segment_content error: %d\n", dst_index);
            return dst_index;
        }
        err = set_dynseg_value_by_tag(elf, DT_STRTAB, elf->data.elf32.phdr[dst_index].p_vaddr);
        if (err != NO_ERR) {
            PRINT_ERROR("set DT_STRTAB error\n");
            return err;
        }
        err = set_dynseg_value_by_tag(elf, DT_STRSZ, elf->data.elf32.phdr[dst_index].p_filesz);
        if (err != NO_ERR) {
            PRINT_ERROR("set DT_STRSZ error\n");
            return err;
        }
        *name_offset = src_size;
    } else if (elf->class == ELFCLASS64) { 
        dst_index = expand_segment_content(elf, src_offset, src_size, name, strlen(name) + 1);
        if (dst_index < 0) {
            PRINT_ERROR("expand_segment_content error: %d\n", dst_index);
            return dst_index;
        }
        err = set_dynseg_value_by_tag(elf, DT_STRTAB, elf->data.elf64.phdr[dst_index].p_vaddr);
        if (err != NO_ERR) {
            PRINT_ERROR("set DT_STRTAB error\n");
            return err;
        }
        err = set_dynseg_value_by_tag(elf, DT_STRSZ, elf->data.elf64.phdr[dst_index].p_filesz);
        if (err != NO_ERR) {
            PRINT_ERROR("set DT_STRSZ error\n");
            return err;
        }
        *name_offset = src_size;
    } else {
        return ERR_ELF_CLASS;
    }

    return NO_ERR;
}

/**
 * @brief 添加符号名字
 * Add a new section header name
 * @param elf Elf custom structure
 * @param name new symbole name
 * @param name_offset offset of new symbol name in dynstr table
 * @return error code
 */
int add_shstr_name(Elf *elf, char *name, uint64_t *name_offset) {
    int shstr_sec_i = get_section_index_by_name(elf, ".shstrtab");
    if (shstr_sec_i < 0) {
        return shstr_sec_i;
    }

    uint64_t offset = 0;    // for expand_segment_load
    uint64_t addr = 0;      // for expand_segment_load
    uint64_t seg_i = 0;
    if (index == FALSE) {
        return ERR_SEC_NOTFOUND;
    }
    if (elf->class == ELFCLASS32) {
        ;
    } else if (elf->class == ELFCLASS64) { 
        /* Determine whether dynstr is within an independent PT_LOAD segment */
        /* 判断shstrtab是否在一个独立的PT_LOAD段内 */
        seg_i = is_isolated_shstr(elf);
        if (seg_i != FALSE) {
            PRINT_VERBOSE("shstr is in an isolated PT_LOAD segment, expand a segment\n");
            int strsz_i = get_dynseg_index_by_tag(elf, DT_STRSZ);
            /* Determine if PT_LOAD has extra space */
            /* 判断PT_LOAD是否有多余空间 */
            if (elf->data.elf64.phdr[seg_i].p_filesz - elf->data.elf64.shdr[shstr_sec_i].sh_size >= strlen(name) + 1) {
                // enough space
                *name_offset = elf->data.elf64.shdr[shstr_sec_i].sh_size;
                memset((void *)elf->mem + elf->data.elf64.shdr[shstr_sec_i].sh_offset + elf->data.elf64.shdr[shstr_sec_i].sh_size, 0, strlen(name) + 1);
                strcpy((char *)elf->mem + elf->data.elf64.shdr[shstr_sec_i].sh_offset + elf->data.elf64.shdr[shstr_sec_i].sh_size, name);
                elf->data.elf64.shdr[shstr_sec_i].sh_size += strlen(name) + 1;
            } else if (expand_segment_load(elf, seg_i, strlen(name) + 1, &offset, &addr) == NO_ERR) {
                *name_offset = elf->data.elf64.shdr[shstr_sec_i].sh_size;
                memset((void *)elf->mem + elf->data.elf64.shdr[shstr_sec_i].sh_offset + elf->data.elf64.shdr[shstr_sec_i].sh_size, 0, strlen(name) + 1);
                strcpy((char *)elf->mem + elf->data.elf64.shdr[shstr_sec_i].sh_offset + elf->data.elf64.shdr[shstr_sec_i].sh_size, name);
                elf->data.elf64.shdr[shstr_sec_i].sh_size += strlen(name) + 1;
            } else {
                return ERR_EXPAND_SEG;
            }

            return NO_ERR;
        } else {
            PRINT_VERBOSE("dynstr is not in an isolated PT_LOAD segment, add a new segment\n");
            size_t src_len = elf->data.elf64.shdr[shstr_sec_i].sh_size;
            size_t dst_len = src_len + strlen(name) + 1;
            if (add_segment_auto(elf, dst_len, &seg_i) != NO_ERR) {
                return ERR_ADD_SEG;
            }

            uint64_t dst_offset = elf->data.elf64.phdr[seg_i].p_offset;
            uint64_t dst_addr = elf->data.elf64.phdr[seg_i].p_vaddr;
            void *src = (void *)elf->mem + elf->data.elf64.shdr[shstr_sec_i].sh_offset;
            void *dst = (void *)elf->mem + dst_offset;

            if (copy_data(src, dst, src_len) == NO_ERR) {
                // new section shdr table
                elf->data.elf64.shdr[shstr_sec_i].sh_offset = dst_offset;
                // elf->data.elf64.shdr[shstr_sec_i].sh_addr = dst_addr;
                elf->data.elf64.shdr[shstr_sec_i].sh_size = dst_len;
                memset(dst + src_len, 0, strlen(name) + 1);
                strcpy(dst + src_len, name);
                // new section name offset
                *name_offset = src_len;
                return NO_ERR;
            } else {
                return ERR_COPY;
            }
        }
    } else {
        return ERR_ELF_CLASS;
    }
    return NO_ERR;
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
        return ERR_SEC_NOTFOUND;
    }
    if (elf->class == ELFCLASS32) {
        size_t src_len = elf->data.elf32.dynstrtab->sh_size;
        size_t dst_len = src_len + strlen(dst_name) + 1;
        // string end: 00
        size_t expand_start = 0;
        int err = expand_segment_test(elf, dst_len, &expand_start);
        if (err != NO_ERR) {
            return ERR_EXPAND_SEG;
        }
        void *src = (void *)elf->mem + elf->data.elf32.dynstrtab->sh_offset;
        void *dst = (void *)elf->mem + expand_start;

        if (copy_data(src, dst, src_len) == NO_ERR) {
            // new section dynstr table
            elf->data.elf32.dynstrtab->sh_offset = expand_start;
            elf->data.elf32.dynstrtab->sh_size = dst_len;
            // map to segment
            int strtab_i = get_dynseg_index_by_tag(elf, DT_STRTAB);
            int strsz_i = get_dynseg_index_by_tag(elf, DT_STRSZ);
            elf->data.elf32.dyn[strtab_i].d_un.d_val = expand_start;
            elf->data.elf32.dyn[strsz_i].d_un.d_val = dst_len;
            // string end: 00
            memset(dst + src_len, 0, strlen(dst_name) + 1);
            strcpy(dst + src_len, dst_name);
            // new section name offset
            elf->data.elf32.dynsym_entry[index].st_name = src_len;
            return NO_ERR;
        } else {
            printf("error: mov section\n");
            return ERR_MOVE;
        }
    } else if (elf->class == ELFCLASS64) {
        if (strlen(dst_name) <= strlen(src_name)) {
            char *name = elf->mem + elf->data.elf64.strtab->sh_offset + elf->data.elf64.sym_entry[index].st_name;
            memset(name, 0, strlen(name));
            strcpy(name, dst_name);
            return NO_ERR;
        } else {
            size_t src_len = elf->data.elf64.strtab->sh_size;
            size_t dst_len = src_len + strlen(dst_name) + 1;
            // string end: 00
            size_t expand_start = 0;
            int err = expand_segment_test(elf, dst_len, &expand_start);
            if (err != NO_ERR) {
                return err;
            }
            void *src = (void *)elf->mem + elf->data.elf64.strtab->sh_offset;
            void *dst = (void *)elf->mem + expand_start;

            if (copy_data(src, dst, src_len) == NO_ERR) {
                // new section dynstr table
                elf->data.elf64.strtab->sh_offset = expand_start;
                elf->data.elf64.strtab->sh_size = dst_len;
                // string end: 00
                memset(dst + src_len, 0, strlen(dst_name) + 1);
                strcpy(dst + src_len, dst_name);
                // new section name offset
                elf->data.elf64.sym_entry[index].st_name = src_len;
                return NO_ERR;
            } else {
                printf("error: mov section\n");
                return ERR_MOVE;
            }
        }
    }
}

/**
 * @brief 设置新的解释器（动态链接器）
 * set up a new interpreter (dynamic linker)
 * @param elf_name elf file name
 * @param new_interpreter string
 * @return error code
 */
int set_interpreter(Elf *elf, char *new_interpreter) {
    uint64_t offset = get_section_offset_by_name(elf, ".interp");
    size_t size = get_section_size_by_name(elf, ".interp");
    // 如果新的解释器的名字的长度小于原有的长度，则不需要修改ELF文件大小
    // if the length of the name of the new interpreter is less than the original length,
    // there is no need to modify the ELF file size
    if (strlen(new_interpreter) + 1 <= size) {
        PRINT_VERBOSE("don't need to add a segment\n");
        memcpy((void *)elf->mem + offset, new_interpreter, strlen(new_interpreter) + 1);
        return NO_ERR;
    }
    if (elf->class == ELFCLASS32) {
        PRINT_VERBOSE("need to add a segment\n");
        // 添加一个新的load段，存放新的interpreter字符串
        // add a new load segment to store the new interpreter string
        size_t seg_added = 0;
        int err = add_segment_easy(elf, strlen(new_interpreter) + 1, &seg_added);
        if (err != NO_ERR) {
            return err;
        }
        
        // 写入新的interpreter字符串
        // write the new interpreter string
        memcpy((void *)elf->mem + elf->data.elf32.phdr[seg_added].p_offset, new_interpreter, strlen(new_interpreter) + 1);
        
        // 原有interpreter段表指向新的load段s
        // the original interpreter segment table points to the new load segment
        size_t seg_interp = 0;
         get_segment_index_by_type(elf, PT_INTERP, &seg_interp);
        elf->data.elf32.phdr[seg_interp].p_offset = elf->data.elf32.phdr[seg_added].p_offset;
        elf->data.elf32.phdr[seg_interp].p_vaddr = elf->data.elf32.phdr[seg_added].p_vaddr;
        elf->data.elf32.phdr[seg_interp].p_paddr = elf->data.elf32.phdr[seg_added].p_paddr;
        elf->data.elf32.phdr[seg_interp].p_filesz = elf->data.elf32.phdr[seg_added].p_filesz;
        elf->data.elf32.phdr[seg_interp].p_memsz = elf->data.elf32.phdr[seg_added].p_memsz;
        // set shdr
        uint32_t sec_i = get_section_index_by_name(elf, ".interp");
        elf->data.elf32.shdr[sec_i].sh_offset = elf->data.elf32.phdr[seg_added].p_offset;
        elf->data.elf32.shdr[sec_i].sh_addr = elf->data.elf32.phdr[seg_added].p_vaddr;
        elf->data.elf32.shdr[sec_i].sh_size = elf->data.elf32.phdr[seg_added].p_filesz;
        return NO_ERR;
    } else if (elf->class == ELFCLASS64){
        PRINT_VERBOSE("need to add a segment\n");
        // 添加一个新的load段，存放新的interpreter字符串
        // add a new load segment to store the new interpreter string
        size_t seg_added = 0;
        int err = add_segment_easy(elf, strlen(new_interpreter) + 1, &seg_added);
        if (err != NO_ERR) {
            return err;
        }
        
        // 写入新的interpreter字符串
        // write the new interpreter string
        memcpy((void *)elf->mem + elf->data.elf64.phdr[seg_added].p_offset, new_interpreter, strlen(new_interpreter) + 1);
        
        // 原有interpreter段表指向新的load段s
        // the original interpreter segment table points to the new load segment
        size_t seg_interp  = 0;
        get_segment_index_by_type(elf, PT_INTERP, &seg_interp);
        elf->data.elf64.phdr[seg_interp].p_offset = elf->data.elf64.phdr[seg_added].p_offset;
        elf->data.elf64.phdr[seg_interp].p_vaddr = elf->data.elf64.phdr[seg_added].p_vaddr;
        elf->data.elf64.phdr[seg_interp].p_paddr = elf->data.elf64.phdr[seg_added].p_paddr;
        elf->data.elf64.phdr[seg_interp].p_filesz = elf->data.elf64.phdr[seg_added].p_filesz;
        elf->data.elf64.phdr[seg_interp].p_memsz = elf->data.elf64.phdr[seg_added].p_memsz;
        // set shdr
        uint64_t sec_i = get_section_index_by_name(elf, ".interp");
        elf->data.elf64.shdr[sec_i].sh_offset = elf->data.elf64.phdr[seg_added].p_offset;
        elf->data.elf64.shdr[sec_i].sh_addr = elf->data.elf64.phdr[seg_added].p_vaddr;
        elf->data.elf64.shdr[sec_i].sh_size = elf->data.elf64.phdr[seg_added].p_filesz;
        return NO_ERR;
    } else {
        return ERR_ELF_CLASS;
    }
}

/**
 * @brief 设置rpath
 * set rpath
 * @param elf Elf custom structure
 * @param rpath string
 * @return error code
 */
int set_rpath(Elf *elf, char *rpath) {
    // 1. store rpath string in .dynstr
    uint64_t path_offset = 0;
    int err = add_dynstr_name(elf, rpath, &path_offset);
    if (err != NO_ERR) {
        PRINT_ERROR("add dynstr name error :%d\n", err);
        return err;
    }
    // 2. add DT_RPATH entry in .dynamic
    return add_dynseg_auto(elf, DT_RPATH, path_offset);
}

/**
 * @brief 设置runpath
 * set runpath
 * @param elf Elf custom structure
 * @param rpath string
 * @return error code
 */
int set_runpath(Elf *elf, char *runpath) {
    // 1. store runpath string in .dynstr
    uint64_t path_offset = 0;
    int err = add_dynstr_name(elf, runpath, &path_offset);
    if (err != NO_ERR) {
        PRINT_ERROR("add dynstr name error :%d\n", err);
        return err;
    }
    // 2. add DT_RUNPATH entry in .dynamic
    return add_dynseg_auto(elf, DT_RUNPATH, path_offset);
}

static int mov_last_sections(Elf *elf, uint64_t expand_offset, size_t size) {
    if (elf->class == ELFCLASS32) {
        // mov section header table
        void *src = (void *)elf->mem + elf->data.elf32.ehdr->e_shoff;
        void *dst = (void *)elf->mem + elf->data.elf32.ehdr->e_shoff + size;
        size_t src_len = elf->data.elf32.ehdr->e_shnum * elf->data.elf32.ehdr->e_shentsize;
        if (copy_data(src, dst, src_len) == NO_ERR) {
            elf->data.elf32.ehdr->e_shoff += size;
            reinit(elf);
        } else {
            printf("error: mov section header\n");
            return ERR_MOVE;
        }

        /* 按节偏移降序排序 */
        /* Sort by section offset in descending order */
        SectionManager *manager = section_manager_create();
        if (!manager) {
            printf("Failed to create section manager\n");
            return ERR_MEM;
        }

        for (int i = 0; i < elf->data.elf32.ehdr->e_shnum; i++) {
            if (elf->data.elf32.shdr[i].sh_addr == 0 && elf->data.elf32.shdr[i].sh_offset != 0 && elf->data.elf32.shdr[i].sh_offset >= expand_offset) {
                section_manager_add_32bit(manager, &elf->data.elf32.shdr[i], i);
            }
        }

        section_manager_sort_by_offset_desc(manager);

        /* 我们只移动节, 不移动段, 注意顺序，从大到小 */
        /* we only move sections, not segments. */
        SectionNode *cur_sec = manager->head;
        int link_index = 0;
        while (cur_sec) {
            void *src = (void *)elf->mem + cur_sec->shdr32->sh_offset;
            void *dst = (void *)elf->mem + cur_sec->shdr32->sh_offset + size;
            if (copy_data(src, dst, cur_sec->shdr32->sh_size) == NO_ERR) {
                cur_sec->shdr32->sh_offset += size;
            } else {
                PRINT_ERROR("error: mov section\n");
                return ERR_MOVE;
            }  
            cur_sec = cur_sec->next;
            link_index++;
        }
        section_manager_destroy(manager);
    } else if (elf->class == ELFCLASS64) {
        // mov section header table
        void *src = (void *)elf->mem + elf->data.elf64.ehdr->e_shoff;
        void *dst = (void *)elf->mem + elf->data.elf64.ehdr->e_shoff + size;
        size_t src_len = elf->data.elf64.ehdr->e_shnum * elf->data.elf64.ehdr->e_shentsize;
        if (copy_data(src, dst, src_len) == NO_ERR) {
            elf->data.elf64.ehdr->e_shoff += size;
            reinit(elf);
        } else {
            printf("error: mov section header\n");
            return ERR_MEM;
        }

        /* 按节偏移降序排序 */
        /* Sort by section offset in descending order */
        SectionManager *manager = section_manager_create();
        if (!manager) {
            printf("Failed to create section manager\n");
            return ERR_MEM;
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
            if (copy_data(src, dst, cur_sec->shdr64->sh_size) == NO_ERR) {
                cur_sec->shdr64->sh_offset += size;
            } else {
                PRINT_ERROR("error: mov section\n");
                return ERR_MOVE;
            }  
            cur_sec = cur_sec->next;
            link_index++;
        }
        section_manager_destroy(manager);
    } else {
        return ERR_ELF_CLASS;
    }
    return NO_ERR;
    
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
 * @brief 扩充一个段，默认只扩充最后一个类型为PT_LOAD的段
 * Expand a segment, default to only expanding the last segment of type PT_LOAD
 * @param elf Elf custom structure
 * @param size expand size
 * @param start expand segment start address
 * @return start offset
 */
int expand_segment_test(Elf *elf, size_t size, size_t *start) {
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
            PRINT_ERROR("mremap");
            return ERR_MEM;
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
            if (copy_data(src, dst, src_len) == NO_ERR) {
                elf->data.elf32.ehdr->e_shoff += size;
                // reinit custom elf structure after move!
                reinit(elf);
            } else {
                PRINT_ERROR("error: mov section header\n");
                return ERR_MOVE;
            }
        }

        /* 按节偏移降序排序 */
        /* Sort by section offset in descending order */
        SectionManager *manager = section_manager_create();
        if (!manager) {
            PRINT_ERROR("error: failed to create section manager\n");
            return ERR_MEM;
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
            if (copy_data(src, dst, current->shdr32->sh_size) == NO_ERR) {
                current->shdr32->sh_offset += size;
            } else {
                PRINT_ERROR("error: mov section\n");
                return ERR_MOVE;
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
            PRINT_ERROR("mremap");
            return ERR_MEM;
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
            if (copy_data(src, dst, src_len) == NO_ERR) {
                elf->data.elf64.ehdr->e_shoff += size;
                // reinit custom elf structure after move!
                reinit(elf);
            } else {
                PRINT_ERROR("error: mov section header\n");
                return ERR_MOVE;
            }
        }

        /* 按节偏移降序排序 */
        /* Sort by section offset in descending order */
        SectionManager *manager = section_manager_create();
        if (!manager) {
            PRINT_ERROR("error: failed to create section manager\n");
            return ERR_MEM;
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
            if (copy_data(src, dst, current->shdr64->sh_size) == NO_ERR) {
                current->shdr64->sh_offset += size;
            } else {
                PRINT_ERROR("error: mov section\n");
                return ERR_MOVE;
            }  
            current = current->next;
            link_index++;
        }
        section_manager_destroy(manager);
        memset(elf->mem + ret_offset, 0, size);
    }
    
    reinit(elf);
    *start = ret_offset;
    return NO_ERR;
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
        PRINT_ERROR("err: mapping_list\n");
        return ERR_MEM;
    }

    if (elf->class == ELFCLASS32) {
        *added_offset = elf->data.elf32.phdr[index].p_offset + elf->data.elf32.phdr[index].p_filesz;
        *added_vaddr = elf->data.elf32.phdr[index].p_vaddr + elf->data.elf32.phdr[index].p_memsz;
        
        size_t free_space = 0;
        // last load segment
        if (elf->data.elf32.phdr[index+1].p_type == PT_LOAD)
            free_space = elf->data.elf32.phdr[index+1].p_offset - elf->data.elf32.phdr[index].p_offset - elf->data.elf32.phdr[index].p_filesz;
        // printf("free_space = %x\n", free_space);
        if (size <= free_space) {
            elf->data.elf32.phdr[index].p_filesz += size;
            elf->data.elf32.phdr[index].p_memsz += size;
            
            // the end sub section
            ListNode* current = found->sec_head;
            while (current != NULL) {
                if (current->next == NULL) {
                    elf->data.elf32.shdr[current->index].sh_size += size;
                } 
                current = current->next;
            }
        } else {
            size_t added_size = align_page(size);
            elf->data.elf32.phdr[index].p_filesz += size;
            elf->data.elf32.phdr[index].p_memsz += size;

            // the end sub section
            ListNode* current = found->sec_head;
            while (current != NULL) {
                if (current->next == NULL) {
                    elf->data.elf32.shdr[current->index].sh_size += size;
                } 
                current = current->next;
            }

            /* ----------------------------0.expand file---------------------------- */
            size_t new_size = elf->size + added_size;
            change_file_size(elf, new_size);

            /* ----------------------------1.mov section---------------------------- */
            mov_last_sections(elf, *added_offset, added_size);
            
            // 2. mov segment after target segment
            /* ----------------------------2.mov segment---------------------------- */
            for (int i = elf->data.elf32.ehdr->e_phnum - 1; i > index; i--) {
                if (elf->data.elf32.phdr[i].p_type == PT_LOAD) {
                    void *src = (void *)elf->mem + elf->data.elf32.phdr[i].p_offset;
                    void *dst = src + added_size;
                    if (copy_data(src, dst, elf->data.elf32.phdr[i].p_filesz) == NO_ERR) {
                        elf->data.elf32.phdr[i].p_offset += added_size;
                        elf->data.elf32.phdr[i].p_vaddr += added_size;
                        elf->data.elf32.phdr[i].p_paddr += added_size;
                    } else {
                        printf("error: mov segment\n");
                        return FALSE;
                    }

                    // set sub segment offset and address
                    IndexMapping* found_seg = find_mapping(mapping_list, i);
                    ListNode* cur_seg = found_seg->seg_head;
                    while (cur_seg != NULL) {
                        elf->data.elf32.phdr[cur_seg->index].p_offset += added_size;
                        elf->data.elf32.phdr[cur_seg->index].p_vaddr += added_size;
                        elf->data.elf32.phdr[cur_seg->index].p_paddr += added_size; 
                        cur_seg = cur_seg->next;
                    }

                    // set sub section offset and address
                    IndexMapping* found_sec = find_mapping(mapping_list, i);
                    ListNode* cur_sec = found_sec->sec_head;
                    while (cur_sec != NULL) {
                        elf->data.elf32.shdr[cur_sec->index].sh_offset += added_size;
                        elf->data.elf32.shdr[cur_sec->index].sh_addr += added_size;
                        cur_sec = cur_sec->next;
                    }

                    // set elf file entry
                    if (elf->data.elf32.phdr[i].p_flags & PF_X) {
                        elf->data.elf32.ehdr->e_entry += added_size;
                    }
                }
            }

            reinit(elf);
            // 3. change dynamic segment entry value
            for (int i = 0; i < elf->data.elf32.dyn_count; i++) {
                uint32_t value = elf->data.elf32.dyn[i].d_un.d_ptr;
                uint32_t tag = elf->data.elf32.dyn[i].d_tag;
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
                            elf->data.elf32.dyn[i].d_un.d_ptr += added_size;
                            break;
                        
                        default:
                            break;
                    }
                }
            }
        }
    } else if (elf->class == ELFCLASS64) {
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
            change_file_size(elf, new_size);

            /* ----------------------------1.mov section---------------------------- */
            mov_last_sections(elf, *added_offset, added_size);
            
            // 2. mov segment after target segment
            /* ----------------------------2.mov segment---------------------------- */
            for (int i = elf->data.elf64.ehdr->e_phnum - 1; i > index; i--) {
                if (elf->data.elf64.phdr[i].p_type == PT_LOAD) {
                    void *src = (void *)elf->mem + elf->data.elf64.phdr[i].p_offset;
                    void *dst = src + added_size;
                    if (copy_data(src, dst, elf->data.elf64.phdr[i].p_filesz) == NO_ERR) {
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
            for (int i = 0; i < elf->data.elf64.dyn_count; i++) {
                uint64_t value = elf->data.elf64.dyn[i].d_un.d_ptr;
                uint64_t tag = elf->data.elf64.dyn[i].d_tag;
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
                            elf->data.elf64.dyn[i].d_un.d_ptr += added_size;
                            break;
                        
                        default:
                            break;
                    }
                }
            }
        }
    } else {
        free_mapping_list(mapping_list);
        return ERR_ELF_CLASS;
    }

    free_mapping_list(mapping_list);
    return NO_ERR;
}

/**
 * @brief 扩充一个节或者一个段
 * expand a section or segment
 * @param elf Elf custom structure 
 * @param src_offset sec/seg offset
 * @param src_size sec/seg origin size
 * @param add_content new added content
 * @param content_size new added content size
 * @return error code
 */
int expand_segment_content(Elf *elf, uint64_t src_offset, size_t src_size, char *add_content, size_t content_size) {
    uint64_t offset = 0;    // for expand_segment_load
    uint64_t addr = 0;      // for expand_segment_load
    uint64_t seg_i = 0;
    uint64_t sec_i = 0;
    if (index == FALSE) {
        return ERR_SEC_NOTFOUND;
    }
    if (elf->class == ELFCLASS32) {
        // update section size
        for (int i = 0; i < elf->data.elf32.ehdr->e_shnum; i++) {
            if (elf->data.elf32.shdr[i].sh_offset == src_offset) {
                elf->data.elf32.shdr[i].sh_size += content_size;
                sec_i = i;
                break;
            }
        }

        /* Determine whether object is within an independent PT_LOAD segment */
        /* 判断是否在一个独立的PT_LOAD段内 */
        seg_i = is_isolated_seg(elf, src_offset);
        if (seg_i != FALSE) {
            PRINT_VERBOSE("object is in an isolated PT_LOAD segment, expand a segment\n");
            // if enough space, just expand it
            if (src_size + content_size <= elf->data.elf32.phdr[seg_i].p_filesz) {
                PRINT_VERBOSE("enough space in the segment, just resize it\n");
                memcpy((char *)elf->mem + src_offset + src_size, add_content, content_size);
                return seg_i;
            } else if (expand_segment_load(elf, seg_i, content_size, &offset, &addr) == NO_ERR) {
                PRINT_VERBOSE("not enough space in the segment, expand the segment\n");
                memcpy((char *)elf->mem + offset, add_content, content_size);
            } else {
                return ERR_EXPAND_SEG;
            }
        } else {
            PRINT_VERBOSE("object is not in an isolated PT_LOAD segment, add a new segment\n");
            if (add_segment_auto(elf, src_size + content_size, &seg_i) != NO_ERR) {
                return ERR_ADD_SEG;
            }

            uint32_t dst_offset = elf->data.elf32.phdr[seg_i].p_offset;
            void *src = (void *)elf->mem + src_offset;
            void *dst = (void *)elf->mem + dst_offset;

            if (copy_data(src, dst, src_size) == NO_ERR) {
                memcpy((char *)dst + src_size, add_content, content_size);
            } else {
                return ERR_COPY;
            }
            
            // update section offset and address
            elf->data.elf32.shdr[sec_i].sh_offset = dst_offset;
            elf->data.elf32.shdr[sec_i].sh_addr = elf->data.elf32.phdr[seg_i].p_vaddr;
        }
        reinit(elf);
        return seg_i;
    } else if (elf->class == ELFCLASS64) {
        // update section size
        for (int i = 0; i < elf->data.elf64.ehdr->e_shnum; i++) {
            if (elf->data.elf64.shdr[i].sh_offset == src_offset) {
                elf->data.elf64.shdr[i].sh_size += content_size;
                sec_i = i;
                break;
            }
        }

        /* Determine whether object is within an independent PT_LOAD segment */
        /* 判断是否在一个独立的PT_LOAD段内 */
        seg_i = is_isolated_seg(elf, src_offset);
        if (seg_i != FALSE) {
            PRINT_VERBOSE("object is in an isolated PT_LOAD segment, expand a segment\n");
            // if enough space, just expand it
            if (src_size + content_size <= elf->data.elf64.phdr[seg_i].p_filesz) {
                PRINT_VERBOSE("enough space in the segment, just resize it\n");
                memcpy((char *)elf->mem + src_offset + src_size, add_content, content_size);
                return seg_i;
            } else if (expand_segment_load(elf, seg_i, content_size, &offset, &addr) == NO_ERR) {
                PRINT_VERBOSE("not enough space in the segment, expand the segment\n");
                memcpy((char *)elf->mem + offset, add_content, content_size);
            } else {
                return ERR_EXPAND_SEG;
            }
        } else {
            PRINT_VERBOSE("object is not in an isolated PT_LOAD segment, add a new segment\n");
            if (add_segment_auto(elf, src_size + content_size, &seg_i) != NO_ERR) {
                return ERR_ADD_SEG;
            }

            uint64_t dst_offset = elf->data.elf64.phdr[seg_i].p_offset;
            void *src = (void *)elf->mem + src_offset;
            void *dst = (void *)elf->mem + dst_offset;

            if (copy_data(src, dst, src_size) == NO_ERR) {
                memcpy((char *)dst + src_size, add_content, content_size);
            } else {
                return ERR_COPY;
            }
            
            // update section offset and address
            elf->data.elf64.shdr[sec_i].sh_offset = dst_offset;
            elf->data.elf64.shdr[sec_i].sh_addr = elf->data.elf64.phdr[seg_i].p_vaddr;
        }
        reinit(elf);
        return seg_i;
    } else {
        return ERR_ELF_CLASS;
    }
}

/**
 * @brief 增加一个段
 * Add a segment
 * @param elf Elf custom structure
 * @param size segment size
 * @param added_index segment index
 * @return error code
 */
int add_segment_common(Elf *elf, size_t size, uint64_t mov_pht, size_t *added_index) {
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
        for (int i = 0; i < elf->data.elf32.ehdr->e_phnum; i++) {
            switch (elf->data.elf32.phdr[i].p_type)
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
        
        if (!is_break && !mov_pht) {
            return ERR_SEG_NOTFOUND;
        }

        start_offset = elf->data.elf32.phdr[last_load].p_offset + elf->data.elf32.phdr[last_load].p_filesz;
        start_addr = elf->data.elf32.phdr[last_load].p_vaddr + elf->data.elf32.phdr[last_load].p_memsz;
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
            return ERR_ELF_TYPE;
        }

        actual_size = align_page(size);
        if (mov_pht) {
            pht_dst_size = (elf->data.elf32.ehdr->e_phnum + 1) * elf->data.elf32.ehdr->e_phentsize;
            pht_src_size = elf->data.elf32.ehdr->e_phnum * elf->data.elf32.ehdr->e_phentsize;
            pht_offset = actual_offset + align_page(size);
            pht_addr = actual_addr + align_page(size);
            actual_size = align_page(size) + align_page(pht_dst_size);
            *added_index = elf->data.elf32.ehdr->e_phnum;
        }
        
        actual_diff = actual_offset - start_offset + actual_size;

        /* ----------------------------0.expand file---------------------------- */
        size_t new_size = elf->size + actual_diff;
        ftruncate(elf->fd, new_size);
        void* new_map = mremap(elf->mem, elf->size, new_size, MREMAP_MAYMOVE);
        if (new_map == MAP_FAILED) {
            return ERR_MEM;
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
        for (int i = 0; i < elf->data.elf32.dyn_count; i++) {
            uint32_t value = elf->data.elf32.dyn[i].d_un.d_ptr;
            uint32_t tag = elf->data.elf32.dyn[i].d_tag;
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
                        elf->data.elf32.dyn[i].d_un.d_ptr += actual_size;
                        break;
                    
                    default:
                        break;
                }
            }
        }

        /* mov program header table */
        if (mov_pht) {
            void *src = elf->mem + elf->data.elf32.ehdr->e_phoff;
            void *dst = elf->mem + pht_offset;
            if (copy_data(src, dst, pht_src_size) == NO_ERR) {
                elf->data.elf32.ehdr->e_phnum++;
                elf->data.elf32.ehdr->e_phoff = pht_offset;
                reinit(elf);
                for (int i = 0; i < elf->data.elf32.ehdr->e_phnum; i++) {
                    if (elf->data.elf32.phdr[i].p_type = PT_PHDR) {
                        elf->data.elf32.phdr[i].p_offset = pht_offset;
                        elf->data.elf32.phdr[i].p_vaddr = pht_addr;
                        elf->data.elf32.phdr[i].p_paddr = pht_addr;
                        elf->data.elf32.phdr[i].p_filesz = pht_dst_size;
                        elf->data.elf32.phdr[i].p_memsz = pht_dst_size;
                        break;
                    }
                }

            } else {
                return ERR_COPY;
            }
        }

        elf->data.elf32.phdr[*added_index].p_offset = actual_offset;
        elf->data.elf32.phdr[*added_index].p_vaddr = actual_addr;
        elf->data.elf32.phdr[*added_index].p_paddr = actual_addr;
        elf->data.elf32.phdr[*added_index].p_filesz = actual_size;
        elf->data.elf32.phdr[*added_index].p_memsz = actual_size;
        elf->data.elf32.phdr[*added_index].p_type = PT_LOAD;
        elf->data.elf32.phdr[*added_index].p_align = ONE_PAGE;
        elf->data.elf32.phdr[*added_index].p_flags = PF_R | PF_W;
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
        
        if (!is_break && !mov_pht) {
            return ERR_SEG_NOTFOUND;
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
            return ERR_ELF_TYPE;
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
            return ERR_MEM;
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
        for (int i = 0; i < elf->data.elf64.dyn_count; i++) {
            uint64_t value = elf->data.elf64.dyn[i].d_un.d_ptr;
            uint64_t tag = elf->data.elf64.dyn[i].d_tag;
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
                        elf->data.elf64.dyn[i].d_un.d_ptr += actual_size;
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
            if (copy_data(src, dst, pht_src_size) == NO_ERR) {
                elf->data.elf64.ehdr->e_phnum++;
                elf->data.elf64.ehdr->e_phoff = pht_offset;
                reinit(elf);
                for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
                    if (elf->data.elf64.phdr[i].p_type = PT_PHDR) {
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
        elf->data.elf64.phdr[*added_index].p_flags = PF_R | PF_W;
    } else {
        return ERR_ELF_CLASS;
    }

    reinit(elf);
    return NO_ERR;
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
int add_segment_easy(Elf *elf, size_t size, size_t *added_index) {
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
int add_segment_difficult(Elf *elf, size_t size, size_t *added_index) {
    return add_segment_common(elf, size, 1, added_index);
}

/**
 * @brief 增加一个段，自动选择增加方式
 * Add a segment, automatically choose the addition method
 * @param elf Elf custom structure
 * @param size segment size
 * @param added_index segment index
 * @return error code
 */
int add_segment_auto(Elf *elf, size_t size, uint64_t *added_index) {
     if (elf->class == ELFCLASS32) {
        // if there is PT_NOTE or PT_NULL segment, we can use it
        for (int i = 0; i < elf->data.elf32.ehdr->e_phnum; i++) {
            if (elf->data.elf32.phdr[i].p_type == PT_NOTE || elf->data.elf32.phdr[i].p_type == PT_NULL) {
                PRINT_VERBOSE("found PT_NOTE or PT_NULL segment, use easy method to add segment\n");
                return add_segment_easy(elf, size, added_index);
            }
        }
        // otherwise, we need to move PHT
        PRINT_VERBOSE("not found PT_NOTE or PT_NULL segment, use difficult method to add segment\n");
        return add_segment_difficult(elf, size, added_index);
    } else if (elf->class == ELFCLASS64) {
        // if there is PT_NOTE or PT_NULL segment, we can use it
        for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
            if (elf->data.elf64.phdr[i].p_type == PT_NOTE || elf->data.elf64.phdr[i].p_type == PT_NULL) {
                PRINT_VERBOSE("found PT_NOTE or PT_NULL segment, use easy method to add segment\n");
                return add_segment_easy(elf, size, added_index);
            }
        }
        // otherwise, we need to move PHT
        PRINT_VERBOSE("not found PT_NOTE or PT_NULL segment, use difficult method to add segment\n");
        return add_segment_difficult(elf, size, added_index);
    } else {
        return ERR_ELF_CLASS;
    }
}

/**
 * @brief 增加一个段，并用文件填充内容
 * add a paragraph and fill in the content with a file
 * @param elf Elf custom structure 
 * @param type segment type
 * @param file file content
 * @return error code
 */
int add_segment_with_file(Elf *elf, int type, char *file) {
    int err = 0;
    uint64_t i = 0;
    char* buffer = NULL;
    int file_size = file_to_mem(file, &buffer);
    if (file_size > 0) {
        PRINT_DEBUG("file size: 0x%x\n", file_size);
    } else {
        PRINT_ERROR("error: Unable to read file %s\n", file);
        goto ERR_EXIT;
    }

    err = add_segment_auto(elf, file_size, &i);
    if (err != NO_ERR) {
        PRINT_DEBUG("add segment error: %d\n", err);
        goto ERR_EXIT;
    }
    
    if (elf->class == ELFCLASS32) {
        memcpy(elf->mem + elf->data.elf32.phdr[i].p_offset, buffer, file_size);
    } else if (elf->class == ELFCLASS64) {
        memcpy(elf->mem + elf->data.elf64.phdr[i].p_offset, buffer, file_size);
    } else {
        PRINT_ERROR("error: Unsupported ELF class %d\n", elf->class);
        goto ERR_EXIT;
    }
    
    free(buffer);
    return i;

ERR_EXIT:
    free(buffer);
    return ERR_ADD_SEG;
}

/**
 * @brief 增加一个段
 * Add a dynamic segment
 * @param elf Elf custom structure
 * @param type dynamic segment type
 * @param value dynamic segment value
 * @return error code
 */
int add_dynseg_difficult(Elf *elf, int type, uint64_t value) {
    if (elf->class == ELFCLASS32) {
        ;
    } else if (elf->class == ELFCLASS64) {
        size_t new_size = elf->data.elf64.dyn_count * sizeof(Elf64_Dyn) + sizeof(Elf64_Dyn);
        size_t old_size = elf->data.elf64.dyn_count * sizeof(Elf64_Dyn);
        int dyn_sec_i = get_section_index_by_name(elf, ".dynamic");
        if (dyn_sec_i < 0) {
            return dyn_sec_i;
        }

        size_t dyn_seg_i = 0;
        get_segment_index_by_type(elf, PT_DYNAMIC, &dyn_seg_i);
        if (dyn_seg_i < 0) {
            return dyn_seg_i;
        }

        uint64_t added_i = 0;
        int err = add_segment_auto(elf, new_size, &added_i);
        if (err != NO_ERR) {
            PRINT_ERROR("add segment error: %d\n", err);
            return err;
        }

        // check is isolated dynamic segment
        int index = is_isolated_dynamic(elf);
        if (index != FALSE && elf->data.elf64.phdr[index].p_memsz >= new_size) {
            elf->data.elf64.shdr[dyn_sec_i].sh_size = new_size;
            elf->data.elf64.phdr[dyn_seg_i].p_memsz = new_size;
            elf->data.elf64.dyn[elf->data.elf64.dyn_count].d_tag = type;
            elf->data.elf64.dyn[elf->data.elf64.dyn_count].d_un.d_ptr = value;
        }

        // move old dynamic segment data to new segment
        else {
            elf->data.elf64.shdr[dyn_sec_i].sh_offset = elf->data.elf64.phdr[added_i].p_offset;
            elf->data.elf64.shdr[dyn_sec_i].sh_addr = elf->data.elf64.phdr[added_i].p_vaddr;
            elf->data.elf64.shdr[dyn_sec_i].sh_size = new_size;
            elf->data.elf64.phdr[dyn_seg_i].p_offset = elf->data.elf64.phdr[added_i].p_offset;
            elf->data.elf64.phdr[dyn_seg_i].p_vaddr = elf->data.elf64.phdr[added_i].p_vaddr;
            elf->data.elf64.phdr[dyn_seg_i].p_filesz = new_size;
            elf->data.elf64.phdr[dyn_seg_i].p_memsz = new_size; 
        }

    } else {
        return ERR_ELF_CLASS;
    }
    reinit(elf);
    return NO_ERR;
}
/**
 * @brief 增加一个段，自动选择增加方式
 * Add a segment, automatically choose the addition method
 * @param elf Elf custom structure
 * @param type dynamic segment type
 * @param value dynamic segment value
 * @return error code
 */
int add_dynseg_auto(Elf *elf, int type, uint64_t value) {
    if (elf->class == ELFCLASS32) {
        int index = get_dynseg_index_by_tag(elf, DT_NULL);
        if (index == ERR_DYN_NOTFOUND) {
            return add_dynseg_difficult(elf, type, value);
        } else {
            elf->data.elf32.dyn[index].d_tag = type;
            elf->data.elf32.dyn[index].d_un.d_ptr = value;
        }
    } else if (elf->class == ELFCLASS64) {
        int index = get_dynseg_index_by_tag(elf, DT_NULL);
        if (index == ERR_DYN_NOTFOUND) {
            return add_dynseg_difficult(elf, type, value);
        } else {
            elf->data.elf64.dyn[index].d_tag = type;
            elf->data.elf64.dyn[index].d_un.d_ptr = value;
        }
        
    } else {
        return ERR_ELF_CLASS;
    }
    return NO_ERR;
}

/**
 * @brief 增加一个节表项
 * Add a section entry
 * @param elf Elf custom structure
 * @param added_index section index
 * @return error code
 */
int add_section_entry(Elf *elf, uint64_t *added_index) {
    if (elf->class == ELFCLASS32) {
        size_t new_size = elf->size + elf->data.elf32.ehdr->e_shentsize;
        ftruncate(elf->fd, new_size);
        void* new_map = mremap(elf->mem, elf->size, new_size, MREMAP_MAYMOVE);
        if (new_map == MAP_FAILED) {
            return ERR_MEM;
        } else {
            // reinit custom elf structure
            elf->mem = new_map;
            elf->size = new_size;
            reinit(elf);
        }
        elf->data.elf32.ehdr->e_shnum++;
        *added_index = elf->data.elf32.ehdr->e_shnum - 1;
        return NO_ERR;
    } else if (elf->class == ELFCLASS64) {
        size_t new_size = elf->size + elf->data.elf64.ehdr->e_shentsize;
        ftruncate(elf->fd, new_size);
        void* new_map = mremap(elf->mem, elf->size, new_size, MREMAP_MAYMOVE);
        if (new_map == MAP_FAILED) {
            return ERR_MEM;
        } else {
            // reinit custom elf structure
            elf->mem = new_map;
            elf->size = new_size;
            reinit(elf);
        }
        elf->data.elf64.ehdr->e_shnum++;
        *added_index = elf->data.elf64.ehdr->e_shnum - 1;
        return NO_ERR;
    } else {
        return ERR_ELF_CLASS;
    }
}

/**
 * @brief 增加一个节，自动选择增加方式
 * Add a section, automatically choose the addition method
 * @param elf Elf custom structure
 * @param size section size
 * @param name section name
 * @param added_index section index
 * @return error code
 */
int add_section_auto(Elf *elf, size_t size, const char *name, uint64_t *added_index) {
    uint64_t added_seg_i = 0;
    int err = add_segment_auto(elf, size, &added_seg_i);
    if (err != NO_ERR) {
        PRINT_ERROR("add segment error: %d\n", err);
        return err;
    }

    err = add_section_entry(elf, added_index);
    if (err != NO_ERR) {
        return err;
    }

    uint64_t name_offset = 0;
    err = add_shstr_name(elf, name, &name_offset);;
    if (err != NO_ERR) {
        return err;
    }

    if (elf->class == ELFCLASS32) {
        elf->data.elf32.shdr[*added_index].sh_name = name_offset;
        elf->data.elf32.shdr[*added_index].sh_offset = elf->data.elf32.phdr[added_seg_i].p_offset;
        elf->data.elf32.shdr[*added_index].sh_size = elf->data.elf32.phdr[added_seg_i].p_filesz;
        return NO_ERR;
    } else if (elf->class == ELFCLASS64) {
        elf->data.elf64.shdr[*added_index].sh_name = name_offset;
        elf->data.elf64.shdr[*added_index].sh_offset = elf->data.elf64.phdr[added_seg_i].p_offset;
        elf->data.elf64.shdr[*added_index].sh_size = elf->data.elf64.phdr[added_seg_i].p_filesz;
        return NO_ERR;
    } else {
        return ERR_ELF_CLASS;
    }
}

/**
 * @brief 增加一个.dynsym table条目
 * add a dynamic symbol stable item
 * @param elf Elf custom structure
 * @param name dynamic symbol name
 * @param value dynamic symbol address
 * @param code_size func size
 * @return int error code
 */
int add_dynsym_entry(Elf *elf, char *name, uint64_t value, size_t code_size) {
    size_t old_size, new_size;
    size_t dynstr_size;
    uint64_t old_offset;
    uint64_t seg_addr;
    int seg_i;
    int err;

    // 1. expand .dynstr section
    PRINT_INFO("1. add a new segment for .dynstr entry\n");
    dynstr_size = get_section_size_by_name(elf, ".dynstr");
    uint64_t name_offset = 0;
    err = add_dynstr_name(elf, name, &name_offset);
    if (err != NO_ERR) {
        PRINT_ERROR("add dynstr name error :%d\n", err);
        return err;
    }

    // 2. expand .dynsym section
    PRINT_INFO("2. add a new segment for .dynsym entry\n");
    old_size = get_section_size_by_name(elf, ".dynsym");
    old_offset = get_section_offset_by_name(elf, ".dynsym");
    if (elf->class == ELFCLASS32) {
        new_size = old_size + sizeof(Elf32_Sym);
        Elf32_Sym sym;
        sym.st_value = value;
        sym.st_info = ELF32_ST_INFO(STB_GLOBAL, STT_FUNC);
        sym.st_other = STV_DEFAULT;
        sym.st_name = dynstr_size;
        sym.st_size = code_size;
        seg_i = expand_segment_content(elf, old_offset, old_size, (void *)&sym, sizeof(Elf32_Sym));
        seg_addr = elf->data.elf32.phdr[seg_i].p_vaddr;
    } else if (elf->class == ELFCLASS64) {
        new_size = old_size + sizeof(Elf64_Sym);
        Elf64_Sym sym;
        sym.st_value = value;
        sym.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
        sym.st_other = STV_DEFAULT;
        sym.st_name = dynstr_size;
        sym.st_size = code_size;
        seg_i = expand_segment_content(elf, old_offset, old_size, (void *)&sym, sizeof(Elf64_Sym));
        seg_addr = elf->data.elf64.phdr[seg_i].p_vaddr;
    } else {
        return ERR_ELF_CLASS;
    }
 
    if (seg_i < 0) {
        PRINT_ERROR("expand .dynsym section error\n");
        return seg_i;
    }
    
    // 3. set phdr
    PRINT_INFO("3. set phdr for DT_SYMTAB segment\n");
    err = set_dynseg_value_by_tag(elf, DT_SYMTAB, seg_addr);
    if (err != NO_ERR) {
        PRINT_ERROR("set DT_SYMTAB error\n");
        return err;
    }
    
    // 4. compute hash table
    PRINT_INFO("4. compute hash table\n");
    err =  refresh_hash_table(elf);
    if (err != NO_ERR) {
        PRINT_ERROR("set hash table error\n");
        return err;
    }
    
    // 5. change exe file to dynamic library
    PRINT_INFO("5. change exe file to dynamic library\n");
    err = set_dynseg_value_by_tag(elf, DT_FLAGS_1, DF_1_NOW);
    if (err != NO_ERR) {
        PRINT_ERROR("set DT_FLAGS_1 error\n");
        return err;
    }
    
    return err;
}

// compute symbol hash
static uint32_t dl_new_hash(const char* name) {
    uint32_t h = 5381;

    for (unsigned char c = *name; c != '\0'; c = *++name) {
        h = h * 33 + c;
    }

    return h & 0xffffffff;
}

/**
 * @brief 添加一个.gnu.hash节
 * Add a .gnu.hash section
 * @param elf Elf custom structure
 * @param content .gnu.hash content
 * @param size .gnu.hash size
 * @return error code
 */
static int add_a_gnuhash(Elf *elf, char *content, uint64_t size) {
    uint64_t added_index = 0;
    int err = 0;
    if (elf->class == ELFCLASS32) {
        err = add_segment_auto(elf, size, &added_index);
        if (err != NO_ERR) {
            PRINT_ERROR("add segment error: %d\n", err);
            return err;
        }

        PRINT_DEBUG("Adding .gnu.hash at segment index: %lu\n", added_index);
        memcpy(elf->mem + elf->data.elf32.phdr[added_index].p_offset, content, size);
        set_section_offset_by_name(elf, ".gnu.hash", elf->data.elf32.phdr[added_index].p_offset);
        set_section_size_by_name(elf, ".gnu.hash", elf->data.elf32.phdr[added_index].p_filesz);
        set_section_addr_by_name(elf, ".gnu.hash", elf->data.elf32.phdr[added_index].p_vaddr);
        err = set_dynseg_value_by_tag(elf, DT_GNU_HASH, elf->data.elf32.phdr[added_index].p_vaddr);
        if (err != NO_ERR) {
            PRINT_ERROR("set DT_GNU_HASH error\n");
            return err;
        }
    } else if (elf->class == ELFCLASS64) { 
        err = add_segment_auto(elf, size, &added_index);
        if (err != NO_ERR) {
            PRINT_ERROR("add segment error: %d\n", err);
            return err;
        }

        PRINT_DEBUG("Adding .gnu.hash at segment index: %lu\n", added_index);
        memcpy(elf->mem + elf->data.elf64.phdr[added_index].p_offset, content, size);
        set_section_offset_by_name(elf, ".gnu.hash", elf->data.elf64.phdr[added_index].p_offset);
        set_section_size_by_name(elf, ".gnu.hash", elf->data.elf64.phdr[added_index].p_filesz);
        set_section_addr_by_name(elf, ".gnu.hash", elf->data.elf64.phdr[added_index].p_vaddr);
        err = set_dynseg_value_by_tag(elf, DT_GNU_HASH, elf->data.elf64.phdr[added_index].p_vaddr);
        if (err != NO_ERR) {
            PRINT_ERROR("set DT_GNU_HASH error\n");
            return err;
        }
    } else {
        return ERR_ELF_CLASS;
    }

    return NO_ERR;
}

/**
 * @brief 刷新ELF文件的.gnu.hash节
 * Refresh the .gnu.hash section of ELF file
 * @param elf Elf custom structure
 * @return error code
 */
int refresh_hash_table(Elf *elf) {
    size_t src_size = 0;    // source .gnu.hash size
    size_t size = 0;        // new .gnu.hash size
    uint64_t src_offset;    // source .gnu.hash offset
    int seg_i = 0;
    int ret = 0;
    int string_count = 0;
    char **string = NULL;
    size_t C = 0;
    src_offset = get_section_offset_by_name(elf, ".gnu.hash");
    src_size =  get_section_size_by_name(elf, ".gnu.hash");
    if (src_offset == ERR_SEC_NOTFOUND || src_size == ERR_SEC_NOTFOUND) {
        PRINT_ERROR(".gnu.hash section not found\n");
        return ERR_SEC_NOTFOUND;
    }

    if (src_size < sizeof(gnuhash_t)) {
        PRINT_ERROR(".gnu.hash section size is too small\n");
        return ERR_OUT_OF_BOUNDS;
    }

    gnuhash_t *src_gnuhash = malloc(sizeof(gnuhash_t));
    if (!src_gnuhash) {
        return ERR_MEM;
    }

    /* store dynstr name */
    if (elf->class == ELFCLASS64) {
        string_count = elf->data.elf64.dynsym_count;
        string = (char **)malloc(sizeof(char*) * string_count);
        for (int i = 0; i < string_count; ++i) {
            string[i] = (char *)elf->mem + elf->data.elf64.dynstrtab->sh_offset + elf->data.elf64.dynsym_entry[i].st_name;
        }
    } else if (elf->class == ELFCLASS32) {
        string_count = elf->data.elf32.dynsym_count;
        string = (char **)malloc(sizeof(char*) * string_count);
        for (int i = 0; i < string_count; ++i) {
            string[i] = (char *)elf->mem + elf->data.elf32.dynstrtab->sh_offset + elf->data.elf32.dynsym_entry[i].st_name;
        }
    } else {
        free(src_gnuhash);
        return ERR_ELF_CLASS;
    }
    

    memset(src_gnuhash, 0, sizeof(gnuhash_t));
    memcpy(src_gnuhash, elf->mem + src_offset, sizeof(gnuhash_t));

    size = 4 * sizeof(uint32_t) +                           // header
            src_gnuhash->maskbits * 8 +                     // bloom filters
            src_gnuhash->nbuckets * sizeof(uint32_t) +      // buckets
            (string_count- src_gnuhash->symndx) * sizeof(uint32_t); // hash values

    gnuhash_t *raw_gnuhash = malloc(size);
    if (!raw_gnuhash) {
        free(string);
        free(src_gnuhash);
        return ERR_MEM;
    }
    memset(raw_gnuhash, 0, size);
    
    /* set header */
    raw_gnuhash->nbuckets = src_gnuhash->nbuckets;
    raw_gnuhash->symndx =  src_gnuhash->symndx;
    raw_gnuhash->maskbits =  src_gnuhash->maskbits;
    raw_gnuhash->shift =  src_gnuhash->shift;

    /* compute bloom filter */
    size_t bloom_size = sizeof(uint64_t) * raw_gnuhash->maskbits;
    uint64_t *bloom_filters = malloc(bloom_size);
    if (!bloom_filters) {
        free(string);
        free(src_gnuhash);
        free(raw_gnuhash);
        return ERR_MEM;
    }
    memset(bloom_filters, 0, bloom_size);
    if (elf->class == ELFCLASS32) {
        C = 32;          // 32 for ELF, 64 for ELF64
        for (size_t i = raw_gnuhash->symndx; i < string_count; ++i) {
            PRINT_DEBUG("Dealing with symbol %s\n", string[i]);
            const uint32_t hash = dl_new_hash(string[i]);
            const size_t pos = (hash / C) & (raw_gnuhash->maskbits - 1);
            uint32_t tmp = 1;   // 32 for ELF, 64 for ELF64
            uint32_t V = (tmp << (hash % C)) |
                    (tmp << ((hash >> raw_gnuhash->shift) % C));
            bloom_filters[pos] |= V;
        }
    }
        
    else if (elf->class == ELFCLASS64) {
        C = 64;          // 32 for ELF, 64 for ELF64
        for (size_t i = raw_gnuhash->symndx; i < string_count; ++i) {
            PRINT_DEBUG("Dealing with symbol %s\n", string[i]);
            const uint32_t hash = dl_new_hash(string[i]);
            const size_t pos = (hash / C) & (raw_gnuhash->maskbits - 1);
            uint64_t tmp = 1;   // 32 for ELF, 64 for ELF64
            uint64_t V = (tmp << (hash % C)) |
                    (tmp << ((hash >> raw_gnuhash->shift) % C));
            bloom_filters[pos] |= V;
        }
    }
        

    for (size_t idx = 0; idx < raw_gnuhash->maskbits; ++idx) {
        PRINT_DEBUG("Bloom filter [%d]: 0x%x\n", idx, bloom_filters[idx]);
    }

    void *bloom_filters_raw = raw_gnuhash->buckets;
    memcpy(bloom_filters_raw, bloom_filters, bloom_size);

    /* set buckets */
    int previous_bucket = -1;
    size_t hash_value_idx = 0;
    size_t buckets_size = sizeof(uint32_t) * raw_gnuhash->nbuckets;
    size_t hash_chain_size = sizeof(uint32_t) * (string_count - raw_gnuhash->symndx);
    uint32_t *buckets = malloc(buckets_size);
    uint32_t *hash_chain = malloc(hash_chain_size);
    memset(buckets, 0, buckets_size);
    memset(hash_chain, 0, hash_chain_size);

    for (size_t i = raw_gnuhash->symndx; i < string_count; ++i) {
        PRINT_DEBUG("Dealing with symbol %s\n", string[i]);
        const uint32_t hash = dl_new_hash(string[i]);
        int bucket = hash % raw_gnuhash->nbuckets;

        if (bucket < previous_bucket) {
            PRINT_ERROR("Previous bucket is greater than the current one (%s < %s)",
                    bucket, previous_bucket);
            return ERR_OUT_OF_BOUNDS;
        }

        if (bucket != previous_bucket) {
            buckets[bucket] = i;
            previous_bucket = bucket;
            if (hash_value_idx > 0) {
                hash_chain[hash_value_idx - 1] |= 1;
            }
        }

        hash_chain[hash_value_idx] = hash & ~1;
        ++hash_value_idx;
    }

    if (hash_value_idx > 0) {
        hash_chain[hash_value_idx - 1] |= 1;
    }

    uint32_t *buckets_raw = &bloom_filters_raw[raw_gnuhash->maskbits];
    memcpy(buckets_raw, buckets, buckets_size);
    uint32_t *hash_chain_raw = &buckets_raw[raw_gnuhash->nbuckets];
    memcpy(hash_chain_raw, hash_chain, hash_chain_size);

    if (size > src_size) {
        /* add hash table*/
        PRINT_VERBOSE("add new .gnu.hash section\n");
        seg_i = add_a_gnuhash(elf, (char *)raw_gnuhash, size);
    } else {
        /* update hash table*/
        PRINT_VERBOSE("update .gnu.hash section\n");
        memcpy(elf->mem + src_offset, raw_gnuhash, size);
    }

    free(string);
    free(hash_chain);
    free(buckets);
    free(bloom_filters);
    free(raw_gnuhash);
    free(src_gnuhash);
    return NO_ERR;
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
        return ERR_ELF_CLASS;
    }
}

/**
 * @brief 从ELF文件中删除数据
 * Delete data from ELF file
 * @param elf Elf custom structure
 * @param offset delete start offset
 * @param size delete size
 * @return error code
 */
static int delete_data(Elf *elf, uint64_t offset, size_t size) {
    if (offset + size > elf->size) {
        return ERR_ARGS;
    }

    // memmove(elf->mem + offset, elf->mem + offset + size, elf->size - offset - size);
    void *dst = elf->mem + offset;
    void *src = elf->mem + offset + size;
    uint64_t move_size = elf->size - offset - size;
    if (copy_data(src, dst, move_size) != NO_ERR) {
        return ERR_COPY;
    }
    size_t new_size = elf->size - size;
    ftruncate(elf->fd, new_size);
    void* new_map = mremap(elf->mem, elf->size, new_size, MREMAP_MAYMOVE);
    if (new_map == MAP_FAILED) {
        return ERR_MEM;
    } else {
        // reinit custom elf structure
        elf->mem = new_map;
        elf->size = new_size;
        reinit(elf);
    }

    return NO_ERR;
}

/**
 * @brief 通过节索引删除节
 * Delete section by index
 * @param elf Elf custom structure
 * @param index section index
 * @return error code
 */
int delete_section_by_index(Elf *elf, uint64_t index) {
    if (elf->class == ELFCLASS32) {
        ;
    } else if (elf->class == ELFCLASS64) {
        uint64_t offset = elf->data.elf64.shdr[index].sh_offset;
        size_t size = elf->data.elf64.shdr[index].sh_size;

        /* 1. set new shstrtab offset */
        int shstr_idx = elf->data.elf64.ehdr->e_shstrndx;
        for (int i = elf->data.elf64.ehdr->e_shnum - 1; i > index; i--) {
            elf->data.elf64.shdr[i].sh_offset -= size;
        }

        /* 2. set new section header table offset */
        elf->data.elf64.ehdr->e_shoff -= size;
        
        /* 3. delete section */
        delete_data(elf, offset, size);

        /* 4. delete section header table entry */
        elf->data.elf64.ehdr->e_shnum--;
        if (index < shstr_idx) {
            elf->data.elf64.ehdr->e_shstrndx--;
        }
        
        uint64_t shdr_offset = elf->data.elf64.ehdr->e_shoff + index * sizeof(Elf64_Shdr);
        delete_data(elf, shdr_offset, sizeof(Elf64_Shdr));
    } else {
        return ERR_ELF_CLASS;
    }
    return NO_ERR;
}

/**
 * @brief 通过节名称删除节
 * Delete section by name
 * @param elf Elf custom structure
 * @param name section name
 * @return error code
 */
int delete_section_by_name(Elf *elf, const char *name) {
    uint64_t index = get_section_index_by_name(elf, name);
    if (index == ERR_SEC_NOTFOUND) {
        return ERR_SEC_NOTFOUND;
    }

    return delete_section_by_index(elf, index);
}

/**
 * @brief 删除所有节头表
 * Delete all section header table
 * @param elf Elf custom structure
 * @return error code
 */
int delete_all_shdr(Elf *elf) {
    int err = 0;
    if (elf->class == ELFCLASS32) {
        // delete .shstrtab section
        err = delete_section_by_name(elf, ".shstrtab");
        if (err != NO_ERR) {
            return err;
        }
        elf->data.elf32.ehdr->e_shstrndx = 0;
        
        // delete all section header table
        err = delete_data(elf, elf->data.elf32.ehdr->e_shoff, elf->data.elf32.ehdr->e_shnum * sizeof(Elf32_Shdr));
        if (err != NO_ERR) {
            return err;
        }
        elf->data.elf32.ehdr->e_shoff = 0;
        elf->data.elf32.ehdr->e_shnum = 0;
    } else if (elf->class == ELFCLASS64) {
        // delete .shstrtab section
        err = delete_section_by_name(elf, ".shstrtab");
        if (err != NO_ERR) {
            return err;
        }
        elf->data.elf64.ehdr->e_shstrndx = 0;
        
        // delete all section header table
        err = delete_data(elf, elf->data.elf64.ehdr->e_shoff, elf->data.elf64.ehdr->e_shnum * sizeof(Elf64_Shdr));
        if (err != NO_ERR) {
            return err;
        }
        elf->data.elf64.ehdr->e_shoff = 0;
        elf->data.elf64.ehdr->e_shnum = 0;
        
    } else {
        return ERR_ELF_CLASS;
    }
    return NO_ERR;
}

/**
 * @brief 删除不必要的节
 * delelet unnecessary section, such as, .comment .symtab .strtab section
 * @param elf_name elf file name
 * @return int error code {-1:error,0:sucess}
 */
int strip(Elf *elf) {
    int err = 0;
    bool flag = false;
    if (elf->class == ELFCLASS32) {
        for( int i = elf->data.elf32.ehdr->e_shnum - 1; i >= 0; i--) {
            err = is_isolated_section_by_index(elf, i, &flag);
            if (err != NO_ERR) {
                PRINT_ERROR("err: is_isolated_section_by_index\n");
                return err;
            }
            if (flag && elf->data.elf32.shdr[i].sh_type != SHT_NULL && strcmp(get_section_name(elf, i), ".shstrtab") != 0) {
                PRINT_VERBOSE("delete: %d %s\n", i, get_section_name(elf, i));
                delete_section_by_index(elf, i);
            }
        }
    } else if (elf->class == ELFCLASS64) {
        for (int i = elf->data.elf64.ehdr->e_shnum - 1; i >= 0; i--) {
            err = is_isolated_section_by_index(elf, i, &flag);
            if (err != NO_ERR) {
                PRINT_ERROR("err: is_isolated_section_by_index\n");
                return err;
            }
            if (flag && elf->data.elf64.shdr[i].sh_type != SHT_NULL && strcmp(get_section_name(elf, i), ".shstrtab") != 0) {
                PRINT_VERBOSE("delete: %d %s\n", i, get_section_name(elf, i));
                delete_section_by_index(elf, i);
            }
        }
    } else {
        return ERR_ELF_CLASS;
    }

   return NO_ERR;
}

/**
 * @brief 为二进制文件添加ELF头
 * Add ELF header to binary file
 * @param bin binary file path
 * @param arch architecture
 * @param class ELF class(32/64)
 * @param endian endianess(little/big)
 * @param base_addr base address
 * @return int error code {-1:error,0:sucess}
 */
int add_elf_header(uint8_t *bin, uint8_t *arch, uint32_t class, uint8_t *endian, uint64_t base_addr){
    int fd;
    struct stat st;
    uint8_t *bin_map;
    uint8_t *new_bin_map;
    uint32_t new_size;

    fd = open(bin, O_RDONLY);
    if (fd < 0) {
        return ERR_FILE_OPEN;
    }

    if (fstat(fd, &st) < 0) {
        return ERR_FILE_STAT;
    }

    bin_map = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (bin_map == MAP_FAILED) {
        return ERR_MEM;
    }

    /* 32bit */
    if (class == 32) {
        /*****| ELF Header | Phdr*2 | Shdr | padding | data | *****/
        if (base_addr == 0) {
            base_addr = 0x08048000;
        }
        new_size = 0x1000 + st.st_size; 
        new_bin_map = malloc(new_size);
        if (new_bin_map < 0) {
            return -1;
        }
        memset(new_bin_map, 0, new_size);

        Elf32_Ehdr ehdr = {
            .e_ident = 0x0,
            .e_type = ET_EXEC,
            .e_machine = arch_to_mach(arch, class),
            .e_version = EV_CURRENT,
            .e_entry = base_addr + 0x1000,
            .e_phoff = sizeof(Elf32_Ehdr),
            .e_shoff = sizeof(Elf32_Ehdr) * 2 + sizeof(Elf32_Phdr) * 2,
            .e_flags = 0,
            .e_ehsize = sizeof(Elf32_Ehdr),
            .e_phentsize = sizeof(Elf32_Phdr),
            .e_phnum = 2,
            .e_shentsize = sizeof(Elf32_Shdr),
            .e_shnum = 1,
            .e_shstrndx = 0,
        };
        if (ehdr.e_machine == EM_ARM) {
            ehdr.e_flags = 0x05000200;  /* arm32 */
        }
        ehdr.e_ident[0] = '\x7f';
        ehdr.e_ident[1] = 'E';
        ehdr.e_ident[2] = 'L';
        ehdr.e_ident[3] = 'F';
        ehdr.e_ident[4] = ELFCLASS32;   /* ELF class */
        if (!strcmp(endian, "little"))
            ehdr.e_ident[5] = '\x01';      
        else if(!strcmp(endian, "big"))
            ehdr.e_ident[5] = '\x02';            
        ehdr.e_ident[6] = '\x01';       /* EI_VERSION */

        Elf32_Phdr phdr1 = {
            .p_type = PT_LOAD,
            .p_offset = 0,
            .p_vaddr = base_addr,
            .p_paddr = base_addr,
            .p_filesz = sizeof(Elf32_Ehdr) + sizeof(Elf32_Phdr) * 2 + sizeof(Elf32_Shdr) * 2,
            .p_memsz = sizeof(Elf32_Ehdr) + sizeof(Elf32_Phdr) * 2 + sizeof(Elf32_Shdr) * 2,
            .p_flags = PF_R,
            .p_align = 0x1000
        };

        Elf32_Phdr phdr2 = {
            .p_type = PT_LOAD,
            .p_offset = 0x1000,
            .p_vaddr = base_addr + 0x1000,
            .p_paddr = base_addr + 0x1000,
            .p_filesz = st.st_size,
            .p_memsz = st.st_size,
            .p_flags = PF_R | PF_W | PF_X,
            .p_align = 0x1000
        };

        Elf32_Shdr shdr = {
            .sh_name = 0x0,
            .sh_type = SHT_PROGBITS,    /* Program data */
            .sh_flags = SHF_EXECINSTR,  /* Executable */ 
            .sh_addr = base_addr + 0x1000,
            .sh_offset = 0x1000,
            .sh_size = st.st_size,      /* Section(bin) size */
            .sh_link = 0x0,
            .sh_info = 0x0,
            .sh_addralign = 4,
            .sh_entsize = 0x0
        };

        /*****| ELF Header | Phdr*2 | Shdr*2 | padding | data | *****/
        memset(new_bin_map, 0, new_size);
        memcpy(new_bin_map, &ehdr, sizeof(Elf32_Ehdr));
        memcpy(new_bin_map + sizeof(Elf32_Ehdr), &phdr1, sizeof(Elf32_Phdr));
        memcpy(new_bin_map + sizeof(Elf32_Ehdr) + sizeof(Elf32_Phdr), &phdr2, sizeof(Elf32_Phdr));
        memcpy(new_bin_map + sizeof(Elf32_Ehdr) + sizeof(Elf32_Phdr) * 2, &shdr, sizeof(Elf32_Shdr));
        memcpy(new_bin_map + 0x1000, bin_map, st.st_size);
    }

    /* 64bit */
    if (class == 64) {
        /*****| ELF Header | ELF Phdr | ELF Section header1 | ELF Section header2 |*****/
        if (base_addr == 0) {
            base_addr = 0x400000;
        }
        new_size = 0x1000 + st.st_size; 
        new_bin_map = malloc(new_size);
        if (new_bin_map < 0) {
            return -1;
        }
        memset(new_bin_map, 0, new_size);

        Elf64_Ehdr ehdr = {
            .e_ident = 0x0,
            .e_type = ET_EXEC,
            .e_machine = arch_to_mach(arch, class),
            .e_version = EV_CURRENT,
            .e_entry = base_addr + 0x1000,
            .e_phoff = sizeof(Elf64_Ehdr),
            .e_shoff = sizeof(Elf64_Ehdr) * 2 + sizeof(Elf64_Phdr) * 2,
            .e_flags = 0,
            .e_ehsize = sizeof(Elf64_Ehdr),
            .e_phentsize = sizeof(Elf64_Phdr),
            .e_phnum = 2,
            .e_shentsize = sizeof(Elf64_Shdr),
            .e_shnum = 1,
            .e_shstrndx = 0,
        };
        if (ehdr.e_machine == EM_ARM) {
            ehdr.e_flags = 0x05000200;  /* arm64?? */
        }
        ehdr.e_ident[0] = '\x7f';
        ehdr.e_ident[1] = 'E';
        ehdr.e_ident[2] = 'L';
        ehdr.e_ident[3] = 'F';
        ehdr.e_ident[4] = ELFCLASS64;   /* ELF class */
        if (!strcmp(endian, "little"))
            ehdr.e_ident[5] = '\x01';      
        else if(!strcmp(endian, "big"))
            ehdr.e_ident[5] = '\x02';            
        ehdr.e_ident[6] = '\x01';       /* EI_VERSION */

        Elf64_Phdr phdr1 = {
            .p_type = PT_LOAD,
            .p_offset = 0,
            .p_vaddr = base_addr,
            .p_paddr = base_addr,
            .p_filesz = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr) * 2 + sizeof(Elf64_Shdr) * 2,
            .p_memsz = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr) * 2 + sizeof(Elf64_Shdr) * 2,
            .p_flags = PF_R,
            .p_align = 0x1000
        };

        Elf64_Phdr phdr2 = {
            .p_type = PT_LOAD,
            .p_offset = 0x1000,
            .p_vaddr = base_addr + 0x1000,
            .p_paddr = base_addr + 0x1000,
            .p_filesz = st.st_size,
            .p_memsz = st.st_size,
            .p_flags = PF_R | PF_W | PF_X,
            .p_align = 0x1000
        };

        Elf64_Shdr shdr = {
            .sh_name = 0x0,
            .sh_type = SHT_PROGBITS,    /* Program data */
            .sh_flags = SHF_EXECINSTR,  /* Executable */ 
            .sh_addr = base_addr + 0x1000,
            .sh_offset = 0x1000,
            .sh_size = st.st_size,      /* Section(bin) size */
            .sh_link = 0x0,
            .sh_info = 0x0,
            .sh_addralign = 4,
            .sh_entsize = 0x0
        };

        /*****| ELF Header | Phdr*2 | Shdr*2 | padding | data | *****/
        memset(new_bin_map, 0, new_size);
        memcpy(new_bin_map, &ehdr, sizeof(Elf64_Ehdr));
        memcpy(new_bin_map + sizeof(Elf64_Ehdr), &phdr1, sizeof(Elf64_Phdr));
        memcpy(new_bin_map + sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr), &phdr2, sizeof(Elf64_Phdr));
        memcpy(new_bin_map + sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr) * 2, &shdr, sizeof(Elf64_Shdr));
        memcpy(new_bin_map + 0x1000, bin_map, st.st_size);
    } else {
        munmap(bin_map, st.st_size);
        free(new_bin_map);
        close(fd);
        return ERR_ELF_CLASS;
    }

    int err = mem_to_file(bin, new_bin_map, new_size, 1);
    free(new_bin_map);
    close(fd);
    return err;
}

/**
 * @brief hook外部函数
 * hook function by .got.plt
 * @param elf_name elf file name
 * @param symbol symbol name
 * @param hookfile hook function file
 * @param hook_offset hook function offset in hook file
 * @return int error code {-1:error,0:sucess}
 */
int hook_extern(Elf *elf, char *symbol, char *hookfile, uint64_t hook_offset) {
    int seg_i = 0;
    int err = -1;
    /* 1. fill new segment with .text */
    seg_i = add_segment_with_file(elf, PT_LOAD, hookfile);
    if (seg_i < 0) {
        PRINT_ERROR("add segment with file error: %d\n", seg_i);
        return seg_i;
    }

    err = set_segment_flags_by_index(elf, seg_i, 7);
    if (err != NO_ERR) {
        PRINT_ERROR("set segment flags error: %d\n", err);
        return err;
    }

    int got_index = get_section_index_by_name(elf, ".got.plt");
    if (got_index < 0) {
        PRINT_ERROR(".got.plt section not found\n");
        return ERR_SEC_NOTFOUND;
    }

    /* 2. get string table */
    char **string = NULL;
    int string_count = 0;
    err = get_dyn_string_table(elf, &string, &string_count);
    if (err != NO_ERR) {
        PRINT_ERROR("get string table error\n");
        return err;
    }
    /* 3.replace symbol with new segment address */
    // We are trying to analyze and edit the content of the section 
    // in a different way than before. Here is a case study
    
    if (elf->class == ELFCLASS32) {
        /* attention: The 32-bit program has not been tested! */
        /**
         * The interaction between PLT and GOT in 32-bit ELF is practically proven to serve the purpose of lazy binding.
         * This hook method is invalid.
         */
        int rel_index = get_section_index_by_name(elf, ".rel.plt");
        if (rel_index < 0) {
            PRINT_ERROR(".rel.plt section not found\n");
            return ERR_SEC_NOTFOUND;
        }
        Elf32_Rel *rel = (Elf32_Rel *)(elf->mem + elf->data.elf32.shdr[rel_index].sh_offset);
        PRINT_DEBUG(".rel.plt section offset: 0x%x\n", elf->data.elf32.shdr[rel_index].sh_offset);
        for (int i = 0; i < elf->data.elf32.shdr[rel_index].sh_size / sizeof(Elf32_Rel); i++) {
            int str_index = ELF32_R_SYM(rel[i].r_info);
            if (!strncmp(string[str_index], symbol, strlen(symbol))) {
                int diff = elf->data.elf32.shdr[got_index].sh_addr - elf->data.elf32.shdr[got_index].sh_offset;
                int offset = rel[i].r_offset - diff;
                PRINT_INFO("%s offset: 0x%x, new value: 0x%x\n", symbol, offset, elf->data.elf32.phdr[seg_i].p_vaddr + hook_offset);
                uint32_t *p = (uint32_t *)(elf->mem + offset);
                *p = elf->data.elf32.phdr[seg_i].p_vaddr + hook_offset;
                free(string);
                return NO_ERR;
            }
        }
    } else if (elf->class == ELFCLASS64) {
        int rela_index = get_section_index_by_name(elf, ".rela.plt");
        if (rela_index < 0) {
            PRINT_ERROR(".rela.plt section not found\n");
            return ERR_SEC_NOTFOUND;
        }
        Elf64_Rela *rela = (Elf64_Rela *)(elf->mem + elf->data.elf64.shdr[rela_index].sh_offset);
        PRINT_DEBUG(".rela.plt section offset: 0x%x\n", elf->data.elf64.shdr[rela_index].sh_offset);
        for (int i = 0; i < elf->data.elf64.shdr[rela_index].sh_size / sizeof(Elf64_Rela); i++) {
            int str_index = ELF64_R_SYM(rela[i].r_info);
            if (!strncmp(string[str_index], symbol, strlen(symbol))) {
                int diff = elf->data.elf64.shdr[got_index].sh_addr - elf->data.elf64.shdr[got_index].sh_offset;
                int offset = rela[i].r_offset - diff;
                PRINT_INFO("%s offset: 0x%x, new value: 0x%x\n", symbol, offset, elf->data.elf64.phdr[seg_i].p_vaddr + hook_offset);
                uint64_t *p = (uint64_t *)(elf->mem + offset);
                *p = elf->data.elf64.phdr[seg_i].p_vaddr + hook_offset;
                free(string);
                return NO_ERR;
            }
        }
    } else {
        free(string);
        return ERR_ELF_CLASS;
    }
    
    free(string);
    return ERR_SEG_NOTFOUND;
}

/**
 * @brief 将命令行传入的shellcode，转化为内存实际值
 * convert the shellcode passed in from the command line to the actual value in memory
 * @param sc_str input shellcode string
 * @param sc_mem output shellcode memory
 * @return error code
 */
int escaped_str_to_mem(char *sc_str, char *sc_mem) {
    if (strlen(sc_str) % 4 != 0) 
        return ERR_ARGS;
    else {
        printf("[+] shellcode: ");
        for (int i = 0; i < strlen(sc_str); i += 4) {
            unsigned char value;
            sscanf(&sc_str[i], "\\x%2hhx", &value);
            *(sc_mem+i/4) = value;
            printf("%02x ", value);
        }
        printf("\n");
    }
    return NO_ERR;
}

/**
 * @brief 编辑ELF文件的十六进制内容
 * Edit the hex content of ELF file
 * @param elf Elf custom structure
 * @param offset edit start offset
 * @param data edit data
 * @param size edit size
 * @return error code
 */
int edit_hex(Elf *elf, uint64_t offset, uint8_t *data, size_t size) {
    if (offset + size > elf->size) {
        return ERR_ARGS;
    }

    void *dst = elf->mem + offset;
    if (!memcpy(dst, data, size)) {
        return ERR_COPY;
    }

    return NO_ERR;
}

/**
 * @brief 编辑ELF文件的指针内容
 * Edit the pointer content of ELF file
 * @param elf Elf custom structure
 * @param offset edit start offset
 * @param value edit value
 * @return error code
 */
int edit_pointer(Elf *elf, uint64_t offset, uint64_t value) {
    if (elf->class == ELFCLASS32) {
        if (offset + sizeof(uint32_t) > elf->size) {
            return ERR_ARGS;
        }
        uint32_t val32 = (uint32_t)value;
        void *dst = elf->mem + offset;
        if (!memcpy(dst, &val32, sizeof(uint32_t))) {
            return ERR_COPY;
        }
    } else if (elf->class == ELFCLASS64) {
        if (offset + sizeof(uint64_t) > elf->size) {
            return ERR_ARGS;
        }
        void *dst = elf->mem + offset;
        if (!memcpy(dst, &value, sizeof(uint64_t))) {
            return ERR_COPY;
        }
    } else {
        return ERR_ELF_CLASS;
    }
    return NO_ERR;
}

/**
 * @brief 从文件中提取指定偏移和大小的数据片段
 * Extract a data fragment from a file at a specified offset and size
 * @param file_name input file name
 * @param offset extract start offset
 * @param size extract size
 * @param output output buffer
 * @return error code
 */
int extract_fragment(const char *file_name, long offset, size_t size, char *output) {
    FILE *input_fp = fopen(file_name, "rb");
    if (input_fp == NULL) {
        return ERR_FILE_OPEN;
    }

    // 设置文件指针偏移量
    fseek(input_fp, offset, SEEK_SET);

    // 读取指定大小的数据
    unsigned char *buffer = (unsigned char *)malloc(size);
    if (buffer == NULL) {
        fclose(input_fp);
        return ERR_MEM;
    }

    fread(buffer, 1, size, input_fp);
    for (int i = 0; i < size; i++) {
        printf("\\x%02x", buffer[i]);
    }
    printf("\n");
    if (output)
        memcpy(output, buffer, size);

    int err = mem_to_file(file_name, buffer, size, 1);
    free(buffer);
    fclose(input_fp);
    return err;
}

/**
 * @brief 将二进制文件转换为Windows cmd脚本
 * convert binary file to Windows cmd script
 * @param input_path input file name with path
 * @return error code
 */
void bin_to_cmd(const char* input_path) {
    char basename[MAX_PATH_LEN];
    char filename[MAX_PATH_LEN];
    char output[MAX_PATH_LEN + 10];
    
    get_filename_with_ext(input_path, filename);
    get_filename_without_ext(input_path, basename);
    sprintf(output, "%s.cmd", basename);
    
    FILE *bin_file = fopen(input_path, "rb");
    FILE *txt_file = fopen(output, "w");
    
    if (!bin_file || !txt_file) {
        PRINT_ERROR("open failed");
        exit(EXIT_FAILURE);
    }

    // create null file
    fprintf(txt_file, "echo|set /p=\"\">%s.%s\n", basename, "hex");

    unsigned char buffer[READ_CHUNK];
    char hex_str[MAX_LINE_LEN + 1] = {0};
    int hex_pos = 0;

    while (1) {
        size_t bytes_read = fread(buffer, 1, READ_CHUNK, bin_file);
        if (bytes_read == 0) break;

        for (size_t i = 0; i < bytes_read; i++) {
            // 每个字节转为2个十六进制字符
            int written = snprintf(hex_str + hex_pos, 3, "%02x", buffer[i]);
            hex_pos += written;

            // 达到行长度限制时换行
            if (hex_pos >= MAX_LINE_LEN) {
                fprintf(txt_file, "echo|set /p=\"%.*s\">>%s.%s\n", MAX_LINE_LEN + 20, hex_str, basename, "hex");
                hex_pos = 0;
            }
        }
    }

    // write the remaining characterw 
    // 写入剩余内容
    if (hex_pos > 0) {
        fprintf(txt_file, "echo|set /p=\"%.*s\">>%s.%s\n", hex_pos, hex_str, basename, "hex");
    }

    // write powershell cmd
    char s1[MAX_LINE_LEN];
    sprintf(s1, "powershell -Command \"$h=Get-Content -readcount 0 -path './%s.%s';", basename, "hex");
    char s2[MAX_LINE_LEN] = "$l=$h[0].length;$b=New-Object byte[] ($l/2);$x=0;for ($i=0;$i -le $l-1;$i+=2){$b[$x]=[byte]::Parse($h[0].Substring($i,2),[System.Globalization.NumberStyles]::HexNumber);$x+=1};";
    char s3[MAX_LINE_LEN];
    sprintf(s3, "set-content -encoding byte '%s' -value $b;", filename);
    char s4[MAX_LINE_LEN] = "Remove-Item -force test.hex;\"";
    char s[1024];
    strcat(s, s1);
    strcat(s, s2);
    strcat(s, s3);
    strcat(s, s4);
    fprintf(txt_file, s);
    PRINT_INFO("write to %s\n", output);
    fclose(bin_file);
    fclose(txt_file);
}

/**
 * @brief 将二进制文件转换为Linux shell脚本
 * convert binary file to Linux shell script
 * @param input_path input file name with path
 * @return error code
 */
void bin_to_sh(const char* input_path) {
    char basename[MAX_PATH_LEN];
    char filename[MAX_PATH_LEN];
    char output[MAX_PATH_LEN + 10];
    
    get_filename_with_ext(input_path, filename);
    get_filename_without_ext(input_path, basename);
    sprintf(output, "%s.sh", basename);
    
    FILE *bin_file = fopen(input_path, "rb");
    FILE *txt_file = fopen(output, "w");
    
    if (!bin_file || !txt_file) {
        PRINT_ERROR("open failed");
        exit(EXIT_FAILURE);
    }

    // create null file
    fprintf(txt_file, "echo \"\"| xxd -r -p > %s\n", filename);

    unsigned char buffer[MAX_LINE_LEN];
    char hex_str[MAX_LINE_LEN + 1] = {0};
    int hex_pos = 0;

    while (1) {
        size_t bytes_read = fread(buffer, 1, READ_CHUNK, bin_file);
        if (bytes_read == 0) break;

        for (size_t i = 0; i < bytes_read; i++) {
            // 每个字节转为2个十六进制字符
            int written = snprintf(hex_str + hex_pos, 3, "%02x", buffer[i]);
            hex_pos += written;

            // 达到行长度限制时换行
            if (hex_pos >= MAX_LINE_LEN) {
                fprintf(txt_file, "echo \"%.*s\" | xxd -r -p >>%s\n", MAX_LINE_LEN + 40, hex_str, filename);
                hex_pos = 0;
            }
        }
    }

    // write the remaining characterw 
    // 写入剩余内容
    if (hex_pos > 0) {
        fprintf(txt_file, "echo \"%.*s\" | xxd -r -p >>%s\n", hex_pos, hex_str, filename);
    }

    PRINT_INFO("write to %s\n", output);
    fclose(bin_file);
    fclose(txt_file);
}

/**
 * @brief 得到字符串
 * get symbol name
 * @param elf elf custom structure
 * @param name symbol name
 * @param count symbol count
 * @return int error code {-1:error,0:sucess}
 */
int get_sym_string_table(Elf *elf, char ***name, int *count) {
    char **string;
    int string_count = 0;
    if (elf->class == ELFCLASS32) {
        string_count = elf->data.elf32.sym_count;
        if (string_count == 0) {
            PRINT_DEBUG("no symbols found in dynsym\n");
            return ERR_NOTFOUND;
        }

        string = (char **)malloc(sizeof(char*) * string_count);
        if (string == NULL) {
            PRINT_DEBUG("memory allocation failed\n");
            return ERR_MEM;
        }

        for (int i = 0; i < string_count; ++i) {
            string[i] = (char *)elf->mem + elf->data.elf32.strtab->sh_offset + elf->data.elf32.sym_entry[i].st_name;
            *count = string_count;
        }
    } else if (elf->class == ELFCLASS64) {
        string_count = elf->data.elf64.sym_count;
        if (string_count == 0) {
            PRINT_DEBUG("no symbols found in dynsym\n");
            return ERR_NOTFOUND;
        }

        string = (char **)malloc(sizeof(char*) * string_count);
        if (string == NULL) {
            PRINT_DEBUG("memory allocation failed\n");
            return ERR_MEM;
        }

        for (int i = 0; i < string_count; ++i) {
            string[i] = (char *)elf->mem + elf->data.elf64.strtab->sh_offset + elf->data.elf64.sym_entry[i].st_name;
            *count = string_count;
        }
    } else {
        return ERR_ELF_CLASS;
    }

    *name = string;
    return NO_ERR;
}

/**
 * @brief 得到字符串
 * get symbol name
 * @param elf elf custom structure
 * @param name symbol name
 * @param count symbol count
 * @return int error code {-1:error,0:sucess}
 */
int get_dyn_string_table(Elf *elf, char ***name, int *count) {
    char **string;
    int string_count = 0;
    if (elf->class == ELFCLASS32) {
        string_count = elf->data.elf32.dynsym_count;
        if (string_count == 0) {
            PRINT_DEBUG("no symbols found in dynsym\n");
            return ERR_NOTFOUND;
        }

        string = (char **)malloc(sizeof(char*) * string_count);
        if (string == NULL) {
            PRINT_DEBUG("memory allocation failed\n");
            return ERR_MEM;
        }

        for (int i = 0; i < string_count; ++i) {
            string[i] = (char *)elf->mem + elf->data.elf32.dynstrtab->sh_offset + elf->data.elf32.dynsym_entry[i].st_name;
            *count = string_count;
        }
    } else if (elf->class == ELFCLASS64) {
        string_count = elf->data.elf64.dynsym_count;
        if (string_count == 0) {
            PRINT_DEBUG("no symbols found in dynsym\n");
            return ERR_NOTFOUND;
        }

        string = (char **)malloc(sizeof(char*) * string_count);
        if (string == NULL) {
            PRINT_DEBUG("memory allocation failed\n");
            return ERR_MEM;
        }

        for (int i = 0; i < string_count; ++i) {
            string[i] = (char *)elf->mem + elf->data.elf64.dynstrtab->sh_offset + elf->data.elf64.dynsym_entry[i].st_name;
            *count = string_count;
        }
    } else {
        return ERR_ELF_CLASS;
    }

    *name = string;
    return NO_ERR;
}

/**
 * @brief 检查elf文件的pie是否开启
 * check if pie of elf file is enabled
 * @param elf elf custom structure
 * @param result ture or false
 * @return int error code
 */
int check_pie(Elf *elf, bool *result) {
    if (elf->class == ELFCLASS32) {
        if (elf->data.elf32.ehdr->e_type == ET_DYN) {
            *result = true;
        } else {
            *result = false;
        }
    } else if (elf->class == ELFCLASS64) {
        if (elf->data.elf64.ehdr->e_type == ET_DYN) {
            *result = true;
        } else {
            *result = false;
        }
    } else {
        return ERR_ELF_CLASS;
    }
    return NO_ERR;
}

/**
 * @brief 检查elf文件的nx是否开启
 * check if nx of elf file is enabled
 * @param elf elf custom structure
 * @param result ture or false
 * @return int error code
 */
int check_nx(Elf *elf, bool *result) {
    size_t index = 0;
    int err = 0;
    err = get_segment_index_by_type(elf, PT_GNU_STACK, &index);
    if (err == NO_ERR) {
        if (elf->class == ELFCLASS32) {
            if ((elf->data.elf32.phdr[index].p_flags & 0x1) == 0) {
                *result = true;
            } else {
                *result = false;
            }
        } else {
            if ((elf->data.elf64.phdr[index].p_flags & 0x1) == 0) {
                *result = true;
            } else {
                *result = false;
            }
        }
        // There will be no ERR_CASS, as the subfunction has already been checked
    }

    return err;
}

static int is_dynamic(Elf *elf, bool *result) {
    if (elf->class == ELFCLASS32) {
        *result = elf->data.elf32.dyn_count?true:false;
    } else if (elf->class == ELFCLASS64)
        *result = elf->data.elf64.dyn_count?true:false;
    else
        return ERR_ELF_CLASS;
    return NO_ERR;
}

/**
 * @brief 检查elf文件的栈保护是否开启
 * check if stack cookie of elf file is enabled
 * @param elf elf custom structure
 * @param result ture or false
 * @return int error code
 */
int check_cookie(Elf *elf, bool *result) {
    bool flag = false;
    int err = 0;
    err = is_dynamic(elf, &flag);
    if (err != NO_ERR) {
        return err; 
    }

    if (flag) {
        char **string = NULL;
        int string_count = 0;
        err = get_dyn_string_table(elf, &string, &string_count);
        if (err != NO_ERR) {
            PRINT_ERROR("get string table error\n");
            if (string) free(string);
            return err;
        }

        for (int i = 0; i < string_count; i++) {
            if (!strcmp(string[i],"__stack_chk_fail" )) {
                *result = true;
                if (string) free(string);
                return err;
            }
        }
        *result = false;
        if (string) free(string);
        return err;
    }
}

/**
 * @brief 检查elf文件的got read only是否开启
 * check if relro of elf file is enabled
 * @param elf elf custom structure
 * @param result ture or false
 * @return int error code
 */
int check_relro(Elf *elf, int *result) {
    size_t index = 0;
    int err = 0;
    err = get_segment_index_by_type(elf, PT_GNU_RELRO, &index);
    if (err == ERR_SEG_NOTFOUND) {
        *result = 0;
        return NO_ERR;
    } else {
        int value = get_dynseg_value_by_tag(elf, DT_FLAGS_1);
        if (has_flag(value, DF_1_NOW)) {
            *result = 2;
        } else {
            *result = 1;
        }
        return NO_ERR;
    }
}