#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>
#include "common.h"
#include "section.h"

enum ELF_TYPE {
    ELF_STATIC,
    ELF_EXE_NOW,
    ELF_EXE_LAZY,
    ELF_SHARED
};

/**
 * @brief elf类型
 * get elf type
 * @param h32 elf file handle struct
 * @param h64 elf file handle struct
 * @return int error code {-1:error,elf type}
 */
int get_elf_type(handle_t32 *h32, handle_t64 *h64) {
    int has_dynamic = 0;
    if (MODE == ELFCLASS32) {
        Elf32_Dyn *dyn = NULL;
        uint32_t dyn_c;
        for (int i = 0; i < h32->ehdr->e_phnum; i++) {
            if (h32->phdr[i].p_type == PT_DYNAMIC) {
                has_dynamic = 1;
                dyn = h32->mem + h32->phdr[i].p_offset;
                dyn_c = h32->phdr[i].p_filesz / sizeof(Elf32_Dyn);
                break;
            }
        }
        if (!has_dynamic && h32->ehdr->e_type == ET_EXEC) {
            return ELF_STATIC;
        }
        else if (has_dynamic && h32->ehdr->e_type == ET_DYN) {
            for (int i = 0; i < dyn_c; i++) {
                if (dyn[i].d_tag == DT_FLAGS_1) {
                    if (has_flag(dyn[i].d_un.d_val, DF_1_NOW))
                        return ELF_EXE_NOW;
                    else
                        return ELF_EXE_LAZY;
                    break;
                }
            }
            return ELF_SHARED;
        }
    }
    if (MODE == ELFCLASS64) {
        Elf64_Dyn *dyn = NULL;
        uint64_t dyn_c;
        for (int i = 0; i < h64->ehdr->e_phnum; i++) {
            if (h64->phdr[i].p_type == PT_DYNAMIC) {
                has_dynamic = 1;
                dyn = h64->mem + h64->phdr[i].p_offset;
                dyn_c = h64->phdr[i].p_filesz / sizeof(Elf64_Dyn);
                break;
            }
        }
        if (!has_dynamic && h64->ehdr->e_type == ET_EXEC) {
            return ELF_STATIC;
        }
        else if (has_dynamic && h64->ehdr->e_type == ET_DYN) {
            for (int i = 0; i < dyn_c; i++) {
                if (dyn[i].d_tag == DT_FLAGS_1) {
                    if (has_flag(dyn[i].d_un.d_val, DF_1_NOW))
                        return ELF_EXE_NOW;
                    else
                        return ELF_EXE_LAZY;
                    break;
                }
            }
            return ELF_SHARED;
        }
    }
    return -1;
}

/**
 * @brief 检查hook外部函数
 * chekc hook function by .got.plt
 * @param h32 elf file handle struct
 * @param h64 elf file handle struct
 * @param start start address
 * @param size area size
 * @return int error code {-1:error,0:sucess,1:failed}
 */
int check_hook(handle_t32 *h32, handle_t64 *h64, uint64_t start, size_t size) {
    uint64_t offset = 0;
    
    /* attention: The 32-bit program has not been tested! */
    if (MODE == ELFCLASS32) {
        h32->sec_size = sizeof(Elf32_Rel);  // init
        for (int i = 0; i < h32->sec_size / sizeof(Elf32_Rel); i++) {
            offset = get_rel32_offset(h32, ".rel.plt", i);
            if (offset == -1) {
                return -1;
            }
            uint32_t *p = (uint32_t *)(h32->mem + offset);
            DEBUG("0x%x, 0x%x\n", offset, *p);
            if (*p < start || *p >= start + size) {
                return 1;
            }
        }
    }

    if (MODE == ELFCLASS64) {
        h64->sec_size = sizeof(Elf64_Rela);  // init
        for (int i = 0; i < h64->sec_size / sizeof(Elf64_Rela); i++) {
            offset = get_rela64_offset(h64, ".rela.plt", i);
            if (offset == -1) {
                return -1;
            }
            uint64_t *p = (uint64_t *)(h64->mem + offset);
            DEBUG("0x%x, 0x%x\n", offset, *p);
            if (*p < start || *p >= start + size) {
                return 1;
            }
        }
    }

    return 0;
}

/**
 * @brief 检查load
 * chekc load segment flags
 * @param h32 elf file handle struct
 * @param h64 elf file handle struct
 * @return int error code {-1:error,0:sucess,1:failed}
 */
int check_load_flags(handle_t32 *h32, handle_t64 *h64) {
    int count = 0;

    if (MODE == ELFCLASS32) {
        for (int i = 0; i < h32->ehdr->e_phnum; i++) {
            if (h32->phdr[i].p_type == PT_LOAD) {
                // flags:E
                if (h32->phdr[i].p_flags & 0x1) {
                    count++;
                }
            }
        }
    }

    if (MODE == ELFCLASS64) {
        for (int i = 0; i < h64->ehdr->e_phnum; i++) {
            if (h64->phdr[i].p_type == PT_LOAD) {
                // flags:E
                if (h64->phdr[i].p_flags & 0x1) {
                    count++;
                }
            }
        }
    }

    DEBUG("executable segment count: %d\n", count);
    if (count > 1) {
        return 1;
    } else if (count == 1) {
        return 0;
    } else if (count == 0) {
        return -1;
    } 
}

/**
 * @brief 检查段是否连续
 * check if the load segments are continuous
 * @param h32 elf file handle struct
 * @param h64 elf file handle struct
 * @return int error code {-1:error,0:sucess,1:failed}
 */
int check_load_continuity(handle_t32 *h32, handle_t64 *h64) {
    int last = 0;
    int current = 0;
    int has_first = 0;

    if (MODE == ELFCLASS32) {
        for (int i = 0; i < h32->ehdr->e_phnum; i++) {
            if (h32->phdr[i].p_type == PT_LOAD) {
                if (!has_first) {
                    has_first = 1;
                    last = i;
                    continue;
                }
                
                current = i;
                if (current - last != 1) {
                    return 1;
                }
                last = i;
            }
        }
    }

    if (MODE == ELFCLASS64) {
        for (int i = 0; i < h64->ehdr->e_phnum; i++) {
            if (h64->phdr[i].p_type == PT_LOAD) {
                if (!has_first) {
                    has_first = 1;
                    last = i;
                    continue;
                }
                
                current = i;
                if (current - last != 1) {
                    return 1;
                }
                last = i;
            }
        }
    }

    return 0;
}

/**
 * @brief 检查DT_NEEDED是否连续
 * check if the DT_NEEDED so are continuous
 * @param h32 elf file handle struct
 * @param h64 elf file handle struct
 * @return int error code {-1:error,0:sucess,1:failed}
 */
int check_needed_continuity(handle_t32 *h32, handle_t64 *h64) {
    int last = 0;
    int current = 0;
    int has_first = 0;
    int ret = 0;

    if (MODE == ELFCLASS32) {
        Elf32_Dyn *dyn = NULL;
        uint32_t dyn_c;
        for (int i = 0; i < h32->ehdr->e_phnum; i++) {
            if (h32->phdr[i].p_type == PT_DYNAMIC) {
                dyn = h32->mem + h32->phdr[i].p_offset;
                dyn_c = h32->phdr[i].p_filesz / sizeof(Elf32_Dyn);
                break;
            }
        }
        if (!dyn) ret = -1;
        else {
            for (int i = 0; i < dyn_c; i++) {
                if (dyn[i].d_tag == DT_NEEDED) {
                    if (!has_first) {
                        has_first = 1;
                        last = i;
                        continue;
                    }
                    
                    current = i;
                    if (current - last != 1) {
                        ret = 1;
                        break;
                    }
                    last = i;
                }
            }
        }
    }

    if (MODE == ELFCLASS64) {
        Elf64_Dyn *dyn = NULL;
        uint64_t dyn_c;
        for (int i = 0; i < h64->ehdr->e_phnum; i++) {
            if (h64->phdr[i].p_type == PT_DYNAMIC) {
                dyn = h64->mem + h64->phdr[i].p_offset;
                dyn_c = h64->phdr[i].p_filesz / sizeof(Elf64_Dyn);
                break;
            }
        }
        if (!dyn) ret = -1;
        else {
            for (int i = 0; i < dyn_c; i++) {
                if (dyn[i].d_tag == DT_NEEDED) {
                    if (!has_first) {
                        has_first = 1;
                        last = i;
                        continue;
                    }
                    
                    current = i;
                    if (current - last != 1) {
                        ret = 1;
                        break;
                    }
                    last = i;
                }
            }
        }
    }

    return ret;
}

/**
 * @brief 检查节头表是否存在
 * check if the section header table exists
 * @param h32 elf file handle struct
 * @param h64 elf file handle struct
 * @return int error code {-1:error,0:sucess,1:failed,2:warn}
 */
int check_shdr(handle_t32 *h32, handle_t64 *h64) {
    int ret = 0;

    if (MODE == ELFCLASS32) {
        if (h32->ehdr->e_shoff == 0 || h32->ehdr->e_shnum == 0) {
            ret = 1;
        } else if (h32->ehdr->e_shoff != h32->size - sizeof(Elf32_Shdr) * h32->ehdr->e_shnum) {
            ret = 2;
        }
    }

    if (MODE == ELFCLASS64) {
        if (h64->ehdr->e_shoff == 0 || h64->ehdr->e_shnum == 0) {
            ret = 1;
        } else if (h64->ehdr->e_shoff != h64->size - sizeof(Elf64_Shdr) * h64->ehdr->e_shnum) {
            ret = 2;
        }
    }

    return ret;
}

/**
 * @brief 检查dynstr是否连续以及字符串是否存在空格
 * check if the dynstr segments are continuous and whether there are extra spaces in the string
 * @param h32 elf file handle struct
 * @param h64 elf file handle struct
 * @return int error code {-1:error,0:sucess,1:failed}
 */
int check_dynstr(handle_t32 *h32, handle_t64 *h64) {
    char *name;
    int ret = 0;
    int dynsym_i = 0, dynstr_i = 0;
    char *tmp;
    size_t tmp_size = 1;
    if (MODE == ELFCLASS32) {
        for (int i = 0; i < h32->ehdr->e_shnum; i++) {
            name = h32->mem + h32->shstrtab->sh_offset + h32->shdr[i].sh_name;
            if (validated_offset(name, h32->mem, h32->mem + h32->size)) {
                ERROR("Corrupt file format\n");
                ret = -1;
            }
            if (!strcmp(name, ".dynsym")) dynsym_i = i;
            if (!strcmp(name, ".dynstr")) dynstr_i = i;
        }
        /* check if the dynstr segments are continuous */
        if (h32->shdr[dynsym_i].sh_offset + h32->shdr[dynsym_i].sh_size != h32->shdr[dynstr_i].sh_offset)
            ret = 1;
        /* check if the string length is less than original one */
        tmp = h32->mem + h32->shdr[dynstr_i].sh_offset + 1;
        while (tmp_size < h32->shdr[dynstr_i].sh_size) {
            tmp_size += strlen(tmp) + 1;
            DEBUG("%s 0x%x\n", tmp, tmp_size);
            tmp += strlen(tmp) + 1;
            if (tmp_size != h32->shdr[dynstr_i].sh_size && strlen(tmp) == 0) {
                ret = 1;
                break;
            }
            ret = 0;
        }
    }
    else if (MODE == ELFCLASS64) {
        for (int i = 0; i < h64->ehdr->e_shnum; i++) {
            name = h64->mem + h64->shstrtab->sh_offset + h64->shdr[i].sh_name;
            if (validated_offset(name, h64->mem, h64->mem + h64->size)) {
                ERROR("Corrupt file format\n");
                ret = -1;
            }
            if (!strcmp(name, ".dynsym")) dynsym_i = i;
            if (!strcmp(name, ".dynstr")) dynstr_i = i;
        }
        /* check if the dynstr segments are continuous */
        if (h64->shdr[dynsym_i].sh_offset + h64->shdr[dynsym_i].sh_size != h64->shdr[dynstr_i].sh_offset)
            ret = 1;
        /* check if the string length is less than original one */
        tmp = h64->mem + h64->shdr[dynstr_i].sh_offset + 1;
        while (tmp_size < h64->shdr[dynstr_i].sh_size) {
            tmp_size += strlen(tmp) + 1;
            DEBUG("%s 0x%x\n", tmp, tmp_size);
            tmp += strlen(tmp) + 1;
            if (tmp_size != h64->shdr[dynstr_i].sh_size && strlen(tmp) == 0) {
                ret = 1;
                break;
            }
            ret = 0;
        }
    }

    return ret;
}

/**
 * @brief 检查interpreter
 * check if the interpreter is legal
 * @param h32 elf file handle struct
 * @param h64 elf file handle struct
 * @return int error code {-1:error,0:sucess,1:failed}
 */
int check_interpreter(handle_t32 *h32, handle_t64 *h64) {
    char *name;
    int ret = 0;
    int interp_i = -1;
    char *tmp;
    size_t tmp_size = 1;
    if (MODE == ELFCLASS32) {
        for (int i = 0; i < h32->ehdr->e_shnum; i++) {
            name = h32->mem + h32->shstrtab->sh_offset + h32->shdr[i].sh_name;
            if (validated_offset(name, h32->mem, h32->mem + h32->size)) {
                ERROR("Corrupt file format\n");
                ret = -1;
            }
            if (!strcmp(name, ".interp")) interp_i = i;
        }
        name = h32->mem + h32->shdr[interp_i].sh_offset;
        /* check index */
        /*
        if (interp_i == -1) {
            ret = -1;
        }
        else if (interp_i > 2) {
            ret = 1;
        }*/
        /* check if the string length is less than original one */
        if (strlen(name) != h32->shdr[interp_i].sh_size - 1) {
            ret = 1;
        }
    }
    else if (MODE == ELFCLASS64) {
        for (int i = 0; i < h64->ehdr->e_shnum; i++) {
            name = h64->mem + h64->shstrtab->sh_offset + h64->shdr[i].sh_name;
            if (validated_offset(name, h64->mem, h64->mem + h64->size)) {
                ERROR("Corrupt file format\n");
                ret = -1;
            }
            if (!strcmp(name, ".interp")) interp_i = i;
        }
        name = h64->mem + h64->shdr[interp_i].sh_offset;
        /* check index */
        /*
        if (interp_i == -1) {
            ret = -1;
        }
        else if (interp_i > 2) {
            ret = 1;
        }*/
        /* check if the string length is less than original one */
        if (strlen(name) != h64->shdr[interp_i].sh_size - 1) {
            ret = 1;
        }
    }

    return ret;
}

/**
 * @brief 检查elf文件是否合法
 * check if the elf file is legal
 * @param elf_name elf file name
 * @return int error code {-1:error,0:sucess}
 */
int checksec(char *elf_name) {
    handle_t32 h32;
    handle_t64 h64;
    int ret = init_elf(elf_name, &h32, &h64);
    if (ret) {
        ERROR("init elf error\n");
        return -1;
    }

    char *mode, *tmp, *bind;
    char elf_info[1000];
    enum ELF_TYPE type;
    type = get_elf_type(&h32, &h64);
    if (MODE == ELFCLASS32) {
        mode = "32-bit";
    } else if (MODE == ELFCLASS64) {
        mode = "64-bit";
    }
    if (type == ELF_EXE_LAZY) {
        bind = "bind lazy";
        tmp = "pie executable";
    } else if (type == ELF_EXE_NOW) {
        bind = "bind now";
        tmp = "pie executable";
    } else if (type == ELF_SHARED) {
        bind = "dynamically linked";
        tmp = "shared object";
    } else if (type == ELF_STATIC) {
        bind = "statically linked";
        tmp = "executable";
    }
    snprintf(elf_info, 1000, "ELF %s %s, %s", mode, tmp, bind);
    printf("%s\n", elf_info);

    char TAG[50];
    printf("|--------------------------------------------------------------------------|\n");
    printf("|%-20s|%1s| %-50s|\n", "checkpoint", "s", "description");
    printf("|--------------------------------------------------------------------------|\n");
    /* check entry */
    strcpy(TAG, "entry point");
    uint64_t entry = get_entry(elf_name);
    uint64_t addr = get_section_addr(elf_name, ".text");
    size_t size = get_section_size(elf_name, ".text");
    if (type == ELF_SHARED && entry == 0) {
        CHECK_COMMON("|%-20s|%1s| %-50s|\n", TAG, "-", "na(shared library)");
    }
    else if (entry == addr) {
        CHECK_COMMON("|%-20s|%1s| %-50s|\n", TAG, "✓", "normal");
    } else if (entry > addr && entry < addr + size) {
        CHECK_WARNING("|%-20s|%1s| %-50s|\n", TAG, "!", "is NOT at the start of the .TEXT section");
    } else {
        CHECK_ERROR("|%-20s|%1s| %-50s|\n", TAG, "✗", "is NOT inside the .TEXT section");
    }

    /* check plt/got hook (lazy bind) */
    strcpy(TAG, "hook in .got.plt");
    if (type == ELF_SHARED) {
        CHECK_COMMON("|%-20s|%1s| %-50s|\n", TAG, "-", "na(shared library)");
    } else if (type == ELF_STATIC) {
        CHECK_COMMON("|%-20s|%1s| %-50s|\n", TAG, "-", "na(statically linked)");
    } else {
        addr = get_section_addr(elf_name, ".plt");
        size = get_section_size(elf_name, ".plt");
        ret = check_hook(&h32, &h64, addr, size);
        switch (ret)
        {
            case 0:
                CHECK_COMMON("|%-20s|%1s| %-50s|\n", TAG, "✓", "normal");
                break;

            case 1:
                CHECK_ERROR("|%-20s|%1s| %-50s|\n", TAG, "✗", ".got.plt hook is detected");
                break;

            default:
                CHECK_COMMON("|%-20s|%1s| %-50s|\n", TAG, "-", "na(bind now)");
                break;
        }
    }
    

    /* check load segment permission */
    strcpy(TAG, "segment flags");
    ret = check_load_flags(&h32, &h64);
    switch (ret)
    {
        case 0:
            CHECK_COMMON("|%-20s|%1s| %-50s|\n", TAG, "✓", "normal");
            break;

        case 1:
            CHECK_ERROR("|%-20s|%1s| %-50s|\n", TAG, "✗", "more than one executable segment");
            break;

        default:
            CHECK_COMMON("|%-20s|%1s| %-50s|\n", TAG, "-", "na(no executable elf file)");
            break;
    }

    /* check segment continuity */
    strcpy(TAG, "segment continuity");
    ret = check_load_continuity(&h32, &h64);
    switch (ret)
    {
        case 0:
            CHECK_COMMON("|%-20s|%1s| %-50s|\n", TAG, "✓", "normal");
            break;

        case 1:
            CHECK_ERROR("|%-20s|%1s| %-50s|\n", TAG, "✗", "load segments are NOT continuous");
            break;

        default:
            CHECK_COMMON("|%-20s|%1s| %-50s|\n", TAG, "-", "na");
            break;
    }

    /* check DLL injection */
    strcpy(TAG, "DLL injection");
    ret = check_needed_continuity(&h32, &h64);
    switch (ret)
    {
        case 0:
            CHECK_COMMON("|%-20s|%1s| %-50s|\n", TAG, "✓", "normal");
            break;

        case 1:
            CHECK_ERROR("|%-20s|%1s| %-50s|\n", TAG, "✗", "DT_NEEDED libraries are NOT continuous");
            break;

        default:
            CHECK_COMMON("|%-20s|%1s| %-50s|\n", TAG, "-", "na(statically linked)");
            break;
    }

    /* check section header table */
    strcpy(TAG, "section header table");
    ret = check_shdr(&h32, &h64);
    switch (ret)
    {
        case 0:
            CHECK_COMMON("|%-20s|%1s| %-50s|\n", TAG, "✓", "normal");
            break;
        
        case 1:
            CHECK_ERROR("|%-20s|%1s| %-50s|\n", TAG, "✗", "NO section header table");
            break;

        case 2:
            CHECK_WARNING("|%-20s|%1s| %-50s|\n", TAG, "!", "is NOT at the end of the file");
            break;
        
        default:
            CHECK_COMMON("|%-20s|%1s| %-50s|\n", TAG, "-", "na");
            break;
    }

    /* check .dynstr */
    strcpy(TAG, "symbol injection");
    ret = check_dynstr(&h32, &h64);
    switch (ret)
    {
        case 0:
            CHECK_COMMON("|%-20s|%1s| %-50s|\n", TAG, "✓", "normal");
            break;
        
        case 1:
            CHECK_ERROR("|%-20s|%1s| %-50s|\n", TAG, "✗", "modified symbol is detected");
            break;
        
        default:
            CHECK_WARNING("|%-20s|%1s| %-50s|\n", TAG, "-", "na(no .dynstr section)");
            break;
    }

    /* check .interp */
    strcpy(TAG, "interp injection");
    ret = check_interpreter(&h32, &h64);
    switch (ret)
    {
        case 0:
            CHECK_COMMON("|%-20s|%1s| %-50s|\n", TAG, "✓", "normal");
            break;
        
        case 1:
            CHECK_ERROR("|%-20s|%1s| %-50s|\n", TAG, "✗", "modified interpreter is detected");
            break;
        
        default:
            CHECK_COMMON("|%-20s|%1s| %-50s|\n", TAG, "-", "na(no .interp section)");
            break;
    }

    printf("|--------------------------------------------------------------------------|\n");
    finit_elf(&h32, &h64);
    return 0;
}