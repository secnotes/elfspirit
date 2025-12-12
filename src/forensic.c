#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>
#include "lib/elfutil.h"
#include "lib/util.h"

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
int get_elf_type(Elf *elf) {
    int has_dynamic = 0;
    if (elf->class == ELFCLASS32) {
        Elf32_Dyn *dyn = NULL;
        uint32_t dyn_c;
        for (int i = 0; i < elf->data.elf32.ehdr->e_phnum; i++) {
            if (elf->data.elf32.phdr[i].p_type == PT_DYNAMIC) {
                has_dynamic = 1;
                dyn = (Elf32_Dyn *)(elf->mem + elf->data.elf32.phdr[i].p_offset);
                dyn_c = elf->data.elf32.phdr[i].p_filesz / sizeof(Elf32_Dyn);
                break;
            }
        }
        if (!has_dynamic && elf->data.elf32.ehdr->e_type == ET_EXEC) {
            return ELF_STATIC;
        }
        else if (has_dynamic && elf->data.elf32.ehdr->e_type == ET_DYN) {
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
    if (elf->class == ELFCLASS64) {
        Elf64_Dyn *dyn = NULL;
        uint64_t dyn_c;
        for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
            if (elf->data.elf64.phdr[i].p_type == PT_DYNAMIC) {
                has_dynamic = 1;
                dyn = (Elf64_Dyn *)(elf->mem + elf->data.elf64.phdr[i].p_offset);
                dyn_c = elf->data.elf64.phdr[i].p_filesz / sizeof(Elf64_Dyn);
                break;
            }
        }
        if (!has_dynamic && elf->data.elf64.ehdr->e_type == ET_EXEC) {
            return ELF_STATIC;
        }
        else if (has_dynamic && elf->data.elf64.ehdr->e_type == ET_DYN) {
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
    } else {
        return ERR_CLASS;
    }
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
int check_hook(Elf *elf, uint64_t start, size_t size) {
    uint64_t offset = 0;

    int got_index = get_section_index_by_name(elf, ".got.plt");
    if (got_index < 0) {
        PRINT_ERROR(".got.plt section not found\n");
        return ERR_SEC_NOTFOUND;
    }
    
    /* attention: The 32-bit program has not been tested! */
    if (elf->class == ELFCLASS32) {
        int rel_index = get_section_index_by_name(elf, ".rel.plt");
        if (rel_index < 0) {
            PRINT_ERROR(".rela.plt section not found\n");
            return ERR_SEC_NOTFOUND;
        }
        Elf32_Rel *rel = (Elf32_Rel *)(elf->mem + elf->data.elf32.shdr[rel_index].sh_offset);
        for (int i = 0; i < elf->data.elf32.shdr[rel_index].sh_size / sizeof(Elf32_Rel); i++) {
            int str_index = ELF32_R_SYM(rel[i].r_info);
            int diff = elf->data.elf32.shdr[got_index].sh_addr - elf->data.elf32.shdr[got_index].sh_offset;
            offset = rel[i].r_offset - diff;
            uint32_t *p = (uint32_t *)(elf->mem + offset);
            PRINT_DEBUG("0x%x, 0x%x\n", offset, *p);
            if (*p < start || *p >= start + size) {
                return TRUE;
            }
        }
    } else if (elf->class == ELFCLASS64) {
        int rela_index = get_section_index_by_name(elf, ".rela.plt");
        if (rela_index < 0) {
            PRINT_ERROR(".rela.plt section not found\n");
            return ERR_SEC_NOTFOUND;
        }
        Elf64_Rela *rela = (Elf64_Rela *)(elf->mem + elf->data.elf64.shdr[rela_index].sh_offset);
        for (int i = 0; i < elf->data.elf64.shdr[rela_index].sh_size / sizeof(Elf64_Rela); i++) {
            int str_index = ELF64_R_SYM(rela[i].r_info);
            int diff = elf->data.elf64.shdr[got_index].sh_addr - elf->data.elf64.shdr[got_index].sh_offset;
            offset = rela[i].r_offset - diff;
            uint64_t *p = (uint64_t *)(elf->mem + offset);
            PRINT_DEBUG("0x%x, 0x%x\n", offset, *p);
            if (*p < start || *p >= start + size) {
                return TRUE;
            }
        }
    } else {
        return ERR_CLASS;
    }

    return FALSE;
}

/**
 * @brief 检查load
 * chekc load segment flags
 * @param elf elf file handle struct
 * @return int error code
 */
int check_load_flags(Elf *elf) {
    int count = 0;

    if (elf->class == ELFCLASS32) {
        for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
            if (elf->data.elf32.phdr[i].p_type == PT_LOAD) {
                // flags:E
                if (elf->data.elf32.phdr[i].p_flags & 0x1) {
                    count++;
                }
            }
        }
    }

    if (elf->class == ELFCLASS64) {
        for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
            if (elf->data.elf64.phdr[i].p_type == PT_LOAD) {
                // flags:E
                if (elf->data.elf64.phdr[i].p_flags & 0x1) {
                    count++;
                }
            }
        }
    }

    PRINT_DEBUG("executable segment count: %d\n", count);
    if (count > 1) {
        return FALSE;
    } else if (count == 1) {
        return TRUE;
    } else if (count == 0) {
        return ERR_CLASS;
    } 
}

/**
 * @brief 检查段是否连续
 * check if the load segments are continuous
 * @param elf elf file handle struct
 * @return int error code
 */
int check_load_continuity(Elf *elf) {
    int last = 0;
    int current = 0;
    int has_first = 0;

    if (elf->class == ELFCLASS32) {
        for (int i = 0; i < elf->data.elf32.ehdr->e_phnum; i++) {
            if (elf->data.elf32.phdr[i].p_type == PT_LOAD) {
                if (!has_first) {
                    has_first = 1;
                    last = i;
                    continue;
                }
                
                current = i;
                if (current - last != 1) {
                    return FALSE;
                }
                last = i;
            }
        }
    } if (elf->class == ELFCLASS64) {
        for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
            if (elf->data.elf64.phdr[i].p_type == PT_LOAD) {
                if (!has_first) {
                    has_first = 1;
                    last = i;
                    continue;
                }
                
                current = i;
                if (current - last != 1) {
                    return FALSE;
                }
                last = i;
            }
        }
    } else {
        return ERR_CLASS;
    }

    return TRUE;
}

/**
 * @brief 检查DT_NEEDED是否连续
 * check if the DT_NEEDED so are continuous
 * @param elf elf file handle struct
 * @return int error code
 */
int check_needed_continuity(Elf *elf) {
    int last = 0;
    int current = 0;
    int has_first = 0;
    int ret = 0;

    if (elf->class == ELFCLASS32) {
        Elf32_Dyn *dyn = NULL;
        uint32_t dyn_c;
        for (int i = 0; i < elf->data.elf32.ehdr->e_phnum; i++) {
            if (elf->data.elf32.phdr[i].p_type == PT_DYNAMIC) {
                dyn = (Elf32_Dyn *)(elf->mem + elf->data.elf32.phdr[i].p_offset);
                dyn_c = elf->data.elf32.phdr[i].p_filesz / sizeof(Elf32_Dyn);
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
    } if (elf->class == ELFCLASS64) {
        Elf64_Dyn *dyn = NULL;
        uint64_t dyn_c;
        for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
            if (elf->data.elf64.phdr[i].p_type == PT_DYNAMIC) {
                dyn = (Elf64_Dyn *)(elf->mem + elf->data.elf64.phdr[i].p_offset);
                dyn_c = elf->data.elf64.phdr[i].p_filesz / sizeof(Elf64_Dyn);
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
    } else {
        return ERR_CLASS;
    }

    if (last == 0)
        return TRUE;
    else
        return FALSE;
}

/**
 * @brief 检查节头表是否存在
 * check if the section header table exists
 * @param elf elf file handle struct
 * @return int error code {-1:error,0:sucess,1:failed,2:warn}
 */
int check_shdr(Elf *elf) {
    int ret = 0;

    if (elf->class == ELFCLASS32) {
        if (elf->data.elf32.ehdr->e_shoff == 0 || elf->data.elf32.ehdr->e_shnum == 0) {
            ret = 1;
        } else if (elf->data.elf32.ehdr->e_shoff != elf->size - sizeof(Elf32_Shdr) * elf->data.elf32.ehdr->e_shnum) {
            ret = 2;
        }
    } else if (elf->class == ELFCLASS64) {
        if (elf->data.elf64.ehdr->e_shoff == 0 || elf->data.elf64.ehdr->e_shnum == 0) {
            ret = 1;
        } else if (elf->data.elf64.ehdr->e_shoff != elf->size - sizeof(Elf64_Shdr) * elf->data.elf64.ehdr->e_shnum) {
            ret = 2;
        }
    } else {
        return ERR_CLASS;
    }

    return ret;
}

/**
 * @brief 检查dynstr是否连续以及字符串是否存在空格
 * check if the dynstr segments are continuous and whether there are extra spaces in the string
 * @param elf elf file handle struct
 * @return int error code {-1:error,0:sucess,1:failed}
 */
int check_dynstr(Elf *elf) {
    char *name;
    int ret = 0;
    int dynsym_i = 0, dynstr_i = 0;
    char *tmp;
    size_t tmp_size = 1;
    if (elf->class == ELFCLASS32) {
        for (int i = 0; i < elf->data.elf32.ehdr->e_shnum; i++) {
            name = elf->mem + elf->data.elf32.shstrtab->sh_offset + elf->data.elf32.shdr[i].sh_name;
            if (validated_offset((uintptr_t)name, (uintptr_t)elf->mem, (uintptr_t)elf->mem + elf->size)) {
                PRINT_ERROR("Corrupt file format\n");
                ret = -1;
            }
            if (!strcmp(name, ".dynsym")) dynsym_i = i;
            if (!strcmp(name, ".dynstr")) dynstr_i = i;
        }
        /* check if the dynstr segments are continuous */
        if (elf->data.elf32.shdr[dynsym_i].sh_offset + elf->data.elf32.shdr[dynsym_i].sh_size != elf->data.elf32.shdr[dynstr_i].sh_offset)
            ret = 1;
        /* check if the string length is less than original one */
        tmp = elf->mem + elf->data.elf32.shdr[dynstr_i].sh_offset + 1;
        while (tmp_size < elf->data.elf32.shdr[dynstr_i].sh_size) {
            tmp_size += strlen(tmp) + 1;
            PRINT_DEBUG("%s 0x%x\n", tmp, tmp_size);
            tmp += strlen(tmp) + 1;
            if (tmp_size != elf->data.elf32.shdr[dynstr_i].sh_size && strlen(tmp) == 0) {
                ret = 1;
                break;
            }
            ret = 0;
        }
    } else if (elf->class == ELFCLASS64) {
        for (int i = 0; i < elf->data.elf64.ehdr->e_shnum; i++) {
            name = elf->mem + elf->data.elf64.shstrtab->sh_offset + elf->data.elf64.shdr[i].sh_name;
            if (validated_offset((uintptr_t)name, (uintptr_t)elf->mem, (uintptr_t)elf->mem + elf->size)) {
                PRINT_ERROR("Corrupt file format\n");
                ret = -1;
            }
            if (!strcmp(name, ".dynsym")) dynsym_i = i;
            if (!strcmp(name, ".dynstr")) dynstr_i = i;
        }
        /* check if the dynstr segments are continuous */
        if (elf->data.elf64.shdr[dynsym_i].sh_offset + elf->data.elf64.shdr[dynsym_i].sh_size != elf->data.elf64.shdr[dynstr_i].sh_offset)
            ret = 1;
        /* check if the string length is less than original one */
        tmp = elf->mem + elf->data.elf64.shdr[dynstr_i].sh_offset + 1;
        while (tmp_size < elf->data.elf64.shdr[dynstr_i].sh_size) {
            tmp_size += strlen(tmp) + 1;
            PRINT_DEBUG("%s 0x%x\n", tmp, tmp_size);
            tmp += strlen(tmp) + 1;
            if (tmp_size != elf->data.elf64.shdr[dynstr_i].sh_size && strlen(tmp) == 0) {
                ret = 1;
                break;
            }
            ret = 0;
        }
    } else {
        return ERR_CLASS;
    }

    return ret;
}

/**
 * @brief 检查interpreter
 * check if the interpreter is legal
 * @param elf elf file handle struct
 * @return int error code {-1:error,0:sucess,1:failed}
 */
int check_interpreter(Elf *elf) {
    char *name;
    int ret = 0;
    int interp_i = -1;
    char *tmp;
    size_t tmp_size = 1;
    if (elf->class == ELFCLASS32) {
        for (int i = 0; i < elf->data.elf32.ehdr->e_shnum; i++) {
            name = elf->mem + elf->data.elf32.shstrtab->sh_offset + elf->data.elf32.shdr[i].sh_name;
            if (validated_offset((uintptr_t)name, (uintptr_t)elf->mem, (uintptr_t)elf->mem + elf->size)) {
                PRINT_ERROR("Corrupt file format\n");
                ret = -1;
            }
            if (!strcmp(name, ".interp")) interp_i = i;
        }
        name = elf->mem + elf->data.elf32.shdr[interp_i].sh_offset;
        /* check index */
        /*
        if (interp_i == -1) {
            ret = -1;
        }
        else if (interp_i > 2) {
            ret = 1;
        }*/
        /* check if the string length is less than original one */
        if (strlen(name) != elf->data.elf32.shdr[interp_i].sh_size - 1) {
            ret = 1;
        }
    }
    else if (elf->class == ELFCLASS64) {
        for (int i = 0; i < elf->data.elf64.ehdr->e_shnum; i++) {
            name = elf->mem + elf->data.elf64.shstrtab->sh_offset + elf->data.elf64.shdr[i].sh_name;
            if (validated_offset((uintptr_t)name, (uintptr_t)elf->mem, (uintptr_t)elf->mem + elf->size)) {
                PRINT_ERROR("Corrupt file format\n");
                ret = -1;
            }
            if (!strcmp(name, ".interp")) interp_i = i;
        }
        name = elf->mem + elf->data.elf64.shdr[interp_i].sh_offset;
        /* check index */
        /*
        if (interp_i == -1) {
            ret = -1;
        }
        else if (interp_i > 2) {
            ret = 1;
        }*/
        /* check if the string length is less than original one */
        if (strlen(name) != elf->data.elf64.shdr[interp_i].sh_size - 1) {
            ret = 1;
        }
    }

    return ret;
}

/**
 * @brief 检查elf文件是否合法
 * check if the elf file is legal
 * @param elf elf file custom structure
 * @return error code
 */
int checksec(Elf *elf) {
    char *mode, *tmp, *bind;
    char elf_info[1000];
    int err;
    enum ELF_TYPE type;
    type = get_elf_type(elf);
    if (elf->class == ELFCLASS32) {
        mode = "32-bit";
    } else if (elf->class == ELFCLASS64) {
        mode = "64-bit";
    } else {
        mode = "Known";
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
    uint64_t entry = elf->class == ELFCLASS32? elf->data.elf32.ehdr->e_entry:elf->data.elf64.ehdr->e_entry;
    uint64_t addr = get_section_addr_by_name(elf, ".text");
    size_t size = get_section_size_by_name(elf, ".text");
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
        addr = get_section_addr_by_name(elf, ".plt");
        size = get_section_size_by_name(elf, ".plt");
        err = check_hook(elf, addr, size);
        switch (err)
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
    err = check_load_flags(elf);
    switch (err)
    {
        case TRUE:
            CHECK_COMMON("|%-20s|%1s| %-50s|\n", TAG, "✓", "normal");
            break;

        case FALSE:
            CHECK_ERROR("|%-20s|%1s| %-50s|\n", TAG, "✗", "more than one executable segment");
            break;

        default:
            CHECK_COMMON("|%-20s|%1s| %-50s|\n", TAG, "-", "na(no executable elf file)");
            break;
    }

    /* check segment continuity */
    strcpy(TAG, "segment continuity");
    err = check_load_continuity(elf);
    switch (err)
    {
        case TRUE:
            CHECK_COMMON("|%-20s|%1s| %-50s|\n", TAG, "✓", "normal");
            break;

        case FALSE:
            CHECK_ERROR("|%-20s|%1s| %-50s|\n", TAG, "✗", "load segments are NOT continuous");
            break;

        default:
            CHECK_COMMON("|%-20s|%1s| %-50s|\n", TAG, "-", "na");
            break;
    }

    /* check DLL injection */
    strcpy(TAG, "DLL injection");
    err = check_needed_continuity(elf);
    switch (err)
    {
        case TRUE:
            CHECK_COMMON("|%-20s|%1s| %-50s|\n", TAG, "✓", "normal");
            break;

        case FALSE:
            CHECK_ERROR("|%-20s|%1s| %-50s|\n", TAG, "✗", "DT_NEEDED libraries are NOT continuous");
            break;

        default:
            CHECK_COMMON("|%-20s|%1s| %-50s|\n", TAG, "-", "na(statically linked)");
            break;
    }

    /* check section header table */
    strcpy(TAG, "section header table");
    err = check_shdr(elf);
    switch (err)
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
    err = check_dynstr(elf);
    switch (err)
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
    err = check_interpreter(elf);
    switch (err)
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
    return 0;
}