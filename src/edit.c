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
#include <stdlib.h>
#include "parse.h"

int edit_dyn_name_value(Elf *elf, int index, char *name) {
    if (elf->class == ELFCLASS32) {
        char *origin_name = elf->mem + elf->data.elf32.dynstrtab->sh_offset + elf->data.elf32.dyn[index].d_un.d_val;
        // 1. copy name
        if (strlen(name) <= strlen(origin_name)) {
            memset(origin_name, 0, strlen(origin_name) + 1);
            strcpy(origin_name, name);
            return NO_ERR;
        } 
        // 2. if new name length > origin_name
        else {
            uint64_t offset = 0;
            int err = add_dynstr_name(elf, name, &offset);
            if (err != NO_ERR) {
                PRINT_ERROR("add dynstr name error :%d\n", err);
                return err;
            }
            elf->data.elf32.dyn[index].d_un.d_val = offset;
            return NO_ERR;
        }
    } if (elf->class == ELFCLASS64) {
        char *origin_name = elf->mem + elf->data.elf64.dynstrtab->sh_offset + elf->data.elf64.dyn[index].d_un.d_val;
        // 1. copy name
        if (strlen(name) <= strlen(origin_name)) {
            memset(origin_name, 0, strlen(origin_name) + 1);
            strcpy(origin_name, name);
            return NO_ERR;
        } 
        // 2. if new name length > origin_name
        else {
            uint64_t offset = 0;
            int err = add_dynstr_name(elf, name, &offset);
            if (err != NO_ERR) {
                PRINT_ERROR("add dynstr name error :%d\n", err);
                return err;
            }
            elf->data.elf64.dyn[index].d_un.d_val = offset;
            return NO_ERR;
        }
    } else {
        return ERR_ELF_CLASS;
    }
}

int edit64(Elf *elf, parser_opt_t *po, int row, int column, int value, char *section_name, char *dst_name) {
    int err = 0;
    int src_value = 0;
    char *src_string = NULL;

    /* edit ELF header information */
    if (!get_option(po, HEADERS)) {
        switch (row)
        {
            case 0:
                src_value = elf->data.elf64.ehdr->e_type;
                elf->data.elf64.ehdr->e_type = value;
                break;

            case 1:
                src_value = elf->data.elf64.ehdr->e_machine;
                elf->data.elf64.ehdr->e_machine = value;
                break;

            case 2:
                src_value = elf->data.elf64.ehdr->e_version;
                elf->data.elf64.ehdr->e_version = value;
                break;

            case 3:
                src_value = elf->data.elf64.ehdr->e_entry;
                elf->data.elf64.ehdr->e_entry = value;
                break;

            case 4:
                src_value = elf->data.elf64.ehdr->e_phoff;
                elf->data.elf64.ehdr->e_phoff = value;
                break;

            case 5:
                src_value = elf->data.elf64.ehdr->e_shoff;
                elf->data.elf64.ehdr->e_shoff = value;
                break;

            case 6:
                src_value = elf->data.elf64.ehdr->e_flags;
                elf->data.elf64.ehdr->e_flags = value;
                break;

            case 7:
                src_value = elf->data.elf64.ehdr->e_ehsize;
                elf->data.elf64.ehdr->e_ehsize = value;
                break;

            case 8:
                src_value = elf->data.elf64.ehdr->e_phentsize;
                elf->data.elf64.ehdr->e_phentsize = value;
                break;

            case 9:
                src_value = elf->data.elf64.ehdr->e_phnum;
                elf->data.elf64.ehdr->e_phnum = value;
                break;

            case 10:
                src_value = elf->data.elf64.ehdr->e_shentsize;
                elf->data.elf64.ehdr->e_shentsize = value;
                break;
            
            case 11:
                src_value = elf->data.elf64.ehdr->e_shnum;
                elf->data.elf64.ehdr->e_shnum = value;
                break;
            
            case 12:
                src_value = elf->data.elf64.ehdr->e_shstrndx;
                elf->data.elf64.ehdr->e_shstrndx = value;
                break;
            
            default:
                goto OUT_OF_BOUNDS;
                break;
        }
    }

    /* edit section informtion */
    if (!get_option(po, SECTIONS)) {
        switch (column)
        {
            case 0:
                src_value = elf->data.elf64.shdr[row].sh_name;
                if (!strlen(dst_name)) {
                    elf->data.elf64.shdr[row].sh_name = value;
                } else {
                    char *sec_name = elf->mem + elf->data.elf64.shstrtab->sh_offset + elf->data.elf64.shdr[row].sh_name;
                    src_string = (char *)malloc(strlen(sec_name) + 1);
                    strcpy(src_string, sec_name);
                    err = set_section_name_t(elf, sec_name, dst_name);
                    if (err == NO_ERR)
                        goto PRINT_STRING;
                    else
                        goto OUT_OF_BOUNDS;
                }
                break;

            case 1:
                src_value = elf->data.elf64.shdr[row].sh_type;
                elf->data.elf64.shdr[row].sh_type = value;
                break;

            case 2:
                src_value = elf->data.elf64.shdr[row].sh_addr;
                elf->data.elf64.shdr[row].sh_addr = value;
                break;

            case 3:
                src_value = elf->data.elf64.shdr[row].sh_offset;
                elf->data.elf64.shdr[row].sh_offset = value;
                break;

            case 4:
                src_value = elf->data.elf64.shdr[row].sh_size;
                elf->data.elf64.shdr[row].sh_size = value;
                break;

            case 5:
                src_value = elf->data.elf64.shdr[row].sh_entsize;
                elf->data.elf64.shdr[row].sh_entsize = value;
                break;

            case 6:
                src_value = elf->data.elf64.shdr[row].sh_flags;
                elf->data.elf64.shdr[row].sh_flags = value;
                break;

            case 7:
                src_value = elf->data.elf64.shdr[row].sh_link;
                elf->data.elf64.shdr[row].sh_link = value;
                break;

            case 8:
                src_value = elf->data.elf64.shdr[row].sh_info;
                elf->data.elf64.shdr[row].sh_info = value;
                break;

            case 9:
                src_value = elf->data.elf64.shdr[row].sh_addralign;
                elf->data.elf64.shdr[row].sh_addralign = value;
                break;
            
            default:
                goto OUT_OF_BOUNDS;
                break;
        }
    }
    
    /* edit segment information */
    if (!get_option(po, SEGMENTS)) {
        switch (column)
        {
            case 0:
                src_value = elf->data.elf64.phdr[row].p_type;
                elf->data.elf64.phdr[row].p_type = value;
                break;

            case 1:
                src_value = elf->data.elf64.phdr[row].p_offset;
                elf->data.elf64.phdr[row].p_offset = value;
                break;

            case 2:
                src_value = elf->data.elf64.phdr[row].p_vaddr;
                elf->data.elf64.phdr[row].p_vaddr = value;
                break;

            case 3:
                src_value = elf->data.elf64.phdr[row].p_paddr;
                elf->data.elf64.phdr[row].p_paddr = value;
                break;

            case 4:
                src_value = elf->data.elf64.phdr[row].p_filesz;
                elf->data.elf64.phdr[row].p_filesz = value;
                break;

            case 5:
                src_value = elf->data.elf64.phdr[row].p_memsz;
                elf->data.elf64.phdr[row].p_memsz = value;
                break;

            case 6:
                src_value = elf->data.elf64.phdr[row].p_flags;
                elf->data.elf64.phdr[row].p_flags = value;
                break;

            case 7:
                src_value = elf->data.elf64.phdr[row].p_align;
                elf->data.elf64.phdr[row].p_align = value;
                break;
            
            default:
                goto OUT_OF_BOUNDS;
                break;
        }
    }

    /* edit .dynsym informtion */
    if (!get_option(po, DYNSYM)) {
        int type = 0;
        int bind = 0;
        switch (column)
        {
            case 0:
                src_value = elf->data.elf64.dynsym_entry[row].st_value;
                elf->data.elf64.dynsym_entry[row].st_value = value;
                break;

            case 1:
                src_value = elf->data.elf64.dynsym_entry[row].st_size;
                elf->data.elf64.dynsym_entry[row].st_size = value;
                break;

            case 2:
                type = ELF64_ST_TYPE(elf->data.elf64.dynsym_entry[row].st_info);
                bind = ELF64_ST_BIND(elf->data.elf64.dynsym_entry[row].st_info);
                src_value = type;
                elf->data.elf64.dynsym_entry[row].st_info = ELF64_ST_INFO(bind, value);
                break;

            case 3:
                type = ELF64_ST_TYPE(elf->data.elf64.dynsym_entry[row].st_info);
                bind = ELF64_ST_BIND(elf->data.elf64.dynsym_entry[row].st_info);
                src_value = bind;
                elf->data.elf64.dynsym_entry[row].st_info = ELF64_ST_INFO(value, type);
                break;

            case 4:
                src_value = elf->data.elf64.dynsym_entry[row].st_other;
                elf->data.elf64.dynsym_entry[row].st_other = value;
                break;

            case 5:
                src_value = elf->data.elf64.dynsym_entry[row].st_shndx;
                elf->data.elf64.dynsym_entry[row].st_shndx = value;
                break;

            case 6:
                if (!strlen(dst_name)) {
                    src_value = elf->data.elf64.dynsym_entry[row].st_name;
                    elf->data.elf64.dynsym_entry[row].st_name = value;
                } else {
                    char *name = elf->mem + elf->data.elf64.dynstrtab->sh_offset + elf->data.elf64.dynsym_entry[row].st_name;
                    src_string = (char *)malloc(strlen(name) + 1);
                    strcpy(src_string, name);
                    err = set_dynstr_name(elf, name, dst_name);
                    if (err == NO_ERR)
                        goto PRINT_STRING;
                    else
                        goto OUT_OF_BOUNDS;
                    }
                break;
            
            default:
                break;
        }
    }

    /* edit .symtab informtion */
    if (!get_option(po, SYMTAB)) {
        int type = 0;
        int bind = 0;
        switch (column)
        {
            case 0:
                src_value = elf->data.elf64.sym_entry[row].st_value;
                elf->data.elf64.sym_entry[row].st_value = value;
                break;

            case 1:
                src_value = elf->data.elf64.sym_entry[row].st_size;
                elf->data.elf64.sym_entry[row].st_size = value;
                break;

            case 2:
                type = ELF64_ST_TYPE(elf->data.elf64.sym_entry[row].st_info);
                bind = ELF64_ST_BIND(elf->data.elf64.sym_entry[row].st_info);
                src_value = type;
                elf->data.elf64.sym_entry[row].st_info = ELF64_ST_INFO(bind, value);
                break;

            case 3:
                type = ELF64_ST_TYPE(elf->data.elf64.sym_entry[row].st_info);
                bind = ELF64_ST_BIND(elf->data.elf64.sym_entry[row].st_info);
                src_value = bind;
                elf->data.elf64.sym_entry[row].st_info = ELF64_ST_INFO(value, type);
                break;

            case 4:
                src_value = elf->data.elf64.sym_entry[row].st_other;
                elf->data.elf64.sym_entry[row].st_other = value;
                break;

            case 5:
                src_value = elf->data.elf64.sym_entry[row].st_shndx;
                elf->data.elf64.sym_entry[row].st_shndx = value;
                break;

            case 6:
                if (!strlen(dst_name)) {
                    src_value = elf->data.elf64.sym_entry[row].st_name;
                    elf->data.elf64.sym_entry[row].st_name = value;
                } else {
                    char *name = elf->mem + elf->data.elf64.strtab->sh_offset + elf->data.elf64.sym_entry[row].st_name;
                    src_string = (char *)malloc(strlen(name) + 1);
                    strcpy(src_string, name);
                    err = set_sym_name_t(elf, name, dst_name);
                    if (err == NO_ERR)
                        goto PRINT_STRING;
                    else
                        goto OUT_OF_BOUNDS;
                }
                break;
            
            default:
                break;
        }
    }

    /* edit .rel and .rela informtion */
    if (!get_option(po, RELA)) {
        if (compare_firstN_chars(section_name, ".rel.", 5)) {
            int rel_index = get_section_index_by_name(elf, section_name);
            Elf64_Rel *rel = (Elf64_Rel *)(elf->mem + elf->data.elf64.shdr[rel_index].sh_offset);
            switch (column)
            {
                case 0:
                    src_value = rel[row].r_offset;
                    rel[row].r_offset = value;
                    break;

                case 1:
                    src_value = rel[row].r_info;
                    rel[row].r_info = value;
                    break;

                case 2:
                    src_value = ELF64_R_TYPE(rel[row].r_info);
                    rel[row].r_info = ELF64_R_INFO(ELF64_R_SYM(rel[row].r_info), value);
                    break;

                case 3:
                    src_value = ELF64_R_SYM(rel[row].r_info);
                    rel[row].r_info = ELF64_R_INFO(value, ELF64_R_TYPE(rel[row].r_info));
                    break;
                
                default:
                    break;
            }
        }
        if (compare_firstN_chars(section_name, ".rela", 5)) {
            int rela_index = get_section_index_by_name(elf, section_name);
            Elf64_Rela *rela = (Elf64_Rela *)(elf->mem + elf->data.elf64.shdr[rela_index].sh_offset);
            switch (column)
            {
                case 0:
                    src_value = rela[row].r_offset;
                    rela[row].r_offset = value;
                    break;

                case 1:
                    src_value = rela[row].r_info;
                    rela[row].r_info = value;
                    break;

                case 2:
                    src_value = ELF64_R_TYPE(rela[row].r_info);
                    rela[row].r_info = ELF64_R_INFO(ELF64_R_SYM(rela[row].r_info), value);
                    break;

                case 3:
                    src_value = ELF64_R_SYM(rela[row].r_info);
                    rela[row].r_info = ELF64_R_INFO(value, ELF64_R_TYPE(rela[row].r_info));
                    break;

                case 4:
                    src_value = rela[row].r_addend;
                    rela[row].r_addend = value;
                
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
            case 1:
                src_value = elf->data.elf64.dyn[row].d_tag;
                elf->data.elf64.dyn[row].d_tag = value;
                break;

            case 2:
                if (!strlen(dst_name)) {
                    src_value = elf->data.elf64.dyn[row].d_un.d_val;
                    elf->data.elf64.dyn[row].d_un.d_val = value;
                } else {
                    char *name = elf->mem + elf->data.elf64.dynstrtab->sh_offset + elf->data.elf64.dyn[row].d_un.d_val;
                    src_string = (char *)malloc(strlen(name) + 1);
                    strcpy(src_string, name);
                    err = edit_dyn_name_value(elf, row, dst_name);
                    if (err == NO_ERR)
                        goto PRINT_STRING;
                    else
                        goto OUT_OF_BOUNDS;
                }
                break;
            
            default:
                break;
        }
    }

    /* edit pointer information */
    if (!get_option(po, POINTER)) {
        int i = get_section_index_by_name(elf, section_name);
        uint64_t *sec = NULL;
        switch (column)
        {
            case 0:
                /* 64bit */
                sec = (uint64_t *)(elf->mem + elf->data.elf64.shdr[i].sh_offset);
                int count = elf->data.elf64.shdr[i].sh_size / sizeof(uint64_t);
                if (row >= count) {
                    err = ERR_ARGS;
                    goto OUT_OF_BOUNDS;
                }
                src_value = sec[row];
                sec[row] = value;
                break;

            case 1:
                PRINT_WARNING("you can edit symbol by option '-B' instead of '-I'\n");
                goto OUT_OF_BOUNDS;
                break;
            
            default:
                break;
        }
    }

    PRINT_INFO("0x%x->0x%x\n" ,src_value, value);
    if (src_string) free(src_string);
    return err;
PRINT_STRING:
    PRINT_INFO("%s->%s\n" ,src_string, dst_name);
    if (src_string) free(src_string);
    return err;
OUT_OF_BOUNDS:
    PRINT_WARNING("Please check if the entered coordinates are out of bounds\n");
    if (src_string) free(src_string);
    return err;
}

int edit32(Elf *elf, parser_opt_t *po, int row, int column, int value, char *section_name, char *dst_name) {
    int err = 0;
    int src_value = 0;
    char *src_string = NULL;

    /* edit ELF header information */
    if (!get_option(po, HEADERS)) {
        switch (row)
        {
            case 0:
                src_value = elf->data.elf32.ehdr->e_type;
                elf->data.elf32.ehdr->e_type = value;
                break;

            case 1:
                src_value = elf->data.elf32.ehdr->e_machine;
                elf->data.elf32.ehdr->e_machine = value;
                break;

            case 2:
                src_value = elf->data.elf32.ehdr->e_version;
                elf->data.elf32.ehdr->e_version = value;
                break;

            case 3:
                src_value = elf->data.elf32.ehdr->e_entry;
                elf->data.elf32.ehdr->e_entry = value;
                break;

            case 4:
                src_value = elf->data.elf32.ehdr->e_phoff;
                elf->data.elf32.ehdr->e_phoff = value;
                break;

            case 5:
                src_value = elf->data.elf32.ehdr->e_shoff;
                elf->data.elf32.ehdr->e_shoff = value;
                break;

            case 6:
                src_value = elf->data.elf32.ehdr->e_flags;
                elf->data.elf32.ehdr->e_flags = value;
                break;

            case 7:
                src_value = elf->data.elf32.ehdr->e_ehsize;
                elf->data.elf32.ehdr->e_ehsize = value;
                break;

            case 8:
                src_value = elf->data.elf32.ehdr->e_phentsize;
                elf->data.elf32.ehdr->e_phentsize = value;
                break;

            case 9:
                src_value = elf->data.elf32.ehdr->e_phnum;
                elf->data.elf32.ehdr->e_phnum = value;
                break;

            case 10:
                src_value = elf->data.elf32.ehdr->e_shentsize;
                elf->data.elf32.ehdr->e_shentsize = value;
                break;
            
            case 11:
                src_value = elf->data.elf32.ehdr->e_shnum;
                elf->data.elf32.ehdr->e_shnum = value;
                break;
            
            case 12:
                src_value = elf->data.elf32.ehdr->e_shstrndx;
                elf->data.elf32.ehdr->e_shstrndx = value;
                break;
            
            default:
                goto OUT_OF_BOUNDS;
                break;
        }
    }

    /* edit section informtion */
    if (!get_option(po, SECTIONS)) {
        switch (column)
        {
            case 0:
                src_value = elf->data.elf32.shdr[row].sh_name;
                if (!strlen(dst_name)) {
                    elf->data.elf32.shdr[row].sh_name = value;
                } else {
                    char *sec_name = elf->mem + elf->data.elf32.shstrtab->sh_offset + elf->data.elf32.shdr[row].sh_name;
                    src_string = (char *)malloc(strlen(sec_name) + 1);
                    strcpy(src_string, sec_name);
                    err = set_section_name_t(elf, sec_name, dst_name);
                    if (err == NO_ERR)
                        goto PRINT_STRING;
                    else
                        goto OUT_OF_BOUNDS;
                }
                break;

            case 1:
                src_value = elf->data.elf32.shdr[row].sh_type;
                elf->data.elf32.shdr[row].sh_type = value;
                break;

            case 2:
                src_value = elf->data.elf32.shdr[row].sh_addr;
                elf->data.elf32.shdr[row].sh_addr = value;
                break;

            case 3:
                src_value = elf->data.elf32.shdr[row].sh_offset;
                elf->data.elf32.shdr[row].sh_offset = value;
                break;

            case 4:
                src_value = elf->data.elf32.shdr[row].sh_size;
                elf->data.elf32.shdr[row].sh_size = value;
                break;

            case 5:
                src_value = elf->data.elf32.shdr[row].sh_entsize;
                elf->data.elf32.shdr[row].sh_entsize = value;
                break;

            case 6:
                src_value = elf->data.elf32.shdr[row].sh_flags;
                elf->data.elf32.shdr[row].sh_flags = value;
                break;

            case 7:
                src_value = elf->data.elf32.shdr[row].sh_link;
                elf->data.elf32.shdr[row].sh_link = value;
                break;

            case 8:
                src_value = elf->data.elf32.shdr[row].sh_info;
                elf->data.elf32.shdr[row].sh_info = value;
                break;

            case 9:
                src_value = elf->data.elf32.shdr[row].sh_addralign;
                elf->data.elf32.shdr[row].sh_addralign = value;
                break;
            
            default:
                goto OUT_OF_BOUNDS;
                break;
        }
    }
    
    /* edit segment information */
    if (!get_option(po, SEGMENTS)) {
        switch (column)
        {
            case 0:
                src_value = elf->data.elf32.phdr[row].p_type;
                elf->data.elf32.phdr[row].p_type = value;
                break;

            case 1:
                src_value = elf->data.elf32.phdr[row].p_offset;
                elf->data.elf32.phdr[row].p_offset = value;
                break;

            case 2:
                src_value = elf->data.elf32.phdr[row].p_vaddr;
                elf->data.elf32.phdr[row].p_vaddr = value;
                break;

            case 3:
                src_value = elf->data.elf32.phdr[row].p_paddr;
                elf->data.elf32.phdr[row].p_paddr = value;
                break;

            case 4:
                src_value = elf->data.elf32.phdr[row].p_filesz;
                elf->data.elf32.phdr[row].p_filesz = value;
                break;

            case 5:
                src_value = elf->data.elf32.phdr[row].p_memsz;
                elf->data.elf32.phdr[row].p_memsz = value;
                break;

            case 6:
                src_value = elf->data.elf32.phdr[row].p_flags;
                elf->data.elf32.phdr[row].p_flags = value;
                break;

            case 7:
                src_value = elf->data.elf32.phdr[row].p_align;
                elf->data.elf32.phdr[row].p_align = value;
                break;
            
            default:
                goto OUT_OF_BOUNDS;
                break;
        }
    }

    /* edit .dynsym informtion */
    if (!get_option(po, DYNSYM)) {
        int type = 0;
        int bind = 0;
        switch (column)
        {
            case 0:
                src_value = elf->data.elf32.dynsym_entry[row].st_value;
                elf->data.elf32.dynsym_entry[row].st_value = value;
                break;

            case 1:
                src_value = elf->data.elf32.dynsym_entry[row].st_size;
                elf->data.elf32.dynsym_entry[row].st_size = value;
                break;

            case 2:
                type = ELF32_ST_TYPE(elf->data.elf32.dynsym_entry[row].st_info);
                bind = ELF32_ST_BIND(elf->data.elf32.dynsym_entry[row].st_info);
                src_value = type;
                elf->data.elf32.dynsym_entry[row].st_info = ELF32_ST_INFO(bind, value);
                break;

            case 3:
                type = ELF32_ST_TYPE(elf->data.elf32.dynsym_entry[row].st_info);
                bind = ELF32_ST_BIND(elf->data.elf32.dynsym_entry[row].st_info);
                src_value = bind;
                elf->data.elf32.dynsym_entry[row].st_info = ELF32_ST_INFO(value, type);
                break;

            case 4:
                src_value = elf->data.elf32.dynsym_entry[row].st_other;
                elf->data.elf32.dynsym_entry[row].st_other = value;
                break;

            case 5:
                src_value = elf->data.elf32.dynsym_entry[row].st_shndx;
                elf->data.elf32.dynsym_entry[row].st_shndx = value;
                break;

            case 6:
                if (!strlen(dst_name)) {
                    src_value = elf->data.elf32.dynsym_entry[row].st_name;
                    elf->data.elf32.dynsym_entry[row].st_name = value;
                } else {
                    char *name = elf->mem + elf->data.elf32.dynstrtab->sh_offset + elf->data.elf32.dynsym_entry[row].st_name;
                    src_string = (char *)malloc(strlen(name) + 1);
                    strcpy(src_string, name);
                    err = set_dynstr_name(elf, name, dst_name);
                    if (err == NO_ERR)
                        goto PRINT_STRING;
                    else
                        goto OUT_OF_BOUNDS;
                    }
                break;
            
            default:
                break;
        }
    }

    /* edit .symtab informtion */
    if (!get_option(po, SYMTAB)) {
        int type = 0;
        int bind = 0;
        switch (column)
        {
            case 0:
                src_value = elf->data.elf32.sym_entry[row].st_value;
                elf->data.elf32.sym_entry[row].st_value = value;
                break;

            case 1:
                src_value = elf->data.elf32.sym_entry[row].st_size;
                elf->data.elf32.sym_entry[row].st_size = value;
                break;

            case 2:
                type = ELF32_ST_TYPE(elf->data.elf32.sym_entry[row].st_info);
                bind = ELF32_ST_BIND(elf->data.elf32.sym_entry[row].st_info);
                src_value = type;
                elf->data.elf32.sym_entry[row].st_info = ELF32_ST_INFO(bind, value);
                break;

            case 3:
                type = ELF32_ST_TYPE(elf->data.elf32.sym_entry[row].st_info);
                bind = ELF32_ST_BIND(elf->data.elf32.sym_entry[row].st_info);
                src_value = bind;
                elf->data.elf32.sym_entry[row].st_info = ELF32_ST_INFO(value, type);
                break;

            case 4:
                src_value = elf->data.elf32.sym_entry[row].st_other;
                elf->data.elf32.sym_entry[row].st_other = value;
                break;

            case 5:
                src_value = elf->data.elf32.sym_entry[row].st_shndx;
                elf->data.elf32.sym_entry[row].st_shndx = value;
                break;

            case 6:
                if (!strlen(dst_name)) {
                    src_value = elf->data.elf32.sym_entry[row].st_name;
                    elf->data.elf32.sym_entry[row].st_name = value;
                } else {
                    char *name = elf->mem + elf->data.elf32.strtab->sh_offset + elf->data.elf32.sym_entry[row].st_name;
                    src_string = (char *)malloc(strlen(name) + 1);
                    strcpy(src_string, name);
                    err = set_sym_name_t(elf, name, dst_name);
                    if (err == NO_ERR)
                        goto PRINT_STRING;
                    else
                        goto OUT_OF_BOUNDS;
                }
                break;
            
            default:
                break;
        }
    }

    /* edit .rel and .rela informtion */
    if (!get_option(po, RELA)) {
        if (compare_firstN_chars(section_name, ".rel.", 5)) {
            int rel_index = get_section_index_by_name(elf, section_name);
            Elf32_Rel *rel = (Elf32_Rel *)(elf->mem + elf->data.elf32.shdr[rel_index].sh_offset);
            switch (column)
            {
                case 0:
                    src_value = rel[row].r_offset;
                    rel[row].r_offset = value;
                    break;

                case 1:
                    src_value = rel[row].r_info;
                    rel[row].r_info = value;
                    break;

                case 2:
                    src_value = ELF32_R_TYPE(rel[row].r_info);
                    rel[row].r_info = ELF32_R_INFO(ELF32_R_SYM(rel[row].r_info), value);
                    break;

                case 3:
                    src_value = ELF32_R_SYM(rel[row].r_info);
                    rel[row].r_info = ELF32_R_INFO(value, ELF32_R_TYPE(rel[row].r_info));
                    break;
                
                default:
                    break;
            }
        }
        if (compare_firstN_chars(section_name, ".rela", 5)) {
            int rela_index = get_section_index_by_name(elf, section_name);
            Elf32_Rela *rela = (Elf32_Rela *)(elf->mem + elf->data.elf32.shdr[rela_index].sh_offset);
            switch (column)
            {
                case 0:
                    src_value = rela[row].r_offset;
                    rela[row].r_offset = value;
                    break;

                case 1:
                    src_value = rela[row].r_info;
                    rela[row].r_info = value;
                    break;

                case 2:
                    src_value = ELF32_R_TYPE(rela[row].r_info);
                    rela[row].r_info = ELF32_R_INFO(ELF32_R_SYM(rela[row].r_info), value);
                    break;

                case 3:
                    src_value = ELF32_R_SYM(rela[row].r_info);
                    rela[row].r_info = ELF32_R_INFO(value, ELF32_R_TYPE(rela[row].r_info));
                    break;

                case 4:
                    src_value = rela[row].r_addend;
                    rela[row].r_addend = value;
                
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
            case 1:
                src_value = elf->data.elf32.dyn[row].d_tag;
                elf->data.elf32.dyn[row].d_tag = value;
                break;

            case 2:
                if (!strlen(dst_name)) {
                    src_value = elf->data.elf32.dyn[row].d_un.d_val;
                    elf->data.elf32.dyn[row].d_un.d_val = value;
                } else {
                    char *name = elf->mem + elf->data.elf32.dynstrtab->sh_offset + elf->data.elf32.dyn[row].d_un.d_val;
                    src_string = (char *)malloc(strlen(name) + 1);
                    strcpy(src_string, name);
                    err = edit_dyn_name_value(elf, row, dst_name);
                    if (err == NO_ERR)
                        goto PRINT_STRING;
                    else
                        goto OUT_OF_BOUNDS;
                }
                break;
            
            default:
                break;
        }
    }

    /* edit pointer information */
    if (!get_option(po, POINTER)) {
        int i = get_section_index_by_name(elf, section_name);
        uint32_t *sec = NULL;
        switch (column)
        {
            case 0:
                /* 32bit */
                sec = (uint32_t *)(elf->mem + elf->data.elf32.shdr[i].sh_offset);
                int count = elf->data.elf32.shdr[i].sh_size / sizeof(uint32_t);
                if (row >= count) {
                    err = ERR_ARGS;
                    goto OUT_OF_BOUNDS;
                }
                src_value = sec[row];
                sec[row] = value & 0xffff;    // avoid interger overflow
                break;

            case 1:
                PRINT_WARNING("you can edit symbol by option '-B' instead of '-I'\n");
                goto OUT_OF_BOUNDS;
                break;
            
            default:
                break;
        }
    }

    PRINT_INFO("0x%x->0x%x\n" ,src_value, value);
    if (src_string) free(src_string);
    return err;
PRINT_STRING:
    PRINT_INFO("%s->%s\n" ,src_string, dst_name);
    if (src_string) free(src_string);
    return err;
OUT_OF_BOUNDS:
    PRINT_WARNING("Please check if the entered coordinates are out of bounds\n");
    if (src_string) free(src_string);
    return err;
}

/**
 * @brief 编辑ELF的各个字段，依据字段所在的坐标
 * edit the various fields of ELF based on their respective coordinates.
 * @param elf elf file structure
 * @param po selection
 * @param row row-i
 * @param column column-j
 * @param section_name only for rela section
 * @param value int value
 * @param dst_name string value
 * @return error code {-1:error,0:sucess} 
 */
int edit(Elf *elf, parser_opt_t *po, int row, int column, int value, char *section_name, char *dst_name) {
    if (elf->class == ELFCLASS32) {
        return edit32(elf, po, row, column, value, section_name, dst_name);
    } else if (elf->class == ELFCLASS64) {
        return edit64(elf, po, row, column, value, section_name, dst_name);
    } else {
        return ERR_ELF_CLASS;
    }
}