/*
 MIT License
 
 Copyright (c) 2021 SecNotes
 
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

#include <stdio.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "common.h"
#include "section.h"
#include "parse.h"

/**
 * @description: delete data from ELF memory
 * @param {char} *elf_map
 * @param {uint32_t} file_size
 * @param {uint32_t} offset data offset in elf
 * @param {uint32_t} data_size data size
 * @return {*}
 */
char *delete_data_from_mem(char *elf_map, uint32_t file_size, uint32_t offset, uint32_t data_size) {
    char *tmp;
    tmp = malloc(file_size - data_size);
    if (tmp < 0) {
        return NULL;
    }

    memcpy(tmp, elf_map, offset);
    memcpy(&tmp[offset], &elf_map[offset + data_size], file_size - data_size - offset);
    return tmp;
}

/**
 * @brief 从文件中删除特定片段，请注意这个操作会改变文件大小
 * Delete specific fragments from the file, 
 * please note that this operation will change the file size
 * @param file_name file name 
 * @param offset fragment offset
 * @param size fragment size
 * @return int error code {-1:error,0:sucess}
 */
int delete_data_from_file(char *file_name, uint64_t offset, size_t size) {
    FILE *file = fopen(file_name, "r+b");

    if (!file) {
        fprintf(stderr, "Error opening file\n");
        return -1;
    }

    // 移动文件指针到删除位置
    if (fseek(file, offset + size, SEEK_SET) != 0) {
        fprintf(stderr, "Error seeking in file\n");
        fclose(file);
        return -1;
    }

    // 读取后续数据位置
    long int file_size;
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);

    // 申请缓冲区，用于存储后续数据
    char *buffer = (char *)malloc(file_size - (offset + size));
    if (!buffer) {
        fprintf(stderr, "Error allocating memory\n");
        fclose(file);
        return -1;
    }

    // 移动文件指针到后续数据位置
    if (fseek(file, offset + size, SEEK_SET) != 0) {
        fprintf(stderr, "Error seeking in file\n");
        free(buffer);
        fclose(file);
        return -1;
    }

    // 读取后续数据
    fread(buffer, 1, file_size - (offset + size), file);

    // 移动文件指针回到删除位置
    fseek(file, offset, SEEK_SET);

    // 写入后续数据
    fwrite(buffer, 1, file_size - (offset + size), file);

    // 截断文件，删除多余数据
    ftruncate(fileno(file), file_size - size);

    free(buffer);
    fclose(file);
}

int clear_section_imp(char *elf_name, char *section_name, int is_rename) {
    int fd;
    struct stat st;
    uint8_t *elf_map;
    uint8_t *elf_map_new;
    uint8_t *tmp_sec_name;

    fd = open(elf_name, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        perror("fstat");
        return -1;
    }

    elf_map = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (elf_map == MAP_FAILED) {
        perror("mmap");
        return -1;
    }
    
    /* 32bit */
    if (MODE == ELFCLASS32) {
        Elf32_Ehdr *ehdr;
        Elf32_Shdr *shdr;
        Elf32_Phdr *phdr;
        Elf32_Shdr shstrtab;

        ehdr = (Elf32_Ehdr *)elf_map;
        shdr = (Elf32_Shdr *)&elf_map[ehdr->e_shoff];
        shstrtab = shdr[ehdr->e_shstrndx];

        for (int i = 0; i < ehdr->e_shnum; i++) {
            tmp_sec_name = elf_map + shstrtab.sh_offset + shdr[i].sh_name;
            if (!strcmp(section_name, tmp_sec_name)) {
                /* clean section */
                memset(elf_map + shdr[i].sh_offset, 0, shdr[i].sh_size);
                
                /* clean shstrtab */
                memset(tmp_sec_name, 0, strlen(tmp_sec_name));
                
                /* modify section header table number */
                ehdr->e_shnum--;

                /* modify section header string table index */
                if (i < ehdr->e_shstrndx) {
                    ehdr->e_shstrndx--;
                } else {
                    WARNING("Delete section header string table will result in a section header resolution error\n");
                    ehdr->e_shstrndx = 0;
                }            
                
                /* delete section header table */
                elf_map_new = delete_data_from_mem(elf_map, st.st_size, ehdr->e_shoff + i * sizeof(Elf32_Shdr), sizeof(Elf32_Shdr));
                if (elf_map_new == NULL) {
                    WARNING("delete section header table error\n");
                    munmap(elf_map, st.st_size);
                    close(fd);
                    return -1;
                }             

                break;
            }
        }

        close(fd);
        create_file(elf_name, elf_map_new, st.st_size - sizeof(Elf32_Shdr), is_rename);
    }

    /* 64bit */
    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        Elf64_Shdr *shdr;
        Elf64_Phdr *phdr;
        Elf64_Shdr shstrtab;

        ehdr = (Elf64_Ehdr *)elf_map;
        shdr = (Elf64_Shdr *)&elf_map[ehdr->e_shoff];
        shstrtab = shdr[ehdr->e_shstrndx];

        for (int i = 0; i < ehdr->e_shnum; i++) {
            tmp_sec_name = elf_map + shstrtab.sh_offset + shdr[i].sh_name;
            if (!strcmp(section_name, tmp_sec_name)) {
                /* clean section */
                memset(elf_map + shdr[i].sh_offset, 0, shdr[i].sh_size);
                
                /* clean shstrtab */
                memset(tmp_sec_name, 0, strlen(tmp_sec_name));
                
                /* modify section header table number */
                ehdr->e_shnum--;

                /* modify section header string table index */
                if (i < ehdr->e_shstrndx) {
                    ehdr->e_shstrndx--;
                } else {
                    WARNING("Delete section header string table will result in a section header resolution error\n");
                    ehdr->e_shstrndx = 0;
                }            
                
                /* delete section header table */
                elf_map_new = delete_data_from_mem(elf_map, st.st_size, ehdr->e_shoff + i * sizeof(Elf64_Shdr), sizeof(Elf64_Shdr));
                if (elf_map_new == NULL) {
                    WARNING("delete section header table error\n");
                    munmap(elf_map, st.st_size);
                    close(fd);
                    return -1;
                }             

                break;
            }
        }

        close(fd);
        create_file(elf_name, elf_map_new, st.st_size - sizeof(Elf64_Shdr), is_rename);
    }

    free(elf_map_new);
    munmap(elf_map, st.st_size);
    
    return 0;
}

/**
 * @brief 清理节的内容，但是并没有改变节的大小
 * clean up the content of the section, but do not change the size of the section
 * @param elf_name elf file name
 * @param section_name section name
 * @param config_name multi section name
 * @return int error code {-1:error,0:sucess}
 */
int clear_section(char *elf_name, char *section_name, char *config_name) {
    FILE *fp;
    int count = 0;
    char tmp_sec_name[LENGTH];
    char new_file[LENGTH];
    snprintf(new_file, LENGTH, "%s.new", elf_name);

    if (strlen(config_name) == 0) {
        printf("delete %s\n", tmp_sec_name);
        clear_section_imp(elf_name, section_name, 1);
        return 0;
    }
   
    fp = fopen(config_name, "r");
    if (fp <= 0) {
        perror("fopen");
        return -1;
    }
    
    while (!feof(fp)) {
        fgets(tmp_sec_name, LENGTH, fp);
        if ( tmp_sec_name[strlen(tmp_sec_name) - 1] == '\n')
            tmp_sec_name[strlen(tmp_sec_name) - 1] = '\0';  /* delete \n */
        printf("delete %s\n", tmp_sec_name);
        
        if (!count)
            clear_section_imp(elf_name, tmp_sec_name, 1);
        else {
            clear_section_imp(new_file, tmp_sec_name, 0);
        }
        count++;
    }
    fclose(fp);
}

/**
 * @brief 删除节头表
 * delelet section header table
 * @param elf_name elf file name
 * @return int error code {-1:error,0:sucess}
 */
int delete_shtab(char *elf_name) {
    int fd;
    struct stat st;
    uint8_t *elf_map;
    uint8_t *elf_map_new;
    uint32_t shtab_size;

    fd = open(elf_name, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        perror("fstat");
        return -1;
    }

    elf_map = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (elf_map == MAP_FAILED) {
        perror("mmap");
        return -1;
    }

    /* 32bit */
    if (MODE == ELFCLASS32) {
        Elf32_Ehdr *ehdr;
        ehdr = (Elf32_Ehdr *)elf_map;
        shtab_size = ehdr->e_shnum * sizeof(Elf32_Shdr);
        elf_map_new = delete_data_from_mem(elf_map, st.st_size, ehdr->e_shoff, shtab_size);
        ehdr = (Elf32_Ehdr *)elf_map_new;
        ehdr->e_shnum = 0;
        ehdr->e_shoff = 0;
        ehdr->e_shentsize = 0;
        create_file(elf_name, elf_map_new, st.st_size - shtab_size, 1);
    }

    /* 64bit */
    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        ehdr = (Elf64_Ehdr *)elf_map;
        shtab_size = ehdr->e_shnum * sizeof(Elf64_Shdr);
        elf_map_new = delete_data_from_mem(elf_map, st.st_size, ehdr->e_shoff, shtab_size);
        ehdr = (Elf64_Ehdr *)elf_map_new;
        ehdr->e_shnum = 0;
        ehdr->e_shoff = 0;
        ehdr->e_shentsize = 0;
        create_file(elf_name, elf_map_new, st.st_size - shtab_size, 1);
    }

    free(elf_map_new);
    munmap(elf_map, st.st_size);
    close(fd);
    return 0;
}

/**
 * @brief 删除不必要的节
 * delelet unnecessary section, such as, .comment .symtab .strtab section
 * @param elf_name elf file name
 * @return int error code {-1:error,0:sucess}
 */
extern struct ElfData g_unmapped_section;
int strip(char *elf_name) {
    int shnum = 0;
    /* The following sequence of operations is very important! Do not modify! */
    int shstr_idx = get_section_index(elf_name, ".shstrtab");
    if (MODE == ELFCLASS32) {
        shnum = get_elf_shnum_32(elf_name);
    }
    else if (MODE == ELFCLASS64) {
        shnum = get_elf_shnum_64(elf_name);
    }
    
    for (int i = g_unmapped_section.count - 1; i >= 0; i--) {
        if (strcmp(g_unmapped_section.name[i], ".shstrtab")) {
            INFO("delete: %s\n", g_unmapped_section.name[i]);
            uint64_t offset = get_section_offset(elf_name, g_unmapped_section.name[i]);
            size_t size = get_section_size(elf_name, g_unmapped_section.name[i]);
            int sh_idx = get_section_index(elf_name, g_unmapped_section.name[i]);
            
            /* 1. set new shstrtab offset */
            if (sh_idx < shstr_idx) {
                uint64_t shstrtab_offset = get_section_offset(elf_name, ".shstrtab");
                set_section_off(elf_name, shstr_idx, shstrtab_offset - size);
            }

            /* 2. set new section header table offset */
            set_header_shoff(elf_name, get_shdr_offset(elf_name) - size);

            /* 3. delete section */
            delete_data_from_file(elf_name, offset, size);

            /* 4. delete section entry */
            set_header_shnum(elf_name, --shnum);
            if (sh_idx < shstr_idx) {
                set_header_shstrndx(elf_name, --shstr_idx);
            }
            
            if (MODE == ELFCLASS32) {
                offset = get_shdr_offset(elf_name) + sh_idx * sizeof(Elf32_Shdr);
                delete_data_from_file(elf_name, offset, sizeof(Elf32_Shdr));
            }
            else if (MODE == ELFCLASS64) {
                offset = get_shdr_offset(elf_name) + sh_idx * sizeof(Elf64_Shdr);
                delete_data_from_file(elf_name, offset, sizeof(Elf64_Shdr));
            }
        }
    }

   return 0;
}