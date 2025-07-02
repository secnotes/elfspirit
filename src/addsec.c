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

/**
 * @description: append data to ELF
 * @param {uint8_t} *elf
 * @param {uint32_t} elf_size
 * @param {uint32_t} offset
 * @param {uint32_t} data_size
 * @param {uint8_t} *ret
 * @return {*}
 */
int add_data(uint8_t *elf, uint32_t elf_size, uint32_t offset, uint32_t data_size, uint8_t *ret) {
    char *tmp;
    tmp = malloc(elf_size + data_size);
    if (tmp < 0) {
        return 0;
    }

    memset(tmp, 0, elf_size + data_size);
    memcpy(tmp, elf, offset);
    memset(&tmp[offset], 0, data_size);
    memcpy(&tmp[offset + data_size], &elf[offset], elf_size - offset);
    memcpy(ret, tmp, elf_size + data_size);
    free(tmp);
    return 0;
}

/**
 * @description: add a section
 * @param {uint8_t} *elf
 * @param {uint32_t} offset
 * @param {uint8_t} *new_sec
 * @param {uint32_t} sec_size
 * @return {*}
 */
int add_section_bak(uint8_t *elf, uint32_t offset, uint8_t *new_sec, uint32_t sec_size) {
    int fd;
    struct stat st;
    int range;              /* indicate the range of offset */
    uint8_t *elf_map;
    uint8_t *elf_map_new;
    uint8_t *tmp_sec_name;
    uint32_t tmp_map_size;
    uint32_t new_map_size;
    uint32_t start;

    fd = open(elf, O_RDONLY);
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

    /* offset is section address */
    offset = offset?offset:st.st_size;          /* set default offset value */
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)elf_map;
    INFO("offset to insert: %p\n", offset);
    if (!(offset == ehdr->e_shoff || offset == st.st_size || is_sec_addr(elf, offset) > -1)) {
        WARNING("The recommended insertion location is the starting address of a section/header/the end of the file\n");
        return -1;
    }

    /* 32bit */
    if (MODE == ELFCLASS32) {
        Elf32_Ehdr *ehdr;
        Elf32_Shdr *shdr;
        Elf32_Shdr *shstrtab;

        ehdr = (Elf32_Ehdr *)elf_map;
        shdr = (Elf32_Shdr *)&elf_map[ehdr->e_shoff];
        shstrtab = (Elf32_Shdr *)&shdr[ehdr->e_shstrndx];

        /* section contnet + section header + section header string */
        new_map_size = st.st_size + sec_size + sizeof(Elf32_Shdr) + PTR_ALIGN(strlen(new_sec), 4);
        elf_map_new = malloc(new_map_size);
        if (elf_map_new == NULL) {
            ERROR("malloc elf new error!\n");
            munmap(elf_map, st.st_size);
            close(fd);
            return -1;
        }

        /* 1.add section content */
        tmp_map_size = st.st_size;
        start = offset;
        add_data(elf_map, tmp_map_size, start, sec_size, elf_map_new);

        ehdr = (Elf32_Ehdr *)elf_map_new;
        if (offset <= shstrtab->sh_offset) {  
            range = 1;          
            ehdr->e_shoff += sec_size;
            shdr = (Elf32_Shdr *)&elf_map_new[ehdr->e_shoff];            
            /* update */
            shstrtab  = (Elf32_Shdr *)&shdr[ehdr->e_shstrndx];
            /* if you use shstrtab without pointer, elf memory will not not be changed.
             * shstrtab = shdr[ehdr->e_shstrndx]
             */

            shstrtab->sh_offset += sec_size;  /* not write data to memory! */
   
        } else if (offset == ehdr->e_shoff) {
            range = 2;
            ehdr->e_shoff += sec_size;
        } else {
            range = 3;
        }

        munmap(elf_map, st.st_size);
        tmp_map_size += sec_size;

        /* 2.add section header */        
        start = ehdr->e_shoff + sizeof(Elf32_Shdr) * ehdr->e_shnum;
        add_data(elf_map_new, tmp_map_size, start, sizeof(Elf32_Shdr), elf_map_new);

        ehdr = (Elf32_Ehdr *)elf_map_new;
        shdr = (Elf32_Shdr *)&elf_map_new[ehdr->e_shoff];
        shstrtab = (Elf32_Shdr *)&shdr[ehdr->e_shstrndx];
        ehdr->e_shnum++;

        if (range == 3) {
            offset += sizeof(Elf32_Shdr);
        }

        tmp_map_size += sizeof(Elf32_Shdr); 

        /* 3.add section header string */                     
        start = shstrtab->sh_offset + shstrtab->sh_size;
        add_data(elf_map_new, tmp_map_size, start, PTR_ALIGN(strlen(new_sec), 4), elf_map_new);
        memcpy(elf_map_new + start, new_sec, strlen(new_sec));

        /* section header off */
        ehdr->e_shoff += PTR_ALIGN(strlen(new_sec), 4);
        ehdr = (Elf32_Ehdr *)elf_map_new;
        shdr = (Elf32_Shdr *)&elf_map_new[ehdr->e_shoff];
        shstrtab = (Elf32_Shdr *)&shdr[ehdr->e_shstrndx];
        shstrtab->sh_size += PTR_ALIGN(strlen(new_sec), 4);
        
        if (range >= 2) {
            offset += PTR_ALIGN(strlen(new_sec), 4);
        }
        
        /* 4.set value for added section header */
        Elf32_Shdr new_sec_head = {
            .sh_name = shstrtab->sh_size - PTR_ALIGN(strlen(new_sec), 4),
            .sh_type = 1,
            .sh_flags = 0x6,
            .sh_addr = offset,
            .sh_offset = offset,
            .sh_size = sec_size,
            .sh_link = 0x0,
            .sh_info = 0x0,
            .sh_addralign = 4,
            .sh_entsize = 0x0
        };

        memcpy(&elf_map_new[ehdr->e_shoff + sizeof(Elf32_Shdr) * (ehdr->e_shnum - 1)], &new_sec_head, sizeof(Elf32_Shdr)); 
    }

    /* 64bit */
    if (MODE == ELFCLASS64) {
        Elf64_Ehdr *ehdr;
        Elf64_Shdr *shdr;
        Elf64_Shdr *shstrtab;

        ehdr = (Elf64_Ehdr *)elf_map;
        shdr = (Elf64_Shdr *)&elf_map[ehdr->e_shoff];
        shstrtab = (Elf64_Shdr *)&shdr[ehdr->e_shstrndx];

        /* section contnet + section header + section header string */
        new_map_size = st.st_size + sec_size + sizeof(Elf64_Shdr) + PTR_ALIGN(strlen(new_sec), 4);
        elf_map_new = malloc(new_map_size);
        if (elf_map_new == NULL) {
            ERROR("malloc elf new error!\n");
            munmap(elf_map, st.st_size);
            close(fd);
            return -1;
        }

        /* 1.add section content */
        tmp_map_size = st.st_size;
        start = offset;
        add_data(elf_map, tmp_map_size, start, sec_size, elf_map_new);

        ehdr = (Elf64_Ehdr *)elf_map_new;
        if (offset <= shstrtab->sh_offset) {  
            range = 1;          
            ehdr->e_shoff += sec_size;
            shdr = (Elf64_Shdr *)&elf_map_new[ehdr->e_shoff];            
            /* update */
            shstrtab  = (Elf64_Shdr *)&shdr[ehdr->e_shstrndx];
            /* if you use shstrtab without pointer, elf memory will not not be changed.
             * shstrtab = shdr[ehdr->e_shstrndx]
             */

            shstrtab->sh_offset += sec_size;  /* not write data to memory! */
   
        } else if (offset == ehdr->e_shoff) {
            range = 2;
            ehdr->e_shoff += sec_size;
        } else {
            range = 3;
        }

        munmap(elf_map, st.st_size);
        tmp_map_size += sec_size;

        /* 2.add section header */        
        start = ehdr->e_shoff + sizeof(Elf64_Shdr) * ehdr->e_shnum;
        add_data(elf_map_new, tmp_map_size, start, sizeof(Elf64_Shdr), elf_map_new);

        ehdr = (Elf64_Ehdr *)elf_map_new;
        shdr = (Elf64_Shdr *)&elf_map_new[ehdr->e_shoff];
        shstrtab = (Elf64_Shdr *)&shdr[ehdr->e_shstrndx];
        ehdr->e_shnum++;

        if (range == 3) {
            offset += sizeof(Elf64_Shdr);
        }

        tmp_map_size += sizeof(Elf64_Shdr); 

        /* 3.add section header string */                     
        start = shstrtab->sh_offset + shstrtab->sh_size;
        add_data(elf_map_new, tmp_map_size, start, PTR_ALIGN(strlen(new_sec), 4), elf_map_new);
        memcpy(elf_map_new + start, new_sec, strlen(new_sec));

        /* section header off */
        ehdr->e_shoff += PTR_ALIGN(strlen(new_sec), 4);
        ehdr = (Elf64_Ehdr *)elf_map_new;
        shdr = (Elf64_Shdr *)&elf_map_new[ehdr->e_shoff];
        shstrtab = (Elf64_Shdr *)&shdr[ehdr->e_shstrndx];
        shstrtab->sh_size += PTR_ALIGN(strlen(new_sec), 4);
        
        if (range >= 2) {
            offset += PTR_ALIGN(strlen(new_sec), 4);
        }
        
        /* 4.set value for added section header */
        Elf64_Shdr new_sec_head = {
            .sh_name = shstrtab->sh_size - PTR_ALIGN(strlen(new_sec), 4),
            .sh_type = 1,
            .sh_flags = 0x6,
            .sh_addr = offset,
            .sh_offset = offset,
            .sh_size = sec_size,
            .sh_link = 0x0,
            .sh_info = 0x0,
            .sh_addralign = 4,
            .sh_entsize = 0x0
        };

        memcpy(&elf_map_new[ehdr->e_shoff + sizeof(Elf64_Shdr) * (ehdr->e_shnum - 1)], &new_sec_head, sizeof(Elf64_Shdr)); 
    }
    
    create_file(elf, elf_map_new, new_map_size, 1);

    free(elf_map_new);
    close(fd);
    
    return 0;
}