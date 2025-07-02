/*
 MIT License
 
 Copyright (c) 2021-2022 SecNotes
 
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
#include <string.h>
#include "common.h"

static int conv_arch(uint8_t *arch, uint32_t class) {
    if (!(strcmp(arch, "arm") & strcmp(arch, "ARM"))) {
        return EM_ARM;
    } 
    
    else if (!(strcmp(arch, "x86") & strcmp(arch, "X86"))) {
        if (class == 32)
            return EM_386;
        else if (class == 64)
            return EM_X86_64;
    } 
    
    else if (!(strcmp(arch, "mips") & strcmp(arch, "MIPS"))) {
        return EM_MIPS;
    } 
    
    else
        return 0;
}

/**
 * @description: add ELF info to firmware for IDA
 * @param {uint8_t} *bin
 * @param {uint8_t} *arch
 * @param {uint32_t} class
 * @param {uint8_t} *endian
 * @param {uint64_t} *base_addr
 * @return {*}
 */
int add_elf_info(uint8_t *bin, uint8_t *arch, uint32_t class, uint8_t *endian, uint64_t base_addr){
    int fd;
    struct stat st;
    uint8_t *bin_map;
    uint8_t *new_bin_map;
    uint32_t new_size;

    fd = open(bin, O_RDONLY);
    if (fd < 0) {
        perror("open in add_elf_info");
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        perror("fstat");
        return -1;
    }

    bin_map = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (bin_map == MAP_FAILED) {
        perror("mmap");
        return -1;
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
            .e_machine = conv_arch(arch, class),
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
            .e_machine = conv_arch(arch, class),
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
    }

    INFO("source file length is 0x%x\n", st.st_size);
    INFO("base address is 0x%x\n", base_addr);
    create_file(bin, new_bin_map, new_size, 1);
    free(new_bin_map);
    close(fd);
}