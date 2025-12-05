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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <elf.h>

#include "cJSON/cJSON.h"

#define LENGTH 64
#define PATH_LENGTH LENGTH
/* generate new file name */
#define PATH_LENGTH_NEW LENGTH + 4

#define __ALIGN_MASK(x, mask) (((x) + (mask))&~(mask))
#define ALIGN(x, a) __ALIGN_MASK(x, (typeof(x))(a) - 1)
#define PTR_ALIGN(p, a) ((typeof(p))ALIGN((unsigned long)(p), (a)))

#define NONE      "\e[0m"              // Clear color 清除颜色，即之后的打印为正常输出，之前的不受影响
#define L_RED     "\e[1;31m"           // Light Red 鲜红
#define L_GREEN   "\e[1;32m"           // Light Green 鲜绿
#define YELLOW    "\e[1;33m"           // Light Yellow 鲜黄

#define WARNING(format, ...) printf (""YELLOW"[!] "format""NONE"", ##__VA_ARGS__)
#define ERROR(format, ...) printf (""L_RED"[-] "format""NONE"", ##__VA_ARGS__)
#define INFO(format, ...) printf (""L_GREEN"[+] "format""NONE"", ##__VA_ARGS__)
#define VERBOSE(format, ...) printf (""YELLOW"[*] "format""NONE"", ##__VA_ARGS__)

#define CHECK_WARNING(format, ...) printf (""YELLOW""format""NONE"", ##__VA_ARGS__)
#define CHECK_ERROR(format, ...) printf (""L_RED""format""NONE"", ##__VA_ARGS__)
#define CHECK_INFO(format, ...) printf (""L_GREEN""format""NONE"", ##__VA_ARGS__)
#define CHECK_COMMON(format, ...) printf (""format"", ##__VA_ARGS__)

#ifdef debug
    #define DEBUG(format, ...) printf (""YELLOW"[d] "format""NONE"", ##__VA_ARGS__)
#else
    #define DEBUG(format, ...)
#endif

#define UNKOWN "Unkown"
#define PAGE_SIZE 4096 // 4K的大小

/* ELF class */
extern int MODE;

/* ELF architecture */
extern int ARCH;

typedef struct handle32 {
    Elf32_Ehdr *ehdr;
    Elf32_Phdr *phdr;
    Elf32_Shdr *shdr;
    Elf32_Shdr *shstrtab;
    int sec_index;      // section index
    size_t sec_size;    // section size
    uint8_t *mem;
    int fd;
    size_t size;        // file size
} handle_t32;

typedef struct handle64 {
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    Elf64_Shdr *shdr;
    Elf64_Shdr *shstrtab;
    int sec_index;      // section index
    size_t sec_size;    // section size
    uint8_t *mem;
    int fd;
    size_t size;        // file size
} handle_t64;

void log_warning(char *str);
void log_error(char *str);
void log_info(char *str);

void get_name(char *file, char *file_name);
void get_path(char *file, char *file_path);

/**
 * @description: hex string to int
 * @param {char} *hex
 * @return {*}
 */
unsigned int hex2int(char *hex);

/**
 * @description: Convert hex to printable string (将十六进制转化为可打印的字符串)
 * @param {unsigned int} hex
 * @param {char} *ret
 * @param {unsigned int} len string length
 * @return {*}
 */
int hex2str(unsigned int hex, char *ret, unsigned int len);

/**
 * @description: String reverse from start to end (指定位置的字符串逆序)
 * @param {char} *str
 * @param {int} offset
 * @param {int} length
 * @return {*}
 */
char *str_reverse(char *str, int offset, int length);

/**
 * @brief Compare string
 * 
 * @param str1 
 * @param str2 
 * @param n 
 * @return int 
 */
int compare_firstN_chars(const char *str1, const char *str2, int n);

/**
 * @brief 计算一个地址的4K对齐地址
 * align 4k address
 * @param address input address
 * @return uint64_t output 4k address
 */
uint64_t align_to_4k(uint64_t address);

/**
 * @brief 将命令行传入的shellcode，转化为内存实际值
 * convert the shellcode passed in from the command line to the actual value in memory
 * @param sc_str input shellcode string
 * @param sc_mem output shellcode memory
 */
int cmdline_shellcode(char *sc_str, char *sc_mem);

/**
 * @description: Determine whether elf is in 32-bit mode or 64-bit mode (判断elf是32位还是64位)
 * @param {char} *elf_name
 * @return {*}
 */
int get_elf_class(char *elf_name);

/**
 * @description: Get elf architecture, such as EM_386, EM_X86_64, EM_ARM and EM_MIPS. (ELF文件架构)
 * @param {char} *elf_name
 * @return {*}
 */
int get_elf_machine(char *elf_name);

/**
 * @description: Get elf section number
 * @param {char} *elf_name
 * @return {*}
 */
int get_elf_shnum_32(char *elf_name);
int get_elf_shnum_64(char *elf_name);

/**
 * @description: Judge whether the address is the starting address of the section (判断地址是否为section起始地址)
 * @param {char} *elf_name
 * @param {int} offset
 * @return {*}
 */
int is_sec_addr(char *elf_name, int offset);

/**
 * @description: Create new file to store changes
 * @param {char} *elf_name original file name
 * @param {char} *elf_map
 * @param {uint32_t} map_size
 * @param {uint32_t} is_new
 * @return {*}
 */
int create_file(char *elf_name, char *elf_map, uint32_t map_size, uint32_t is_new);

/**
 * @description: Create json object from json file
 * @param {char} *name original json file name
 * @return {*}
 */
cJSON *get_json_object(char *name);

/**
 * @brief 获取节头表的偏移
 * get program header table offset
 * @return uint64_t section address
 */
uint64_t get_shdr_offset(char *elf_name);

/**
 * @brief 获取程序头表的偏移
 * get program header table offset
 * @return uint64_t segment address
 */
uint64_t get_phdr_offset(char *elf_name);

/**
 * @brief 获取程序入口
 * get program entry
 * @return uint64_t program entry
 */
uint64_t get_entry(char *elf_name);

/* EXTERN API */
/**
 * @description: Judge whether the memory address is legal
 * @param {uint64_t} addr
 * @param {uint64_t} start
 * @param {uint64_t} end
 * @return {*}
 */
int validated_offset(uint64_t addr, uint64_t start, uint64_t end);

/**
 * @brief 判断二进制是否开启地址随机化
 * determine whether binary has enabled address randomization
 * @param elfname 
 * @return int {1:true,0:false}
 */
int is_pie(char *elfname);

/**
 * @brief 向ELF文件特定偏移处，写入一段数据
 * Write a piece of data to a specific offset in the ELF file
 * @param elf_name elf file name
 * @param offset start elf file offset
 * @param content new value string value to be edited
 * @param size content size
 * @return int error code {-1:error,0:sucess}
 */
int set_content(char *elf_name, uint64_t offset, char *content, size_t size);

/**
 * @brief hook外部函数
 * hook function by .got.plt
 * @param elf_name elf file name
 * @param symbol symbol name
 * @param hookfile hook function file
 * @param hook_offset hook function offset in hook file
 * @return int error code {-1:error,0:sucess}
 */
int hook_extern(char *elf_name, char *symbol, char *hookfile, uint64_t hook_offset);

/* Non repetitive data structures */
/* 不重复的数据结构 */
#ifndef UNIQUE_SEQUENCE_H
#define UNIQUE_SEQUENCE_H

#define true 1
#define false 0

typedef struct {
    int *data;
    int size;
    int capacity;
} UniqueSequence;

UniqueSequence* sequence_create(int initial_capacity);
void sequence_destroy(UniqueSequence *seq);
int sequence_insert(UniqueSequence *seq, int value);
int sequence_remove(UniqueSequence *seq, int value);
int sequence_contains(const UniqueSequence *seq, int value);
int sequence_size(const UniqueSequence *seq);
int sequence_is_empty(const UniqueSequence *seq);
void sequence_clear(UniqueSequence *seq);
void sequence_print(const UniqueSequence *seq);
int sequence_get(const UniqueSequence *seq, int index);
int sequence_union(UniqueSequence *result, const UniqueSequence *seq1, const UniqueSequence *seq2);
int sequence_intersection(UniqueSequence *result, const UniqueSequence *seq1, const UniqueSequence *seq2);

#endif