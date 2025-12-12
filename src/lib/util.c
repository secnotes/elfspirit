
#include <elf.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include "elfutil.h"
#include "util.h"

/**
 * @brief 计算一个地址的4K对齐地址
 * align 4k address
 * @param address input address
 * @return uint64_t output 4k address
 */
uint64_t align_page(uint64_t address) {
    return ((address + ONE_PAGE - 1) & ~(ONE_PAGE - 1));
}

/**
 * @brief 根据虚拟地址计算符合条件的偏移地址
 * calculate eligible offset addresses based on virtual addresses
 * @param p_offset input segment file offset
 * @param p_vaddr input segment address
 * @return uint64_t output 4k address
 */
uint64_t align_offset(uint64_t p_offset, uint64_t p_vaddr) {
    if (ONE_PAGE == 0) return p_offset;
    uint64_t remainder_diff = (p_vaddr - p_offset) % ONE_PAGE;
    return p_offset + (remainder_diff & (ONE_PAGE - 1));
}

/**
 * @brief 转换架构名称为ELF机器码
 * Convert architecture name to ELF machine code
 * @param arch architecture
 * @param class ELF class(32/64)
 * @return ELF machine code
 */
int arch_to_mach(uint8_t *arch, uint32_t class) {
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
        return ERR_ARGS;
}

/**
 * @brief 创建文件
 * Create a file
 * @param file_name file name
 * @param map file content
 * @param map_size file size
 * @param is_new create new file or overwrite the old file
 * @return int error code {-1:error,0:sucess}
 */
int mem_to_file(char *file_name, char *map, uint32_t map_size, uint32_t is_new) {
    /* new file */
    char new_name[MAX_PATH_LEN];
    memset(new_name, 0, MAX_PATH_LEN);
    if (is_new) 
        snprintf(new_name, MAX_PATH_LEN, "%s.out", file_name);
    else
        strncpy(new_name, file_name, MAX_PATH_LEN);
        
    int fd_new = open(new_name, O_RDWR|O_CREAT|O_TRUNC, 0777);
    if (fd_new < 0) {
        return ERR_OPEN;
    }
    
    write(fd_new, map, map_size);  
    close(fd_new);
    printf("[+] Create file: %s\n", new_name);
    return TRUE;
}

/**
 * @brief 读取文件内容到buf
 * save file content
 * @param filename file name
 * @param buffer buffer, need to free
 * @return error code {-1:false,0:success}
 */
int file_to_mem(const char* filename, char** buffer) {
    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        return -1; 
    }

    fseek(file, 0, SEEK_END); // 将文件指针移动到文件末尾
    long size = ftell(file); // 获取文件大小
    fseek(file, 0, SEEK_SET); // 将文件指针移动回文件开头

    *buffer = (char*)malloc(size + 1); // 分配足够的内存来存储文件内容
    if (*buffer == NULL) {
        fclose(file);
        return -2; // 内存分配失败，返回-2表示错误
    }

    fread(*buffer, 1, size, file); // 读取文件内容到缓冲区
    (*buffer)[size] = '\0'; // 在末尾添加字符串结束符

    fclose(file); 
    return size; 
}

/**
 * @brief 从路径中提取文件名
 * extract file name from path
 * @param path path
 * @param result
 * @return error code
 */
void get_filename_with_ext(const char* path, char* result) {
    const char* p = strrchr(path, '/');
    if (p == NULL) p = strrchr(path, '\\');
    if (p == NULL) p = path - 1;
    strcpy(result, p + 1);
}

/**
 * @brief 从路径中提取文件名（不带扩展名）
 * extract file name from path (without extension)
 * @param path path
 * @param result
 * @return error code
 */
void get_filename_without_ext(const char* path, char* result) {
    char with_ext[256];
    get_filename_with_ext(path, with_ext);
    
    char* dot = strrchr(with_ext, '.');
    if (dot != NULL) {
        strncpy(result, with_ext, dot - with_ext);
        result[dot - with_ext] = '\0';
    } else {
        strcpy(result, with_ext);
    }
}

/**
 * @description: 判断内存是否越界
 * Judge whether the memory address is legal
 * @param addr object address
 * @param start start address
 * @param end end adddress
 * @return bool
 */
int validated_offset(uint64_t addr, uint64_t start, uint64_t end){
    return addr <= end && addr >= start? 0:-1;
}

/**
 * @description: 将十六进制字符串转换为整型(int)数值
 * hex string to int.
 * @param {char} *hex
 * @return {*}
 */
unsigned int hex2int(char *hex) {  
    int len;
    int num = 0;
    int temp;
    int bits;
    int i;

    if (strlen(hex) <= 2) {
        return -1;
    }

    char *new_hex = hex + 2;
    len = strlen(new_hex);

    for (i = 0, temp = 0; i < len; i++, temp = 0)  
    {
        temp = c2i(*(new_hex + i));  
        bits = (len - i - 1) * 4;  
        temp = temp << bits;  
        num = num | temp;  
    }
    
    return num;  
}

/**
 * @brief 计算一个地址的4K对齐地址
 * align 4k address
 * @param address input address
 * @return uint64_t output 4k address
 */
uint64_t align_to_4k(uint64_t address) {
    return ((address + ONE_PAGE - 1) & ~(ONE_PAGE- 1));
}

/**
 * @brief 将命令行传入的shellcode，转化为内存实际值
 * convert the shellcode passed in from the command line to the actual value in memory
 * @param sc_str input shellcode string
 * @param sc_mem output shellcode memory
 */
int cmdline_shellcode(char *sc_str, char *sc_mem) {
    if (strlen(sc_str) % 4 != 0) 
        return -1;
    else {
        printf("shellcode: ");
        for (size_t i = 0; i < strlen(sc_str); i += 4) {
            unsigned char value;
            sscanf(&sc_str[i], "\\x%2hhx", &value);
            *(sc_mem+i/4) = value;
            printf("%02x ", value);
        }
        printf("\n");
    }
}

/**
 * @description: 将字符转换为数值
 * char to int
 * @param {char} ch
 * @return {*}
 */
int c2i(char ch) {
    if(isdigit(ch))
        return ch - 48;
 
    if( ch < 'A' || (ch > 'F' && ch < 'a') || ch > 'z' )
        return -1;
 
    if(isalpha(ch))
        return isupper(ch) ? ch - 55 : ch - 87;

    return -1;
}

// 函数用于检查整数是否包含特定的宏标志位
int has_flag(int num, int flag) {
    return (num & flag) == flag;
}