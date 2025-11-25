
#include <elf.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
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
