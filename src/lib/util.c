
#include <elf.h>
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
