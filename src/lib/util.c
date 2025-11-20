
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