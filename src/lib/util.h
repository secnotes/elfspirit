#define NONE      "\e[0m"              // Clear color 清除颜色，即之后的打印为正常输出，之前的不受影响
#define RED     "\e[1;31m"           // Light Red 鲜红
#define GREEN   "\e[1;32m"           // Light Green 鲜绿
#define YELLOW    "\e[1;33m"           // Light Yellow 鲜黄

#define PRINT_WARNING(format, ...) printf (""YELLOW"[!] "format""NONE"", ##__VA_ARGS__)
#define PRINT_ERROR(format, ...) printf (""RED"[-] "format""NONE"", ##__VA_ARGS__)
#define PRINT_INFO(format, ...) printf (""NONE"[+] "format""NONE"", ##__VA_ARGS__)
#define PRINT_VERBOSE(format, ...) printf (""GREEN"[*] "format""NONE"", ##__VA_ARGS__)

#define ONE_PAGE 4096 // 4K的大小

/**
 * @brief 计算一个地址的4K对齐地址
 * align 4k address
 * @param address input address
 * @return uint64_t output 4k address
 */
uint64_t align_page(uint64_t address);

/**
 * @brief 根据虚拟地址计算符合条件的偏移地址
 * calculate eligible offset addresses based on virtual addresses
 * @param p_offset input segment file offset
 * @param p_vaddr input segment address
 * @return uint64_t output 4k address
 */
uint64_t align_offset(uint64_t p_offset, uint64_t p_vaddr);

/**
 * @brief 转换架构名称为ELF机器码
 * Convert architecture name to ELF machine code
 * @param arch architecture
 * @param class ELF class(32/64)
 * @return ELF machine code
 */
int arch_to_mach(uint8_t *arch, uint32_t class);