#define MAX_PATH_LEN 4096
#define MAX_LINE_LEN 256  // 每行最大字符数
#define READ_CHUNK 128    // 每次读取128字节(对应256字符)

#define NONE         "\033[m"
#define RED          "\033[0;32;31m"
#define LIGHT_RED    "\033[1;31m"
#define GREEN        "\033[0;32;32m"
#define LIGHT_GREEN  "\033[1;32m"
#define BLUE         "\033[0;32;34m"
#define LIGHT_BLUE   "\033[1;34m"
#define DARY_GRAY    "\033[1;30m"
#define CYAN         "\033[0;36m"
#define LIGHT_CYAN   "\033[1;36m"
#define PURPLE       "\033[0;35m"
#define LIGHT_PURPLE "\033[1;35m"
#define BROWN        "\033[0;33m"
#define YELLOW       "\033[1;33m"
#define LIGHT_GRAY   "\033[0;37m"
#define WHITE        "\033[1;37m"

#define PRINT_WARNING(format, ...) printf (""YELLOW"[!] "format""NONE"", ##__VA_ARGS__)
#define PRINT_ERROR(format, ...) printf (""RED"[-] "format""NONE"", ##__VA_ARGS__)
#define PRINT_INFO(format, ...) printf (""LIGHT_GREEN"[+] "format""NONE"", ##__VA_ARGS__)
#define PRINT_VERBOSE(format, ...) printf (""NONE"[*] "format""NONE"", ##__VA_ARGS__)

#ifdef debug
    #define PRINT_DEBUG(...)  do{printf(BROWN "[D] %s#%d: " NONE, __FILE__,__LINE__); printf(BROWN __VA_ARGS__);printf(NONE);}while(0)
#else
    #define PRINT_DEBUG(format, ...)
#endif

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

/**
 * @brief 创建文件
 * Create a file
 * @param file_name file name
 * @param map file content
 * @param map_size file size
 * @param is_new create new file or overwrite the old file
 * @return int error code {-1:error,0:sucess}
 */
int mem_to_file(char *file_name, char *map, uint32_t map_size, uint32_t is_new);

/**
 * @brief 读取文件内容到buf
 * save file content
 * @param filename file name
 * @param buffer buffer, need to free
 * @return error code {-1:false,0:success}
 */
int file_to_mem(const char* filename, char** buffer);

/**
 * @brief 从路径中提取文件名
 * extract file name from path
 * @param path path
 * @param result
 * @return error code
 */
void get_filename_with_ext(const char* path, char* result);

/**
 * @brief 从路径中提取文件名（不带扩展名）
 * extract file name from path (without extension)
 * @param path path
 * @param result
 * @return error code
 */
void get_filename_without_ext(const char* path, char* result);

/**
 * @brief Compare string
 * 比较两个字符串的前n位是否相同
 * @param str1 
 * @param str2 
 * @param n 
 * @return int 
 */
int compare_firstN_chars(const char *str1, const char *str2, int n);
