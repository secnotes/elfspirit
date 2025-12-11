#include <elf.h>
#include <stddef.h>

enum ErrorCode {
    /* ELF file error */
    ERR_DYN_NOTFOUND = -20,
    ERR_SEC_NOTFOUND = -13,
    ERR_SEG_NOTFOUND = -12,
    ERR_TYPE = -11,
    ERR_CLASS,
    /* other error */
    ERR_ARGS,
    ERR_OPEN,
    ERR_STAT,
    ERR_MMAP,
    ERR_COPY,
    ERR_EXPANDSEG,
    ERR_ADDSEG,
    ERROR = -2,
    FALSE,
    TRUE
};

typedef struct Elf32_Data {
    Elf32_Ehdr *ehdr;
    Elf32_Phdr *phdr;
    Elf32_Shdr *shdr;
    /* string table */
    Elf32_Shdr *shstrtab;
    Elf32_Shdr *dynstrtab;
    Elf32_Shdr *strtab;
    /* other section */
    Elf32_Shdr *sym;        // .symtab->strtab
    Elf32_Shdr *dynsym;
    Elf32_Sym *sym_entry;
    int sym_count;
    Elf32_Sym *dynsym_entry;
    int dynsym_count;
    Elf32_Dyn *dyn_segment_entry;
    int dyn_segment_count;
} Elf32;

typedef struct Elf64_Data {
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    Elf64_Shdr *shdr;
    /* string table */
    Elf64_Shdr *shstrtab;   // .shstrtab
    Elf64_Shdr *dynstrtab;  // .dynstr
    Elf64_Shdr *strtab;     // .strtab
    /* other section */
    Elf64_Shdr *sym;        // .symtab->strtab
    Elf64_Shdr *dynsym;     // .dynsym->dynstr
    Elf64_Sym *sym_entry;
    int sym_count;
    Elf64_Sym *dynsym_entry;
    int dynsym_count;
    Elf64_Dyn *dyn_segment_entry;
    int dyn_segment_count;
} Elf64;

typedef struct Elf_Data{
    int type;           // elf file type
    int class;          // elf class
    int fd;             // file pointer
    uint8_t *mem;       // file mmap pointer
    size_t size;        // file size
    union {
        Elf32 elf32;
        Elf64 elf64;
    } data;
} Elf;

typedef struct GnuHash {
    uint32_t nbuckets;      // 桶的数量
    uint32_t symndx;        // 符号表的开始索引
    uint32_t maskbits;      // 掩码位数
    uint32_t shift;         // 用于计算哈希值的位移量
    uint32_t buckets[];     // 桶数组，大小为 nbuckets
    // 后面可能跟着链表和其他数据
} gnuhash_t;

/**
 * @brief 打印错误信息
 * print error message
 * @param code error code
 */
void print_error(enum ErrorCode code);

/**
 * @brief 初始化elf文件，将elf文件转化为elf结构体
 * initialize the elf file and convert it into an elf structure
 * @param elf elf file name
 * @return error code
 */
int init(char *elf_name, Elf *elf);
int finit(Elf *elf);
void reinit(Elf *elf);

/**
 * @brief 根据节的名称，获取节的信息
 * Obtain section information based on its name.
 * @param elf Elf custom structure
 * @param name Elf section name
 * @return section virtual address
 */
int get_section_addr_by_name(Elf *elf, char *name);
int get_section_offset_by_name(Elf *elf, char *name);
int get_section_type_by_name(Elf *elf, char *name);
int get_section_size_by_name(Elf *elf, char *name);
int get_section_entsize_by_name(Elf *elf, char *name);
int get_section_addralign_by_name(Elf *elf, char *name);
int get_section_flags_by_name(Elf *elf, char *name);
int get_section_link_by_name(Elf *elf, char *name);
int get_section_info_by_name(Elf *elf, char *name);

/**
 * @brief 根据节的名称，设置节的信息
 * Set the virtual address of the section based on its name.
 * @param elf Elf custom structure
 * @param name Elf section name
 * @param addr the values that need to be set
 * @return error code
 */
int set_section_addr_by_name(Elf *elf, char *name, uint64_t addr);
int set_section_offset_by_name(Elf *elf, char *name, uint64_t offset);
int set_section_type_by_name(Elf *elf, char *name, uint64_t type);
int set_section_size_by_name(Elf *elf, char *name, uint64_t size);
int set_section_entsize_by_name(Elf *elf, char *name, uint64_t entsize);
int set_section_addralign_by_name(Elf *elf, char *name, uint64_t addralign);
int set_section_flags_by_name(Elf *elf, char *name, uint64_t flags);
int set_section_link_by_name(Elf *elf, char *name, uint64_t link);
int set_section_info_by_name(Elf *elf, char *name, uint64_t info);

/**
 * @brief 根据段的下标,获取节的名称
 * Get the section name based on its index.
 * @param elf Elf custom structure
 * @param index Elf section index
 * @return section name
 */
char *get_section_name(Elf *elf, int index);

/**
 * @brief 根据段的下标,获取段的信息
 * Get the segment information based on its index.
 * @param elf Elf custom structure
 * @param index Elf segment index
 * @return error code
 */
int get_segment_align_by_index(Elf *elf, int index);
int get_segment_filesz_by_index(Elf *elf, int index);
int get_segment_flags_by_index(Elf *elf, int index);
int get_segment_memsz_by_index(Elf *elf, int index);
int get_segment_offset_by_index(Elf *elf, int index);
int get_segment_paddr_by_index(Elf *elf, int index);
int get_segment_type_by_index(Elf *elf, int index);
int get_segment_vaddr_by_index(Elf *elf, int index);

/**
 * @brief 根据段的下标,设置段的对齐方式
 * Set the segment alignment based on its index.
 * @param elf Elf custom structure
 * @param index Elf segment index
 * @return error code
 */
int set_segment_align_by_index(Elf *elf, int index, uint64_t align);
int set_segment_filesz_by_index(Elf *elf, int index, uint64_t filesz);
int set_segment_flags_by_index(Elf *elf, int index, uint64_t flags);
int set_segment_memsz_by_index(Elf *elf, int index, uint64_t memsz);
int set_segment_offset_by_index(Elf *elf, int index, uint64_t offset);
int set_segment_paddr_by_index(Elf *elf, int index, uint64_t paddr);
int set_segment_type_by_index(Elf *elf, int index, uint64_t type);
int set_segment_vaddr_by_index(Elf *elf, int index, uint64_t vaddr);

/**
 * @brief 根据符号表的名称，获取符号表的下标
 * Obtain the index of the symbol based on its name.
 * @param elf Elf custom structure
 * @param name Elf section name
 * @return section index
 */
int get_sym_index_by_name(Elf *elf, char *name);
int get_dynsym_index_by_name(Elf *elf, char *name);

/**
 * @brief 根据节的名字，获取该节对应的段的下标.请注意，一个节可能属于多个段！
 * Obtain the subscript of the segment corresponding to the section based on its name.
 * Please note that a section may belong to multiple segments!
 * @param elf Elf custom structure
 * @param name Elf section name
 * @param out_index Elf segment index
 * @param max_size Elf segment index count
 * @return error code
 */
int get_section_index_in_segment(Elf *elf, char *name, int out_index[], int max_size);

/**
 * @brief 根据节的名字，判断该节是否是一个孤立节，即不属于任何段
 * Determine whether the section is an isolated section based on its name, that is, it does not belong to any segment.
 * @param elf Elf custom structure
 * @param name Elf section name
 * @return TRUE or FALSE
 */
int is_isolated_section_by_name(Elf *elf, char *name);
int is_isolated_section_by_index(Elf *elf, int index);


/****************************************/
/* dynamic segmentation */
/**
 * @brief 根据dynamic段的tag,获取段的下标
 * Get the dynamic segment index based on its tag.
 * @param elf Elf custom structure
 * @param tag Elf dynamic segment tag
 * @return index
 */
int get_dynseg_index_by_tag(Elf *elf, int tag);

/**
 * @brief 根据dynamic段的tag，得到值
 * get dynamic segment value by tag
 * @param elfname 
 * @param tag dynamic segment tag
 * @return value
 */
int get_dynseg_value_by_tag(Elf *elf, int tag);


/**
 * @brief 根据dynamic段的tag，设置tag
 * set dynamic segment tag by tag
 * @param elfname 
 * @param tag dynamic segment tag
 * @param value dynamic segment value
 * @return value
 */
int set_dynseg_tag_by_tag(Elf *elf, int tag, uint64_t new_tag);

/**
 * @brief 根据dynamic段的tag，设置值
 * set dynamic segment value by tag
 * @param elfname 
 * @param tag dynamic segment tag
 * @param value dynamic segment value
 * @return value
 */
int set_dynseg_value_by_tag(Elf *elf, int tag, uint64_t value);
/* dynamic segmentation */
/****************************************/


/**
 * @brief 设置新的节名
 * Set a new section name
 * @param elf Elf custom structure
 * @param src_name original section name
 * @param dst_name new section name
 * @return error code
 */
int set_section_name_t(Elf *elf, char *src_name, char *dst_name);

/**
 * @brief 设置符号表的名字
 * Set a new symbol name
 * @param elf Elf custom structure
 * @param src_name original symbo name
 * @param dst_name new symbol name
 * @return error code
 */
int set_sym_name_t(Elf *elf, char *src_name, char *dst_name);
int set_dynstr_name(Elf *elf, char *src_name, char *dst_name);

/**
 * @brief 添加符号名字
 * Add a new symbol name
 * @param elf Elf custom structure
 * @param name new symbol name
 * @param name_offset offset of new symbol name in dynstr table
 * @return error code
 */
int add_shstr_name(Elf *elf, char *name, uint64_t *name_offset);
int add_dynstr_name(Elf *elf, char *name, uint64_t *name_offset);

/**
 * @brief 扩充一个段，默认只扩充最后一个类型为PT_LOAD的段
 * Expand a segment, default to only expanding the last segment of type PT_LOAD
 * @param elf Elf custom structure
 * @return start offset
 */
/* deprecated */
int expand_segment_test(Elf *elf, size_t size);

// these variables need to be refreshed!
/**
 * @brief 扩充一个段
 * Expand a segment by its index
 * @param elf Elf custom structure
 * @param index segment index
 * @param size expand size
 * @param added_offset return start offset
 * @param added_vaddr return start virtual address
 * @return error code
 */
int expand_segment_load(Elf *elf, uint64_t index, size_t size, uint64_t *added_offset, uint64_t *added_vaddr);

/**
 * @brief 扩充一个节或者一个段
 * expand a section or segment
 * @param elf Elf custom structure 
 * @param offset sec/seg offset
 * @param org_size sec/seg origin size
 * @param add_content new added content
 * @param content_size new added content size
 * @return error code
 */
int expand_segment_content(Elf *elf, uint64_t org_offset, size_t org_size, char *add_content, size_t content_size);

/**
 * @brief 增加一个段，但是不在PHT增加新条目。我们可以通过修改不重要的段条目，比如类型为PT_NOTE、PT_NULL的段，实现这一功能。
 * Add a segment, but do not add a new entry in PHT. 
 * We can achieve this function by modifying unimportant segment entries, such as segments of type PT_NOTE or PT_NULL.
 * @param elf Elf custom structure
 * @param size segment size
 * @param added_index segment index
 * @return error code
 */
int add_segment_easy(Elf *elf, size_t size, size_t *added_index);

/**
 * @brief 增加一个段，但是不在PHT增加新条目。增加一个段，但是不修改已有的PHT新条目。为了不修改已有的PT_LOAD段的地址，我们只能搬迁PHT
 * Add a segment, but do not modify the existing PHT new entry. 
 * In order not to modify the address of the existing PT_LOAD segment, we can only relocate PHT.
 * @param elf Elf custom structure
 * @param size segment size
 * @param added_index segment index
 * @return error code
 */
int add_segment_difficult(Elf *elf, size_t size, size_t *added_index);

/**
 * @brief 增加一个段，自动选择增加方式
 * Add a segment, automatically choose the addition method
 * @param elf Elf custom structure
 * @param size segment size
 * @param added_index segment index
 * @return error code
 */
int add_segment_auto(Elf *elf, size_t size, size_t *added_index);

/**
 * @brief 增加一个段，并用文件填充内容
 * add a paragraph and fill in the content with a file
 * @param elf Elf custom structure 
 * @param type segment type
 * @param file file content
 * @return error code
 */
int add_segment_with_file(Elf *elf, int type, char *file);

/**
 * @brief 增加一个节，自动选择增加方式
 * Add a section, automatically choose the addition method
 * @param elf Elf custom structure
 * @param size section size
 * @param name section name
 * @param added_index section index
 * @return error code
 */
int add_section_auto(Elf *elf, size_t size, const char *name, uint64_t *added_index);

/**
 * @brief 增加一个段，自动选择增加方式
 * Add a segment, automatically choose the addition method
 * @param elf Elf custom structure
 * @param type dynamic segment type
 * @param value dynamic segment value
 * @return error code
 */
int add_dynseg_auto(Elf *elf, int type, uint64_t value);

/**
 * @brief 增加一个段
 * Add a dynamic segment
 * @param elf Elf custom structure
 * @param type dynamic segment type
 * @param value dynamic segment value
 * @return error code
 */
int add_dynseg_difficult(Elf *elf, int type, uint64_t value);

/**
 * @brief 增加一个.dynsym table条目
 * add a dynamic symbol stable item
 * @param elf Elf custom structure
 * @param name dynamic symbol name
 * @param value dynamic symbol address
 * @param code_size func size
 * @return int error code
 */
int add_dynsym_entry(Elf *elf, char *name, uint64_t value, size_t code_size);

/**
 * @brief 刷新ELF文件的.gnu.hash节
 * Refresh the .gnu.hash section of ELF file
 * @param elf Elf custom structure
 * @return error code
 */
int refresh_hash_table(Elf *elf);

/**i
 * @brief 获取elf文件类型
 * get elf file type
 * @param elf Elf custom structure
 * @return elf file type
 */
int get_file_type(Elf *elf);

/**
 * @brief 通过节索引删除节
 * Delete section by index
 * @param elf Elf custom structure
 * @param index section index
 * @return error code
 */
int delete_section_by_index(Elf *elf, uint64_t index);
int delete_section_by_name(Elf *elf, const char *name);

/**
 * @brief 删除所有节头表
 * Delete all section header table
 * @param elf Elf custom structure
 * @return error code
 */
int delete_all_shdr(Elf *elf);

/**
 * @brief 删除不必要的节
 * delelet unnecessary section, such as, .comment .symtab .strtab section
 * @param elf_name elf file name
 * @return error code
 */
int strip(Elf *elf);

/**
 * @brief 为二进制文件添加ELF头
 * Add ELF header to binary file
 * @param bin binary file path
 * @param arch architecture
 * @param class ELF class(32/64)
 * @param endian endianess(little/big)
 * @param base_addr base address
 * @return error code
 */
int add_elf_header(uint8_t *bin, uint8_t *arch, uint32_t class, uint8_t *endian, uint64_t base_addr);

/**
 * @brief 设置新的解释器（动态链接器）
 * set up a new interpreter (dynamic linker)
 * @param elf_name elf file name
 * @param new_interpreter string
 * @return error code
 */
int set_interpreter(Elf *elf, char *new_interpreter);

/**
 * @brief 设置rpath
 * set rpath
 * @param elf Elf custom structure
 * @param rpath string
 * @return error code
 */
int set_rpath(Elf *elf, char *rpath);

/**
 * @brief 设置runpath
 * set runpath
 * @param elf Elf custom structure
 * @param rpath string
 * @return error code
 */
int set_runpath(Elf *elf, char *runpath);

/**
 * @brief hook外部函数
 * hook function by .got.plt
 * @param elf_name elf file name
 * @param symbol symbol name
 * @param hookfile hook function file
 * @param hook_offset hook function offset in hook file
 * @return int error code {-1:error,0:sucess}
 */
int hook_extern(Elf *elf, char *symbol, char *hookfile, uint64_t hook_offset);

/***********************file***********************/

/**
 * @brief 将命令行传入的shellcode，转化为内存实际值
 * convert the shellcode passed in from the command line to the actual value in memory
 * @param sc_str input shellcode string
 * @param sc_mem output shellcode memory
 * @return error code
 */
int escaped_str_to_mem(char *sc_str, char *sc_mem);

/**
 * @brief 编辑ELF文件的十六进制内容
 * Edit the hex content of ELF file
 * @param elf Elf custom structure
 * @param offset edit start offset
 * @param data edit data
 * @param size edit size
 * @return error code
 */
int edit_hex(Elf *elf, uint64_t offset, uint8_t *data, size_t size);

/**
 * @brief 编辑ELF文件的指针内容
 * Edit the pointer content of ELF file
 * @param elf Elf custom structure
 * @param offset edit start offset
 * @param value edit value
 * @return error code
 */
int edit_pointer(Elf *elf, uint64_t offset, uint64_t value);

/**
 * @brief 从文件中提取指定偏移和大小的数据片段
 * Extract a data fragment from a file at a specified offset and size
 * @param file_name input file name
 * @param offset extract start offset
 * @param size extract size
 * @param output output buffer
 * @return error code
 */
int extract_fragment(const char *file_name, long offset, size_t size, char *output);

/**
 * @brief 将二进制文件转换为Windows cmd脚本
 * convert binary file to Windows cmd script
 * @param input_path input file name with path
 * @return error code
 */
void bin_to_cmd(const char* input_path);

/**
 * @brief 将二进制文件转换为Linux shell脚本
 * convert binary file to Linux shell script
 * @param input_path input file name with path
 * @return error code
 */
void bin_to_sh(const char* input_path);

/**
 * @brief 得到字符串
 * get symbol name
 * @param elf elf custom structure
 * @param name symbol name
 * @param count symbol count
 * @return int error code {-1:error,0:sucess}
 */
int get_sym_string_table(Elf *elf, char ***name, int *count);

/**
 * @brief 得到字符串
 * get symbol name
 * @param elf elf custom structure
 * @param name symbol name
 * @param count symbol count
 * @return int error code {-1:error,0:sucess}
 */
int get_dyn_string_table(Elf *elf, char ***name, int *count);