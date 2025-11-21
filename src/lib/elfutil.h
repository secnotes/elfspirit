#include <elf.h>
#include <stddef.h>

enum {
    /* ELF file error */
    ERR_SEG = -9,
    ERR_TYPE = -8,
    ERR_CLASS,
    /* other error */
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
    Elf32_Sym *dynsym_entry;
    Elf32_Dyn *dyn_segment_entry;
    size_t dyn_segment_count;
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
    Elf64_Sym *dynsym_entry;
    Elf64_Dyn *dyn_segment_entry;
    size_t dyn_segment_count;
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

/**
 * @brief 初始化elf文件，将elf文件转化为elf结构体
 * initialize the elf file and convert it into an elf structure
 * @param elf elf file name
 * @return error code
 */
int init(char *elf_name, Elf *elf);
int finit(Elf *elf);

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
 * @param src_name original symbole name
 * @param dst_name new symbole name
 * @return error code
 */
int set_sym_name_t(Elf *elf, char *src_name, char *dst_name);
int set_dynsym_name(Elf *elf, char *src_name, char *dst_name);

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
 * @brief 增加一个段，但是不在PHT增加新条目。我们可以通过修改不重要的段条目，比如类型为PT_NOTE、PT_NULL的段，实现这一功能。
 * Add a segment, but do not add a new entry in PHT. 
 * We can achieve this function by modifying unimportant segment entries, such as segments of type PT_NOTE or PT_NULL.
 * @param elf Elf custom structure
 * @param size segment size
 * @param added_index segment index
 * @return error code
 */
int add_segment_easy(Elf *elf, size_t size, uint64_t *added_index);

/**
 * @brief 增加一个段，但是不在PHT增加新条目。增加一个段，但是不修改已有的PHT新条目。为了不修改已有的PT_LOAD段的地址，我们只能搬迁PHT
 * Add a segment, but do not modify the existing PHT new entry. 
 * In order not to modify the address of the existing PT_LOAD segment, we can only relocate PHT.
 * @param elf Elf custom structure
 * @param size segment size
 * @param added_index segment index
 * @return error code
 */
int add_segment_difficult(Elf *elf, size_t size, uint64_t *added_index);

int get_file_type(Elf *elf);