#include <elf.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// 统一节头类型枚举
typedef enum {
    SECTION_32BIT,
    SECTION_64BIT
} SectionType;

// 通用节头包装器
typedef struct SectionNode {
    SectionType type;
    size_t original_index;
    union {
        Elf32_Shdr *shdr32;
        Elf64_Shdr *shdr64;
    };
    struct SectionNode *next;
} SectionNode;

// 动态节头管理器
typedef struct {
    SectionNode *head;
    SectionNode *tail;
    size_t size;
} SectionManager;

SectionManager* section_manager_create();
void section_manager_destroy(SectionManager *manager);
int section_manager_add_32bit(SectionManager *manager, Elf32_Shdr *shdr, size_t original_index);
int section_manager_add_64bit(SectionManager *manager, Elf64_Shdr *shdr, size_t original_index);
void section_manager_sort_by_offset_def(SectionManager *manager);
void section_manager_sort_by_offset_desc(SectionManager *manager);
void section_manager_print(const SectionManager *manager);