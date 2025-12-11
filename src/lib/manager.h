#include <elf.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Section Manager */
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

/* Segment Manager */
// 统一段类型枚举
typedef enum {
    SEGMENT_32BIT,
    SEGMENT_64BIT
} SegmentType;

// 通用段头包装器
typedef struct SegmentNode {
    SegmentType type;
    size_t original_index;
    union {
        Elf32_Phdr *phdr32;
        Elf64_Phdr *phdr64;
    };
    struct SegmentNode *next;
} SegmentNode;

// 动态段管理器
typedef struct {
    SegmentNode *head;
    SegmentNode *tail;
    size_t size;
} SegmentManager;

SegmentManager* segment_manager_create();
void segment_manager_destroy(SegmentManager *manager);
int segment_manager_add_32bit(SegmentManager *manager, Elf32_Phdr *phdr, size_t original_index);
int segment_manager_add_64bit(SegmentManager *manager, Elf64_Phdr *phdr, size_t original_index);
void segment_manager_sort_by_offset_asc(SegmentManager *manager);
void segment_manager_sort_by_offset_desc(SegmentManager *manager);
void* segment_manager_get(SegmentManager *manager, size_t index);
size_t segment_manager_get_size(const SegmentManager *manager);
void segment_manager_print(const SegmentManager *manager);


/* Section to Segment Mapper */
// 链表节点结构
typedef struct ListNode {
    int index;
    struct ListNode* next;
} ListNode;

// 单个映射关系结构
typedef struct IndexMapping {
    int main_index;
    ListNode* seg_head;
    ListNode* sec_head;
    struct IndexMapping* next;
} IndexMapping;

// 映射列表结构
typedef struct {
    IndexMapping* head;
    int count;
} MappingList;

// 函数声明
ListNode* create_node(int index);
void append_node(ListNode** head, int index);
IndexMapping* create_mapping(int main_index);
void add_subseg(IndexMapping* mapping, int index);
void add_subsec(IndexMapping* mapping, int index);
MappingList* create_mapping_list();
void add_mapping_to_list(MappingList* list, IndexMapping* mapping);
IndexMapping* find_mapping(MappingList* list, int main_index);
void remove_mapping(MappingList* list, int main_index);
void print_list(const char* name, ListNode* head);
void print_mapping(IndexMapping* mapping);
void print_all_mappings(MappingList* list);
void free_list(ListNode* head);
void free_mapping(IndexMapping* mapping);
void free_mapping_list(MappingList* list);

#define INITIAL_CAPACITY 10

typedef struct {
    int *data;
    int size;
    int capacity;
} Set;

// 创建集合
Set* create_set();

// 检查元素是否在集合中
int contains_element(Set *set, int value);

// 增加元素
void add_element(Set *set, int value);

// 移除元素
void remove_element(Set *set, int value);

// 打印集合
void print_set(Set *set);

// 释放集合
void free_set(Set *set);