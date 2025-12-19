/*
 * prompt: 使用C语言，设计一个数据结构，包含Elf64_Shdr *shdr和Elf32_Shdr *shdr类型的节，可以动态往这个结构中添加节，也可以按照shdr[index].sh_offset，对结构进行排序
 * prompt: 请使用链表实现，因为我不知道initial_capacity会有几个
 * prompt: 能否修改ELF节管理器，使其不是通过深拷贝方式独立存储的，而是直接引用原始section的地址，这样我就可以直接对section中的属性变量赋值了
*/
#include <stdio.h>
#include "manager.h"
#include "elfutil.h"

// 创建节管理器
SectionManager* section_manager_create() {
    SectionManager *manager = malloc(sizeof(SectionManager));
    if (!manager) return NULL;
    
    manager->head = NULL;
    manager->tail = NULL;
    manager->size = 0;
    return manager;
}

// 销毁节管理器（不释放原始section数据）
void section_manager_destroy(SectionManager *manager) {
    if (!manager) return;
    
    SectionNode *current = manager->head;
    while (current) {
        SectionNode *next = current->next;
        free(current);  // 只释放节点本身，不释放原始section数据
        current = next;
    }
    free(manager);
}

// 添加32位节头（直接引用原始地址）
int section_manager_add_32bit(SectionManager *manager, Elf32_Shdr *shdr, size_t index) {
    if (!manager || !shdr) return 0;
    
    SectionNode *new_node = malloc(sizeof(SectionNode));
    if (!new_node) return 0;
    
    // 直接引用原始section地址，不进行深拷贝
    new_node->type = SECTION_32BIT;
    new_node->original_index = index;
    new_node->shdr32 = shdr;  // 指向原始section
    new_node->next = NULL;
    
    if (manager->tail) {
        manager->tail->next = new_node;
    } else {
        manager->head = new_node;
    }
    manager->tail = new_node;
    manager->size++;
    
    return 1;
}

// 添加64位节头（直接引用原始地址）
int section_manager_add_64bit(SectionManager *manager, Elf64_Shdr *shdr, size_t index) {
    if (!manager || !shdr) return 0;
    
    SectionNode *new_node = malloc(sizeof(SectionNode));
    if (!new_node) return 0;
    
    // 直接引用原始section地址，不进行深拷贝
    new_node->type = SECTION_64BIT;
    new_node->original_index = index;
    new_node->shdr64 = shdr;  // 指向原始section
    new_node->next = NULL;
    
    if (manager->tail) {
        manager->tail->next = new_node;
    } else {
        manager->head = new_node;
    }
    manager->tail = new_node;
    manager->size++;
    
    return 1;
}

// 获取链表中间节点（用于归并排序）
static SectionNode* get_middle(SectionNode *head) {
    if (!head) return NULL;
    
    SectionNode *slow = head;
    SectionNode *fast = head->next;
    
    while (fast && fast->next) {
        slow = slow->next;
        fast = fast->next->next;
    }
    
    return slow;
}

// 合并两个已排序链表
static SectionNode* merge_sorted_lists(SectionNode *left, SectionNode *right, 
                                     int (*compare)(const SectionNode*, const SectionNode*)) {
    if (!left) return right;
    if (!right) return left;
    
    SectionNode *result = NULL;
    
    if (compare(left, right) <= 0) {
        result = left;
        result->next = merge_sorted_lists(left->next, right, compare);
    } else {
        result = right;
        result->next = merge_sorted_lists(left, right->next, compare);
    }
    
    return result;
}

// 比较函数用于排序
static int compare_sections(const SectionNode *a, const SectionNode *b) {
    Elf64_Off offsetA, offsetB;
    
    if (a->type == SECTION_32BIT) {
        offsetA = a->shdr32->sh_offset;
    } else {
        offsetA = a->shdr64->sh_offset;
    }
    
    if (b->type == SECTION_32BIT) {
        offsetB = b->shdr32->sh_offset;
    } else {
        offsetB = b->shdr64->sh_offset;
    }
    
    if (offsetA < offsetB) return -1;
    if (offsetA > offsetB) return 1;
    return 0;
}

// 比较函数用于降序排序
static int compare_sections_desc(const SectionNode *a, const SectionNode *b) {
    Elf64_Off offsetA, offsetB;
    
    if (a->type == SECTION_32BIT) {
        offsetA = a->shdr32->sh_offset;
    } else {
        offsetA = a->shdr64->sh_offset;
    }
    
    if (b->type == SECTION_32BIT) {
        offsetB = b->shdr32->sh_offset;
    } else {
        offsetB = b->shdr64->sh_offset;
    }
    
    if (offsetA > offsetB) return -1;
    if (offsetA < offsetB) return 1;
    return 0;
}

// 归并排序实现
static SectionNode* merge_sort(SectionNode *head, 
                              int (*compare)(const SectionNode*, const SectionNode*)) {
    if (!head || !head->next) return head;
    
    // 找到中间节点
    SectionNode *middle = get_middle(head);
    SectionNode *next_of_middle = middle->next;
    
    // 分割链表
    middle->next = NULL;
    
    // 递归排序
    SectionNode *left = merge_sort(head, compare);
    SectionNode *right = merge_sort(next_of_middle, compare);
    
    // 合并排序后的链表
    return merge_sorted_lists(left, right, compare);
}

/* 按节偏移升序排序 */
/* Sort by section offset in ascending order */
void section_manager_sort_by_offset_def(SectionManager *manager) {
    if (!manager || manager->size <= 1) return;
    
    manager->head = merge_sort(manager->head, compare_sections);
    
    // 更新尾指针
    SectionNode *current = manager->head;
    while (current && current->next) {
        current = current->next;
    }
    manager->tail = current;
}

/* 按节偏移降序排序 */
/* Sort by section offset in descending order */
void section_manager_sort_by_offset_desc(SectionManager *manager) {
    if (!manager || manager->size <= 1) return;
    
    manager->head = merge_sort(manager->head, compare_sections_desc);
    
    // 更新尾指针
    SectionNode *current = manager->head;
    while (current && current->next) {
        current = current->next;
    }
    manager->tail = current;
}

// 打印节信息
void section_manager_print(const SectionManager *manager) {
    if (!manager) return;
    
    printf("Total sections: %zu\n", manager->size);
    SectionNode *current = manager->head;
    size_t index = 0;
    
    while (current) {
        printf("Section [%zu]: ", index++);
        
        if (current->type == SECTION_32BIT) {
            printf("32-bit, offset: 0x%x\n", current->shdr32->sh_offset);
        } else {
            printf("64-bit, offset: 0x%lx\n", current->shdr64->sh_offset);
        }
        current = current->next;
    }
}

// 创建段管理器
SegmentManager* segment_manager_create() {
    SegmentManager *manager = malloc(sizeof(SegmentManager));
    if (!manager) return NULL;
    
    manager->head = NULL;
    manager->tail = NULL;
    manager->size = 0;
    
    return manager;
}

// 销毁段管理器
void segment_manager_destroy(SegmentManager *manager) {
    if (!manager) return;
    
    SegmentNode *current = manager->head;
    while (current) {
        SegmentNode *next = current->next;
        free(current);
        current = next;
    }
    free(manager);
}

// 添加32位段
int segment_manager_add_32bit(SegmentManager *manager, Elf32_Phdr *phdr, size_t original_index) {
    if (!manager || !phdr) return 0;
    
    SegmentNode *new_node = malloc(sizeof(SegmentNode));
    if (!new_node) return 0;
    
    new_node->type = SEGMENT_32BIT;
    new_node->original_index = original_index;
    new_node->phdr32 = phdr;
    new_node->next = NULL;
    
    if (!manager->head) {
        manager->head = new_node;
        manager->tail = new_node;
    } else {
        manager->tail->next = new_node;
        manager->tail = new_node;
    }
    
    manager->size++;
    return 1;
}

// 添加64位段
int segment_manager_add_64bit(SegmentManager *manager, Elf64_Phdr *phdr, size_t original_index) {
    if (!manager || !phdr) return 0;
    
    SegmentNode *new_node = malloc(sizeof(SegmentNode));
    if (!new_node) return 0;
    
    new_node->type = SEGMENT_64BIT;
    new_node->original_index = original_index;
    new_node->phdr64 = phdr;
    new_node->next = NULL;
    
    if (!manager->head) {
        manager->head = new_node;
        manager->tail = new_node;
    } else {
        manager->tail->next = new_node;
        manager->tail = new_node;
    }
    
    manager->size++;
    return 1;
}

// 获取段数量
size_t segment_manager_get_size(const SegmentManager *manager) {
    return manager ? manager->size : 0;
}

// 获取指定索引的段
void* segment_manager_get(SegmentManager *manager, size_t index) {
    if (!manager || index >= manager->size) return NULL;
    
    SegmentNode *current = manager->head;
    for (size_t i = 0; i < index && current; i++) {
        current = current->next;
    }
    
    return current ? (current->type == SEGMENT_32BIT ? (void*)current->phdr32 : (void*)current->phdr64) : NULL;
}

// 比较函数 - 升序
static int compare_offset_asc(const void *a, const void *b) {
    const SegmentNode *node1 = *(const SegmentNode**)a;
    const SegmentNode *node2 = *(const SegmentNode**)b;
    
    if (node1->type == SEGMENT_32BIT && node2->type == SEGMENT_32BIT) {
        return (node1->phdr32->p_offset > node2->phdr32->p_offset) - (node1->phdr32->p_offset < node2->phdr32->p_offset);
    } else if (node1->type == SEGMENT_64BIT && node2->type == SEGMENT_64BIT) {
        return (node1->phdr64->p_offset > node2->phdr64->p_offset) - (node1->phdr64->p_offset < node2->phdr64->p_offset);
    }
    return 0;
}

// 比较函数 - 降序
static int compare_offset_desc(const void *a, const void *b) {
    const SegmentNode *node1 = *(const SegmentNode**)a;
    const SegmentNode *node2 = *(const SegmentNode**)b;
    
    if (node1->type == SEGMENT_32BIT && node2->type == SEGMENT_32BIT) {
        return (node1->phdr32->p_offset < node2->phdr32->p_offset) - (node1->phdr32->p_offset > node2->phdr32->p_offset);
    } else if (node1->type == SEGMENT_64BIT && node2->type == SEGMENT_64BIT) {
        return (node1->phdr64->p_offset < node2->phdr64->p_offset) - (node1->phdr64->p_offset > node2->phdr64->p_offset);
    }
    return 0;
}

// 按p_offset升序排序
void segment_manager_sort_by_offset_asc(SegmentManager *manager) {
    if (!manager || manager->size <= 1) return;
    
    // 将链表转换为数组进行排序
    SegmentNode **node_array = malloc(sizeof(SegmentNode*) * manager->size);
    if (!node_array) return;
    
    SegmentNode *current = manager->head;
    for (size_t i = 0; i < manager->size && current; i++) {
        node_array[i] = current;
        current = current->next;
    }
    
    qsort(node_array, manager->size, sizeof(SegmentNode*), compare_offset_asc);
    
    // 重新构建链表
    manager->head = node_array[0];
    for (size_t i = 0; i < manager->size - 1; i++) {
        node_array[i]->next = node_array[i + 1];
    }
    node_array[manager->size - 1]->next = NULL;
    manager->tail = node_array[manager->size - 1];
    
    free(node_array);
}

// 按p_offset降序排序
void segment_manager_sort_by_offset_desc(SegmentManager *manager) {
    if (!manager || manager->size <= 1) return;
    
    SegmentNode **node_array = malloc(sizeof(SegmentNode*) * manager->size);
    if (!node_array) return;
    
    SegmentNode *current = manager->head;
    for (size_t i = 0; i < manager->size && current; i++) {
        node_array[i] = current;
        current = current->next;
    }
    
    qsort(node_array, manager->size, sizeof(SegmentNode*), compare_offset_desc);
    
    manager->head = node_array[0];
    for (size_t i = 0; i < manager->size - 1; i++) {
        node_array[i]->next = node_array[i + 1];
    }
    node_array[manager->size - 1]->next = NULL;
    manager->tail = node_array[manager->size - 1];
    
    free(node_array);
}

// 打印段信息
void segment_manager_print(const SegmentManager *manager) {
    if (!manager) {
        printf("Segment manager is NULL\n");
        return;
    }
    
    printf("Segment Manager (size: %zu):\n", manager->size);
    SegmentNode *current = manager->head;
    size_t index = 0;
    
    while (current) {
        printf("  [%zu] ", index);
        if (current->type == SEGMENT_32BIT) {
            printf("32-bit: offset=0x%x, size=0x%x, flags=0x%x\n",
               current->phdr32->p_offset, current->phdr32->p_filesz, current->phdr32->p_flags);
        } else {
            printf("64-bit: offset=0x%lx, size=0x%lx, flags=0x%x\n",
               current->phdr64->p_offset, current->phdr64->p_filesz, current->phdr64->p_flags);
        }
        current = current->next;
        index++;
    }
}

/**
 * prompt: 
 * 请使用链表设计一个数据结构，用于表示下标的映射关系
 * 例如，main_index=1，对应的sub_segment=[6, 9, 10]，sub_section=[2, 5, 9]
 */
// 创建新节点
ListNode* create_node(int index) {
    ListNode* new_node = (ListNode*)malloc(sizeof(ListNode));
    if (new_node == NULL) {
        printf("内存分配失败\n");
        return NULL;
    }
    new_node->index = index;
    new_node->next = NULL;
    return new_node;
}

// 向链表尾部添加节点
void append_node(ListNode** head, int index) {
    ListNode* new_node = create_node(index);
    if (new_node == NULL) return;
    
    if (*head == NULL) {
        *head = new_node;
        return;
    }
    
    ListNode* current = *head;
    while (current->next != NULL) {
        current = current->next;
    }
    current->next = new_node;
}

// 创建单个映射关系
IndexMapping* create_mapping(int main_index) {
    IndexMapping* mapping = (IndexMapping*)malloc(sizeof(IndexMapping));
    if (mapping == NULL) {
        printf("内存分配失败\n");
        return NULL;
    }
    mapping->main_index = main_index;
    mapping->seg_head = NULL;
    mapping->sec_head = NULL;
    mapping->next = NULL;
    return mapping;
}

// 添加sub_segment
void add_subseg(IndexMapping* mapping, int index) {
    append_node(&(mapping->seg_head), index);
}

// 添加sub_section
void add_subsec(IndexMapping* mapping, int index) {
    append_node(&(mapping->sec_head), index);
}

// 创建映射列表
MappingList* create_mapping_list() {
    MappingList* list = (MappingList*)malloc(sizeof(MappingList));
    if (list == NULL) {
        printf("内存分配失败\n");
        return NULL;
    }
    list->head = NULL;
    list->count = 0;
    return list;
}

// 添加映射到列表
void add_mapping_to_list(MappingList* list, IndexMapping* mapping) {
    if (list == NULL || mapping == NULL) return;
    
    if (list->head == NULL) {
        list->head = mapping;
    } else {
        IndexMapping* current = list->head;
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = mapping;
    }
    list->count++;
}

// 查找指定main_index的映射
IndexMapping* find_mapping(MappingList* list, int main_index) {
    if (list == NULL) return NULL;
    
    IndexMapping* current = list->head;
    while (current != NULL) {
        if (current->main_index == main_index) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

// 从列表中删除映射
void remove_mapping(MappingList* list, int main_index) {
    if (list == NULL || list->head == NULL) return;
    
    IndexMapping* current = list->head;
    IndexMapping* prev = NULL;
    
    while (current != NULL) {
        if (current->main_index == main_index) {
            if (prev == NULL) {
                list->head = current->next;
            } else {
                prev->next = current->next;
            }
            free_mapping(current);
            list->count--;
            return;
        }
        prev = current;
        current = current->next;
    }
}

// 打印链表
void print_list(const char* name, ListNode* head) {
    printf("%s: [", name);
    ListNode* current = head;
    while (current != NULL) {
        printf("%d", current->index);
        if (current->next != NULL) {
            printf(", ");
        }
        current = current->next;
    }
    printf("]\n");
}

// 打印单个映射关系
void print_mapping(IndexMapping* mapping) {
    if (mapping == NULL) return;
    printf("main_index = %d\n", mapping->main_index);
    print_list("sub_segment", mapping->seg_head);
    print_list("sub_section", mapping->sec_head);
    printf("---\n");
}

// 打印所有映射关系
void print_all_mappings(MappingList* list) {
    if (list == NULL || list->head == NULL) {
        printf("映射列表为空\n");
        return;
    }
    
    printf("=== 所有映射关系 (共%d个) ===\n", list->count);
    IndexMapping* current = list->head;
    while (current != NULL) {
        print_mapping(current);
        current = current->next;
    }
}

// 释放链表内存
void free_list(ListNode* head) {
    ListNode* current = head;
    while (current != NULL) {
        ListNode* temp = current;
        current = current->next;
        free(temp);
    }
}

// 释放单个映射关系内存
void free_mapping(IndexMapping* mapping) {
    if (mapping != NULL) {
        free_list(mapping->seg_head);
        free_list(mapping->sec_head);
        free(mapping);
    }
}

// 释放整个映射列表内存
void free_mapping_list(MappingList* list) {
    if (list == NULL) return;
    
    IndexMapping* current = list->head;
    while (current != NULL) {
        IndexMapping* temp = current;
        current = current->next;
        free_mapping(temp);
    }
    free(list);
}


/**
 * @brief Compare string
 * 比较两个字符串的前n位是否相同
 * @param str1 
 * @param str2 
 * @param n 
 * @return int 
 */
int compare_firstN_chars(const char *str1, const char *str2, int n) {
    // 检查字符串长度是否小于n，如果是，则返回0（不相同）
    if (strlen(str1) < n || strlen(str2) < n) {
        return 0;
    }

    // 比较两个字符串的前n位是否相同
    return strncmp(str1, str2, n) == 0;
}

// 创建集合
Set* create_set() {
    Set *set = malloc(sizeof(Set));
    set->data = malloc(INITIAL_CAPACITY * sizeof(int));
    set->size = 0;
    set->capacity = INITIAL_CAPACITY;
    return set;
}

// 检查元素是否在集合中
int contains_element(Set *set, int value) {
    for (int i = 0; i < set->size; i++) {
        if (set->data[i] == value) {
            return true; // 找到
        }
    }
    return false; // 未找到
}

// 增加元素
void add_element(Set *set, int value) {
    if (contains_element(set, value)) {
        return; // 元素已存在
    }
    if (set->size >= set->capacity) {
        set->capacity *= 2;
        set->data = realloc(set->data, set->capacity * sizeof(int));
    }
    set->data[set->size++] = value;
}

// 移除元素
void remove_element(Set *set, int value) {
    for (int i = 0; i < set->size; i++) {
        if (set->data[i] == value) {
            set->data[i] = set->data[--set->size]; // 用最后一个元素替换已删除的元素
            return;
        }
    }
}

// 打印集合
void print_set(Set *set) {
    printf("{ ");
    for (int i = 0; i < set->size; i++) {
        printf("%d ", set->data[i]);
    }
    printf("}\n");
}

// 释放集合
void free_set(Set *set) {
    free(set->data);
    free(set);
}