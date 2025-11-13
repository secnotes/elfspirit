/*
 * prompt: 使用C语言，设计一个数据结构，包含Elf64_Shdr *shdr和Elf32_Shdr *shdr类型的节，可以动态往这个结构中添加节，也可以按照shdr[index].sh_offset，对结构进行排序
 * prompt: 请使用链表实现，因为我不知道initial_capacity会有几个
 * prompt: 能否修改ELF节管理器，使其不是通过深拷贝方式独立存储的，而是直接引用原始section的地址，这样我就可以直接对section中的属性变量赋值了
*/
#include "section_manager.h"
#include <stdio.h>

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
