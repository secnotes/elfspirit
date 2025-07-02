/*
 MIT License
 
 Copyright (c) 2021 SecNotes
 
 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:
 
 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
*/

/**
 * @description: delete data from ELF memory
 * @param {char} *elf_map
 * @param {uint32_t} file_size
 * @param {uint32_t} offset data offset in elf
 * @param {uint32_t} data_size data size
 * @return {*}
 */
char *delete_data_from_mem(char *elf_map, uint32_t file_size, uint32_t offset, uint32_t data_size);

/**
 * @brief 从文件中删除特定片段，请注意这个操作会改变文件大小
 * Delete specific fragments from the file, 
 * please note that this operation will change the file size
 * @param file_name file name 
 * @param offset fragment offset
 * @param size fragment size
 * @return int error code {-1:error,0:sucess}
 */
int delete_data_from_file(char *file_name, uint64_t offset, size_t size);

/**
 * @brief 清理节的内容，但是并没有改变节的大小
 * clean up the content of the section, but do not change the size of the section
 * @param elf_name elf file name
 * @param section_name section name
 * @param config_name multi section name
 * @return int error code {-1:error,0:sucess}
 */
int clear_section(char *elf_name, char *section_name, char *config_name);

/**
 * @brief 删除节头表
 * delelet section header table
 * @param elf_name elf file name
 * @return int error code {-1:error,0:sucess}
 */
int delete_shtab(char *elf);