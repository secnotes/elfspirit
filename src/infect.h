/*
 MIT License
 
 Copyright (c) 2024 SecNotes
 
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
 * @brief 使用silvio感染算法，填充text段
 * use the Silvio infection algorithm to fill in text segments
 * @param elf elf file custom structure
 * @param parasite shellcode
 * @param size shellcode size (< 1KB)
 * @return uint64_t parasite address {-1:error,0:false,address}
 */
uint64_t infect_silvio(Elf *elf, char *parasite, size_t size);

/**
 * @brief 使用skeksi增强版感染算法，填充text段. 此算法适用于开启pie的二进制
 * use the Skeksi plus infection algorithm to fill in text segments
 * this algorithm is suitable for opening binary pie
 * @param elf elf file custom structure
 * @param parasite shellcode
 * @param size shellcode size (< 1KB)
 * @return uint64_t parasite address {-1:error,0:false,address}
 */
uint64_t infect_skeksi_pie(Elf *elf, char *parasite, size_t size);

/**
 * @brief 填充text段感染
 * fill in data segments infection algorithm
 * @param elf file custom structure
 * @param parasite shellcode
 * @param size shellcode size (< 1KB)
 * @return uint64_t parasite address {-1:error,0:false,address}
 */
uint64_t infect_data(Elf *elf, char *parasite, size_t size);