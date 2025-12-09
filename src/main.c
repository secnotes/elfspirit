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

#include <getopt.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>

#include "parse.h"
#include "common.h"
#include "edit.h"
#include "segment.h"
#include "rel.h"
#include "lib/elfutil.h"
#include "lib/util.h"

#define VERSION "1.10.2"
#define CONTENT_LENGTH 1024 * 1024

char section_name[LENGTH];
char string[PAGE_SIZE];
char file[PAGE_SIZE];
char config_name[PAGE_SIZE];
char arch[LENGTH];
char endian[LENGTH];
char ver[LENGTH];
char ver_elfspirt[LENGTH];
char elf_name[LENGTH];
char function[LENGTH];
char *g_shellcode;
int err;
uint64_t base_addr;
uint32_t size;
uint32_t off;
uint32_t class;
uint32_t value;
uint32_t row;
uint32_t column;
uint32_t length;
parser_opt_t po;
/* Additional long parameters */
static int g_long_option;
enum LONG_OPTION {
    EDIT_POINTER = 1,
    EDIT_CONTENT,
    EDIT_EXTRACT,
    SET_INTERPRETER,
    ADD_SEGMENT,
    ADD_SECTION,
    REMOVE_SECTION,
    REMOVE_SHDR,
    REMOVE_STRIP,
    REFRESH_HASH,
    INFECT_SILVIO,
    INFECT_SKEKSI,
    INFECT_DATA,
    SET_RPATH,
    SET_RUNPATH,
    TO_EXE2SO,
    TO_HEX2BIN,
    TO_BIN2ELF,
    TO_SCRIPT,
    INJECT_HOOK,
};

/**
 * @description: obtain tool version
 */
static int get_version(char *ver, size_t len) {
    int fd;
    int ret;

    fd = open("./VERSION", O_RDONLY);
    if (fd < 0) {
        ret = strcpy(ver, VERSION);
        return ret;
    }

    ret = read(fd, ver, len);
    close(fd);
    return ret;
}

/**
 * @description: initialize arguments
 */
static void main_init() {
    memset(section_name, 0, LENGTH);
    memset(string, 0, PAGE_SIZE);
    memset(file, 0, PAGE_SIZE);
    memset(config_name, 0, LENGTH);
    memset(elf_name, 0, LENGTH);
    memset(function, 0, LENGTH);
    size = 0;
    off = 0;
    err = 0;
    get_version(ver_elfspirt, LENGTH);
    po.index = 0;
    memset(po.options, 0, sizeof(po.options));
}
static const char *shortopts = "n:z:s:f:c:a:m:e:b:o:v:i:j:l:h::AHSPBDLRIG";

static const struct option longopts[] = {
    {"section-name", required_argument, NULL, 'n'},
    {"section-size", required_argument, NULL, 'z'},
    {"string", required_argument, NULL, 's'},
    {"file-name", required_argument, NULL, 'f'},
    {"configure-name", required_argument, NULL, 'c'},
    {"architcture", required_argument, NULL, 'a'},
    {"class", required_argument, NULL, 'm'},
    {"value", required_argument, NULL, 'm'},
    {"endian", required_argument, NULL, 'e'},
    {"base", required_argument, NULL, 'b'},
    {"offset", required_argument, NULL, 'o'},
    {"lib-version", required_argument, NULL, 'v'},
    {"help", optional_argument, NULL, 'h'},
    {"index", required_argument, NULL, 'i'},
    {"row", required_argument, NULL, 'i'},
    {"column", required_argument, NULL, 'j'},
    {"length", required_argument, NULL, 'l'},
    {"edit-pointer", no_argument, &g_long_option, EDIT_POINTER},
    {"edit-hex", no_argument, &g_long_option, EDIT_CONTENT},
    {"edit-extract", no_argument, &g_long_option, EDIT_EXTRACT},
    {"set-interp", no_argument, &g_long_option, SET_INTERPRETER},
    {"add-segment", no_argument, &g_long_option, ADD_SEGMENT},
    {"add-section", no_argument, &g_long_option, ADD_SECTION},
    {"rm-section", no_argument, &g_long_option, REMOVE_SECTION},
    {"rm-shdr", no_argument, &g_long_option, REMOVE_SHDR},
    {"rm-strip", no_argument, &g_long_option, REMOVE_STRIP},
    {"refresh-hash", no_argument, &g_long_option, REFRESH_HASH},
    {"infect-silvio", no_argument, &g_long_option, INFECT_SILVIO},
    {"infect-skeksi", no_argument, &g_long_option, INFECT_SKEKSI},
    {"infect-data", no_argument, &g_long_option, INFECT_DATA},
    {"set-rpath", no_argument, &g_long_option, SET_RPATH},
    {"set-runpath", no_argument, &g_long_option, SET_RUNPATH},
    {"to-exe2so", no_argument, &g_long_option, TO_EXE2SO},
    {"to-hex2bin", no_argument, &g_long_option, TO_HEX2BIN},
    {"to-bin2elf", no_argument, &g_long_option, TO_BIN2ELF},
    {"to-script", no_argument, &g_long_option, TO_SCRIPT},
    {"inject-hook", no_argument, &g_long_option, INJECT_HOOK},
    {0, 0, 0, 0}
};

/**
 * @description: the online help text.
 */
static const char *help = 
    "Usage: elfspirit [function] [option]<argument>... ELF\n"
    "Currently defined functions:\n"
    "  parse        Parse ELF file statically like readelf\n"
    "  edit         Modify ELF file information freely\n"
    "  shellcode    Extract binary fragments and convert shellcode. [extract, hex2bin]\n"
    "  firmware     Add ELF info to firmware or join mutli bin file. [bin2elf, joinelf]\n"
    "  patch        Patch ELF. [--set-interpreter, --set-rpath, --set-runpath]\n"
    "  confuse      Obfuscate ELF symbols. [--rm-section, --rm-shdr, --rm-strip, confuse]\n"
    "  infect       Infect ELF like virus. [--infect-silvio, --infect-skeksi, --infect-data, exe2so]\n"
    "  forensic     Analyze the Legitimacy of ELF File Structure. [checksec]\n"
    "Currently defined options:\n"
    "  -n, --section-name=<section name>         Set section name\n"
    "  -z, --section-size=<section size>         Set section size\n"
    "  -f, --file-name=<file name>               File containing code(e.g. so, etc.)\n"
    "  -s, --string-name=<string name>           String value\n"
    "  -c, --configure-name=<file name>          File containing configure(e.g. json, etc.)\n"
    "  -a, --architecture=<ELF architecture>     ELF architecture\n"
    "  -m, --class=<ELF machine>                 ELF class(e.g. 32bit, 64bit, etc.)\n"
    "      --value=<math value>                  Reserve value(e.g. 7=111=rwx)\n"
    "  -e, --endian=<ELF endian>                 ELF endian(e.g. little, big, etc.)\n"
    "  -b, --base=<ELF base address>             ELF base address\n"
    "  -o, --offset=<injection offset>           Offset of injection point\n"
    "  -i, --row=<object index>                  Index of the object to be read or written\n"
    "  -j, --column=<vertical axis>              The vertical axis of the object to be read or written\n"
    "  -l, --length=<string length>              Display the maximum length of the string\n"
    "  -v, --version-libc=<libc version>         Libc.so or ld.so version\n"
    "  -h, --help[={none|English|Chinese}]       Display this output\n"
    "  -A, (no argument)                         Display all ELF file infomation\n"
    "  -H, (no argument)                         Display | Edit ELF file header\n"
    "  -S, (no argument)                         Display | Edit the section header\n"
    "  -P, (no argument)                         Display | Edit the program header\n"
    "  -B, (no argument)                         Display | Edit .symtab information\n"
    "  -D, (no argument)                         Display | Edit .dynsym information\n"
    "  -L, (no argument)                         Display | Edit .dynamic information\n"
    "  -R, (no argument)                         Display | Edit relocation section\n"
    "  -I, (no argument)                         Display | Edit pointer(e.g. .init_array, etc.)\n"
    "  -G, (no argument)                         Display hash table\n"
    "Detailed Usage: \n"
    "  elfspirit parse    [-A|H|S|P|B|D|R|I|G] ELF\n"
    "  elfspirit edit     [-H|S|P|B|D|R|I] [-i]<row> [-j]<column> [-m|-s]<int|string value> ELF\n" 
    "  elfspirit checksec ELF\n"
    "  elfspirit --edit-hex      [-o]<offset> [-s]<hex string> [-z]<size> file\n"
    "  elfspirit --edit-pointer  [-o]<offset> [-m]<pointer value> file\n"
    "  elfspirit --edit-extract  [-o]<file offset> [-z]<size> file\n"
    "  elfspirit --set-interp  [-s]<new interpreter> ELF\n"
    "  elfspirit --set-rpath   [-s]<rpath> ELF\n"
    "  elfspirit --set-runpath [-s]<runpath> ELF\n"
    "  elfspirit --add-section [-z]<size> [-n]<section name> ELF\n"
    "  elfspirit --add-segment [-z]<size> ELF\n"
    "                          [-f]<segment file> ELF\n"
    "  elfspirit --rm-section  [-n]<section name> ELF\n"
    "                          [-c]<multi section name> ELF\n"
    "  elfspirit --rm-shdr ELF\n"
    "  elfspirit --rm-strip ELF\n"
    "  elfspirit --inject-hook [-s]<hook symbol> [-f]<new function bin> [-o]<new function start offset> ELF\n"
    "  elfspirit --to-hex2bin  [-s]<shellcode hex> [-z]<size> outfile\n"
    "  elfspirit --to-bin2elf  [-a]<arm|x86> [-m]<32|64> [-e]<little|big> [-b]<base address> ELF\n"
    "  elfspirit --to-exe2so   [-s]<symbol> [-m]<function offset> [-z]<function size> ELF\n"
    "  elfspirit --to-script   file\n"
    "  elfspirit --refresh-hash ELF\n"
    "  elfspirit --infect-silvio [-s]<shellcode> [-z]<size> ELF\n"
    "  elfspirit --infect-skeksi [-s]<shellcode> [-z]<size> ELF\n"
    "  elfspirit --infect-data   [-s]<shellcode> [-z]<size> ELF\n";

static const char *help_chinese = 
    "用法: elfspirit [功能] [选项]<参数>... ELF\n"
    "当前已定义的功能:\n"
    "  parse        ELF文件格式分析, 类似于readelf\n"
    "  edit         自由修改ELF每个字节\n"
    "  shellcode    从目标文件中提取二进制片段，将shellcode转化为二进制. [extract, hex2bin]\n"
    "  firmware     用于IOT固件，比如将二进制转换为elf文件，连接多个bin文件. [bin2elf, joinelf]\n"
    "  patch        修补ELF. [--set-interpreter, --set-rpath, --set-runpath]\n"
    "  confuse      删除节、过滤符号表、删除节头表，混淆ELF符号. [--rm-section, --rm-shdr, --rm-strip, confuse]\n"
    "  infect       ELF文件感染. [--infect-silvio, --infect-skeksi, --infect-data, exe2so]\n"
    "  forensic     分析ELF文件结构的合法性. [checksec]\n"
    "支持的选项:\n"
    "  -n, --section-name=<section name>         设置节名\n"
    "  -z, --section-size=<section size>         设置节大小\n"
    "  -f, --file-name=<file name>               包含代码的文件名称(如某个so库)\n"
    "  -s, --string-name=<string name>           传入字符串值\n"
    "  -c, --configure-name=<file name>          配置文件(如json)\n"
    "  -a, --architecture=<ELF architecture>     ELF文件的架构(预留选项，非必须)\n"
    "  -m, --class=<ELF machine>                 设置ELF字长(32bit, 64bit)\n"
    "      --value=<math value>                  预留的参数，可以用于传递数值(e.g. 7=111=rwx)\n"
    "  -e, --endian=<ELF endian>                 设置ELF大小端(little, big)\n"
    "  -b, --base=<ELF base address>             设置ELF入口地址\n"
    "  -o, --offset=<injection offset>           注入点的偏移位置(预留选项，非必须)\n"
    "  -i, --row=<object index>                  待读出或者写入的对象的下标\n"
    "  -j, --column=<vertical axis>              待读出或者写入的对象的纵坐标\n"
    "  -l, --length=<string length>              解析ELF文件时，显示字符串的最大长度\n"
    "  -v, --version-libc=<libc version>         libc或者ld的版本\n"
    "  -h, --help[={none|English|Chinese}]       帮助\n"
    "  -A, 不需要参数                    显示ELF解析器解析的所有信息\n"
    "  -H, 不需要参数                    显示|编辑ELF: ELF头\n"
    "  -S, 不需要参数                    显示|编辑ELF: 节头\n"
    "  -P, 不需要参数                    显示|编辑ELF: 程序头\n"
    "  -B, 不需要参数                    显示|编辑ELF: 静态符号表\n"
    "  -D, 不需要参数                    显示|编辑ELF: 动态符号表\n"
    "  -L, 不需要参数                    显示|编辑ELF: 动态链接\n"
    "  -R, 不需要参数                    显示|编辑ELF: 重定位表\n"
    "  -R, 不需要参数                    显示|编辑ELF: 指针(e.g. .init_array, etc.)\n"
    "  -G, 不需要参数                    显示hash表\n"
    "细节: \n"
    "  elfspirit parse    [-A|H|S|P|B|D|R|I|G] ELF\n"
    "  elfspirit edit     [-H|S|P|B|D|R] [-i]<第几行> [-j]<第几列> [-m|-s]<int|str修改值> ELF\n"
    "  elfspirit checksec ELF\n"
    "  elfspirit --edit-hex      [-o]<偏移> [-s]<hex string> [-z]<size> file\n"
    "  elfspirit --edit-pointer  [-o]<偏移> [-m]<指针值> file\n"
    "  elfspirit --edit-extract  [-o]<节的偏移> [-z]<size> file\n"
    "  elfspirit --set-interp  [-s]<新的链接器> ELF\n"
    "  elfspirit --set-rpath   [-s]<rpath> ELF\n"
    "  elfspirit --set-runpath [-s]<runpath> ELF\n"
    "  elfspirit --add-section [-z]<size> [-n]<节的名字> ELF\n"
    "  elfspirit --add-segment [-z]<size> ELF\n"
    "                          [-f]<segment file> ELF\n"
    "  elfspirit --rm-section  [-n]<节的名字> ELF\n"
    "                          [-c]<多个节的名字> ELF\n"
    "  elfspirit --rm-shdr ELF\n"
    "  elfspirit --rm-strip ELF\n"
    "  elfspirit --inject-hook [-s]<hook函数名> [-f]<新的函数二进制> [-o]<新函数偏移> ELF\n"
    "  elfspirit --to-hex2bin  [-s]<shellcode> [-z]<size> outfile\n"
    "  elfspirit --to-bin2elf  [-a]<arm|x86> [-m]<32|64> [-e]<little|big> [-b]<基地址> ELF\n"
    "  elfspirit --to-exe2so   [-s]<函数名> [-m]<函数偏移> [-z]<函数大小> ELF\n"
    "  elfspirit --to-script   file\n"
    "  elfspirit --refresh-hash ELF\n"
    "  elfspirit --infect-silvio [-s]<shellcode> [-z]<size> ELF\n"
    "  elfspirit --infect-skeksi [-s]<shellcode> [-z]<size> ELF\n"
    "  elfspirit --infect-data   [-s]<shellcode> [-z]<size> ELF\n";

static void readcmdline(int argc, char *argv[]) {
    int opt;
    if (argc == 1) {
        printf("Current version: %s\n", ver_elfspirt);
        fputs(help, stdout);
    }
    while((opt = getopt_long(argc, argv, shortopts, longopts, NULL)) != EOF) {
        /* The row of options cannot be greater than the array capacity */
        if (po.index >= sizeof(po.options)) {
            break;
        }
        switch (opt) {
            // set section name
            case 'n':
                memcpy(section_name, optarg, LENGTH);
                break;
            
            // set section size
            case 'z':
                if (optarg[0] == '0' && optarg[1] == 'x') {
                    size = hex2int(optarg);
                }
                else{
                    size = atoi(optarg);
                }                
                break;
            
            // set string
            case 's':
                memcpy(string, optarg, strlen(optarg));
                break;
            
            // set file name
            case 'f':
                memcpy(file, optarg, strlen(optarg));
                break;

            // configure
            case 'c':
                memcpy(config_name, optarg, LENGTH);
                break;

            /***** add elf info to firmware for IDA - STRT*****/
            // set architecture
            case 'a':
                memcpy(arch, optarg, LENGTH);
                break;

            // set class
            case 'm':
                if (optarg[0] == '0' && optarg[1] == 'x') {
                    class = hex2int(optarg);
                }
                else{
                    class = atoi(optarg);
                }
                value = class;
                break;
            
            // set endian
            case 'e':
                memcpy(endian, optarg, LENGTH);
                break;

            // set base address
            case 'b':
                if (optarg[0] == '0' && optarg[1] == 'x') {
                    base_addr = hex2int(optarg);
                }
                else{
                    base_addr = atoi(optarg);
                }                
                break;
            /***** add elf info to firmware for IDA - END *****/

            // set offset
            case 'o':
                if (optarg[0] == '0' && optarg[1] == 'x') {
                    off = hex2int(optarg);
                }
                else{
                    off = atoi(optarg);
                }                
                break;

            // set libc version
            case 'v':
                memcpy(ver, optarg, LENGTH);
                break;
            
            case 'h':
                if (optarg != NULL && !strcmp(optarg, "Chinese")){       
                    fputs(help_chinese, stdout);
                    printf("当前版本: %s\n", ver_elfspirt);
                }
                else {
                    fputs(help, stdout);
                    printf("Current version: %s\n", ver_elfspirt);                
                }                    
                           
                break;

            case 'i':
                if (strlen(optarg) > 1 && optarg[0] == '0' && optarg[1] == 'x') {
                    row = hex2int(optarg);
                }
                else{
                    row = atoi(optarg);
                }                
                break;

            case 'j':
                if (strlen(optarg) > 1 && optarg[0] == '0' && optarg[1] == 'x') {
                    column = hex2int(optarg);
                }
                else{
                    column = atoi(optarg);
                }                
                break;

            case 'l':
                if (strlen(optarg) > 1 && optarg[0] == '0' && optarg[1] == 'x') {
                    length = hex2int(optarg);
                }
                else{
                    length = atoi(optarg);
                }                
                break;

            /* ELF parser's options */
            case 'A':
                po.options[po.index++] = ALL;
                break;
            case 'H':
                po.options[po.index++] = HEADERS;
                break;
            
            case 'S':
                po.options[po.index++] = SECTIONS;
                break;

            case 'P':
                po.options[po.index++] = SEGMENTS;
                break;
            
            case 'B':
                po.options[po.index++] = SYMTAB;
                break;

            case 'D':
                po.options[po.index++] = DYNSYM;
                break;

            case 'L':
                po.options[po.index++] = LINK;
                break;

            case 'R':
                po.options[po.index++] = RELA;
                break;

            case 'I':
                po.options[po.index++] = POINTER;
                break;

            case 'G':
                po.options[po.index++] = GNUHASH;
                break;
            
            default:
                break;
        }
    }

    /* handle additional long parameters */
    Elf elf;
    char *shellcode;
    if (optind == argc - 1) {
        memcpy(elf_name, argv[optind], LENGTH);
        MODE = get_elf_class(elf_name);
        if (g_long_option) {
            switch (g_long_option)
            {
                case EDIT_POINTER:
                    /* set pointer */
                    init(elf_name, &elf);
                    err = edit_pointer(&elf, off, value);
                    print_error(err);
                    finit(&elf);
                    break;

                case EDIT_CONTENT:
                    /* set content */
                    init(elf_name, &elf);
                    shellcode = calloc(size, 1);
                    err = escaped_str_to_mem(string, shellcode);
                    if (err != TRUE) {
                        free(shellcode);
                        print_error(err);
                        exit(-1);
                    }

                    err = edit_hex(&elf, off, shellcode, size);
                    print_error(err);
                    free(shellcode);
                    finit(&elf);
                    break;

                case EDIT_EXTRACT:
                    /* set contract */
                    err = extract_fragment(elf_name, off, size, NULL);
                    print_error(err);
                    break;

                case SET_INTERPRETER:
                    /* set new interpreter */
	                init(elf_name, &elf);
                    err = set_interpreter(&elf, string);
                    print_error(err);
                    finit(&elf);
                    break;
                
                case SET_RPATH:
                    /* set rpath */
	                init(elf_name, &elf);
                    err = set_rpath(&elf, string);
                    print_error(err);
                    finit(&elf);
                    break;

                case SET_RUNPATH:
                    /* set runpath */
	                init(elf_name, &elf);
                    err = set_runpath(&elf, string);
                    print_error(err);
                    finit(&elf);
                    break;

                case ADD_SEGMENT:
                    init(elf_name, &elf);
                    uint64_t index = 0;
                    if (strlen(file) == 0)
                        err = add_segment_auto(&elf, size, &index);
                    else
                        err = add_segment_with_file(&elf, PT_LOAD, file);
                    print_error(err);
                    finit(&elf);
                    break;

                case ADD_SECTION:
                    init(elf_name, &elf);
                    uint64_t index1 = 0;
                    err = add_section_auto(&elf, size, section_name, &index1);
                    print_error(err);
                    finit(&elf);
                    break;

                case REMOVE_SECTION:
                    init(elf_name, &elf);
                    err = delete_section_by_name(&elf, section_name);
                    print_error(err);
                    finit(&elf);
                    break;

                case REMOVE_SHDR:
                    init(elf_name, &elf);
                    err = delete_all_shdr(&elf);
                    print_error(err);
                    finit(&elf);
                    break;

                case REMOVE_STRIP:
                    init(elf_name, &elf);
                    err = strip(&elf);
                    print_error(err);
                    finit(&elf);
                    break;

                case INJECT_HOOK:
                    /* hook */
                    init(elf_name, &elf);
                    err = hook_extern(&elf, string, file, off);
                    print_error(err);
                    finit(&elf);
                    break;
                
                case TO_EXE2SO:
                    /* convert exe to so */
                    init(elf_name, &elf);
                    err = add_dynsym_entry(&elf, string, value, size);
                    print_error(err);
                    finit(&elf);
                    break;

                case TO_HEX2BIN:
                    /* save escapsed string to file */
                    shellcode = calloc(size, 1);
                    err = escaped_str_to_mem(string, shellcode);
                    if (err != TRUE) {
                        free(shellcode);
                        print_error(err);
                        exit(-1);
                    }

                    err = mem_to_file(elf_name, shellcode, size, 0);
                    if (err != TRUE) {
                        free(shellcode);
                        print_error(err);
                        exit(-1);
                    }
                    PRINT_INFO("shellcode has been saved to %s\n", elf_name);
                    free(shellcode);
                    break;

                case TO_BIN2ELF:
                    /* convert bin to elf */
                    /* add elf info to firmware for IDA */
                    err = add_elf_header(elf_name, arch, class, endian, base_addr);
                    if (err != TRUE) {
                        print_error(err);
                        exit(-1);
                    }
                    break;

                case TO_SCRIPT:
                    /* convert file to script */
                    bin_to_cmd(elf_name);
                    bin_to_sh(elf_name);
                    break;

                case REFRESH_HASH:
                    /* refresh gnu hash table */
                    init(elf_name, &elf);
                    err = refresh_hash_table(&elf);
                    print_error(err);
                    finit(&elf);
                    break;

                case INFECT_SILVIO:
                    /* infect using silvio */
                    g_shellcode = malloc(size + 1);
                    cmdline_shellcode(string, g_shellcode);
                    g_shellcode[size] = '\0';
                    infect_silvio(elf_name, g_shellcode, size + 1);
                    free(g_shellcode);
                    break;

                case INFECT_SKEKSI:
                    /* infect using skeksi plus */
                    g_shellcode = malloc(size + 1);
                    cmdline_shellcode(string, g_shellcode);
                    g_shellcode[size] = '\0';
                    infect_skeksi_pie(elf_name, g_shellcode, size + 1);
                    free(g_shellcode);
                    break;

                case INFECT_DATA:
                    /* infect DATA segment */
                    g_shellcode = malloc(size + 1);
                    cmdline_shellcode(string, g_shellcode);
                    g_shellcode[size] = '\0';
                    infect_data(elf_name, g_shellcode, size + 1);
                    free(g_shellcode);
                    break;
                
                default:
                    break;
            }
        }
        exit(-1);
    }

    else if (optind != argc - 2) {
        exit(-1);
    }
    /* handle additional function parameters */
    else {
        memcpy(function, argv[optind], LENGTH);
        memcpy(elf_name, argv[++optind], LENGTH);
        MODE = get_elf_class(elf_name);
    }

    /* ELF parser */
    if (!strcmp(function, "parse")) {
        parse(elf_name, &po, length);
    }

    /* edit elf */
    if (!strcmp(function, "edit")) {
        edit(elf_name, &po, row, column, value, section_name, string);
    }

    /* forensics */
    if (!strcmp(function, "checksec")) {
        checksec(elf_name);
    }
}

int main(int argc, char *argv[]) {
    main_init();
    readcmdline(argc, argv);
    return 0;
}
