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
#include "edit.h"
#include "infect.h"
#include "forensic.h"

#define VERSION "2.0.0.beta"
#define CONTENT_LENGTH 1024 * 1024
#define LENGTH 64

char section_name[MAX_PATH_LEN];
char string[ONE_PAGE];
char file[ONE_PAGE];
char config_name[ONE_PAGE];
char arch[MAX_PATH_LEN];
char endian[MAX_PATH_LEN];
char ver_elfspirt[MAX_PATH_LEN];
char elf_name[MAX_PATH_LEN];
char function[MAX_PATH_LEN];
char *shellcode;

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
    int err;

    fd = open("./VERSION", O_RDONLY);
    if (fd < 0) {
        strcpy(ver, VERSION);
        return true;
    }

    err = read(fd, ver, len);
    close(fd);
    return err>0?true:false;
}

/**
 * @description: initialize arguments
 */
static void init_main() {
    memset(section_name, 0, MAX_PATH_LEN);
    memset(string, 0, ONE_PAGE);
    memset(file, 0, ONE_PAGE);
    memset(config_name, 0, MAX_PATH_LEN);
    memset(elf_name, 0, MAX_PATH_LEN);
    memset(function, 0, MAX_PATH_LEN);
    size = 0;
    off = 0;
    err = 0;
    get_version(ver_elfspirt, LENGTH);
    po.index = 0;
    memset(po.options, 0, sizeof(po.options));
}
static void init_shellcode() {
    if (strlen(string)) {
        shellcode = calloc(size, 1);
        err = escaped_str_to_mem(string, shellcode);
        if (err != NO_ERR) {
            free(shellcode);
            print_error(err);
            exit(-1);
        }
    }
}

static const char *shortopts = "n:z:s:f:c:a:m:e:b:o:v:i:j:l:h::AHSPBDLRIG";

static const struct option longopts[] = {
    {"section-name", required_argument, NULL, 'n'},
    {"section-size", required_argument, NULL, 'z'},
    {"string", required_argument, NULL, 's'},
    {"file-name", required_argument, NULL, 'f'},
    {"architcture", required_argument, NULL, 'a'},
    {"class", required_argument, NULL, 'm'},
    {"value", required_argument, NULL, 'm'},
    {"endian", required_argument, NULL, 'e'},
    {"base", required_argument, NULL, 'b'},
    {"offset", required_argument, NULL, 'o'},
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
    "  confuse      Obfuscate ELF symbols. [--rm-section, --rm-shdr, --rm-strip]\n"
    "  infect       Infect ELF like virus. [--infect-silvio, --infect-skeksi, --infect-data, exe2so]\n"
    "  forensic     Analyze the Legitimacy of ELF File Structure. [checksec]\n"
    "Currently defined options:\n"
    "  -n, --section-name=<section name>         Set section name\n"
    "  -z, --section-size=<section size>         Set section size\n"
    "  -f, --file-name=<file name>               File containing code(e.g. so, etc.)\n"
    "  -s, --string-name=<string name>           String value\n"
    "  -m, --class=<ELF machine>                 ELF class(e.g. 32bit, 64bit, etc.)\n"
    "      --value=<math value>                  Reserve value(e.g. 7=111=rwx)\n"
    "  -a, --architecture=<ELF architecture>     ELF architecture\n"
    "  -e, --endian=<ELF endian>                 ELF endian(e.g. little, big, etc.)\n"
    "  -b, --base=<ELF base address>             ELF base address\n"
    "  -o, --offset=<injection offset>           Offset of injection point\n"
    "  -i, --row=<object index>                  Index of the object to be read or written\n"
    "  -j, --column=<vertical axis>              The vertical axis of the object to be read or written\n"
    "  -l, --length=<string length>              Display the maximum length of the string\n"
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
    "  confuse      删除节、过滤符号表、删除节头表，混淆ELF符号. [--rm-section, --rm-shdr, --rm-strip]\n"
    "  infect       ELF文件感染. [--infect-silvio, --infect-skeksi, --infect-data, exe2so]\n"
    "  forensic     分析ELF文件结构的合法性. [checksec]\n"
    "支持的选项:\n"
    "  -n, --section-name=<section name>         设置节名\n"
    "  -z, --section-size=<section size>         设置节大小\n"
    "  -f, --file-name=<file name>               包含代码的文件名称(如某个so库)\n"
    "  -s, --string-name=<string name>           传入字符串值\n"
    "  -m, --class=<ELF machine>                 设置ELF字长(32bit, 64bit)\n"
    "      --value=<math value>                  预留的参数，可以用于传递数值(e.g. 7=111=rwx)\n"
    "  -a, --architecture=<ELF architecture>     ELF文件的架构(预留选项，非必须)\n"
    "  -e, --endian=<ELF endian>                 设置ELF大小端(little, big)\n"
    "  -b, --base=<ELF base address>             设置ELF入口地址\n"
    "  -o, --offset=<injection offset>           注入点的偏移位置(预留选项，非必须)\n"
    "  -i, --row=<object index>                  待读出或者写入的对象的下标\n"
    "  -j, --column=<vertical axis>              待读出或者写入的对象的纵坐标\n"
    "  -l, --length=<string length>              解析ELF文件时，显示字符串的最大长度\n"
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
                memcpy(section_name, optarg, strlen(optarg));
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

            /***** add elf info to firmware for IDA - STRT*****/
            // set architecture
            case 'a':
                memcpy(arch, optarg, MAX_PATH_LEN);
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
                memcpy(endian, optarg, MAX_PATH_LEN);
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
    if (optind == argc - 1) {
        memcpy(elf_name, argv[optind], strlen(argv[optind]));
        init(elf_name, &elf, false);
        if (g_long_option) {
            switch (g_long_option)
            {
                case EDIT_POINTER:
                    /* set pointer */
                    err = edit_pointer(&elf, off, value);
                    print_error(err);
                    break;

                case EDIT_CONTENT:
                    /* set content */
                    init_shellcode();
                    err = edit_hex(&elf, off, shellcode, size);
                    print_error(err);
                    break;

                case SET_INTERPRETER:
                    /* set new interpreter */
                    err = set_interpreter(&elf, string);
                    print_error(err);
                    break;
                
                case SET_RPATH:
                    /* set rpath */
                    err = set_rpath(&elf, string);
                    print_error(err);
                    break;

                case SET_RUNPATH:
                    /* set runpath */
                    err = set_runpath(&elf, string);
                    print_error(err);
                    break;

                case ADD_SEGMENT:
                    uint64_t index = 0;
                    if (strlen(file) == 0)
                        err = add_segment_auto(&elf, size, &index);
                    else
                        err = add_segment_with_file(&elf, PT_LOAD, file);
                    print_error(err);
                    break;

                case ADD_SECTION:
                    uint64_t index1 = 0;
                    err = add_section_auto(&elf, size, section_name, &index1);
                    print_error(err);
                    break;

                case REMOVE_SECTION:
                    err = delete_section_by_name(&elf, section_name);
                    print_error(err);
                    break;

                case REMOVE_SHDR:
                    err = delete_all_shdr(&elf);
                    print_error(err);
                    break;

                case REMOVE_STRIP:
                    err = strip(&elf);
                    print_error(err);
                    break;

                case INJECT_HOOK:
                    /* hook */
                    err = hook_extern(&elf, string, file, off);
                    print_error(err);
                    break;
                
                case TO_EXE2SO:
                    /* convert exe to so */
                    err = add_dynsym_entry(&elf, string, value, size);
                    print_error(err);
                    break;

                case REFRESH_HASH:
                    /* refresh gnu hash table */
                    err = refresh_hash_table(&elf);
                    print_error(err);
                    break;

                case INFECT_SILVIO:
                    /* infect using silvio */
                    init_shellcode();
                    err = infect_silvio(&elf, shellcode, size);
                    print_error(err);
                    break;

                case INFECT_SKEKSI:
                    /* infect using skeksi plus */
                    init_shellcode();
                    infect_skeksi_pie(&elf, shellcode, size);
                    print_error(err);
                    break;

                case INFECT_DATA:
                    /* infect DATA segment */
                    init_shellcode();
                    err = infect_data(&elf, shellcode, size);
                    print_error(err);
                    break;
                
                default:
                    break;
            }

            finit(&elf);

            switch (g_long_option)
            {
                case EDIT_EXTRACT:
                    /* set contract */
                    err = extract_fragment(elf_name, off, size, NULL);
                    print_error(err);
                    break;

                case TO_HEX2BIN:
                    /* save escapsed string to file */
                    init_shellcode();
                    err = mem_to_file(elf_name, shellcode, size, 0);
                    if (err != NO_ERR) {
                        free(shellcode);
                        print_error(err);
                        exit(-1);
                    }
                    PRINT_INFO("shellcode has been saved to %s\n", elf_name);
                    break;

                case TO_BIN2ELF:
                    /* convert bin to elf */
                    /* add elf info to firmware for IDA */
                    err = add_elf_header(elf_name, arch, class, endian, base_addr);
                    if (err != NO_ERR) {
                        print_error(err);
                        exit(-1);
                    }
                    break;

                case TO_SCRIPT:
                    /* convert file to script */
                    bin_to_cmd(elf_name);
                    bin_to_sh(elf_name);
                    break;
                
                default:
                    break;
            }
        }
        if (shellcode) free(shellcode);
        exit(-1);
    }

    else if (optind != argc - 2) {
        exit(-1);
    }
    /* handle additional function parameters */
    else {
        memcpy(function, argv[optind], LENGTH);
        memcpy(elf_name, argv[++optind], LENGTH);
    }

    init(elf_name, &elf, true);     /* true: elf read only */
    /* ELF parser */
    if (!strcmp(function, "parse")) {
        parse(&elf, &po, length);
    }

    /* forensics */
    if (!strcmp(function, "checksec")) {
        err = checksec_t1(&elf);
    }
    finit(&elf);

    init(elf_name, &elf, false);   /* false: elf read and write */
    /* edit elf */
    if (!strcmp(function, "edit")) {
        edit(&elf, &po, row, column, value, section_name, string);
    }
    finit(&elf);
}

int main(int argc, char *argv[]) {
    init_main();
    readcmdline(argc, argv);
    return 0;
}
