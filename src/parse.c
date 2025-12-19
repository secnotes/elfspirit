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

#include <stdio.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdarg.h>
#include "parse.h"
#include "lib/manager.h"

#define UNKOWN "Unkown"

#ifdef ANDROID
#define ELF32_ST_VISIBILITY(o)	((o) & 0x03)
#define ELF64_ST_VISIBILITY(o)	ELF32_ST_VISIBILITY (o)
#endif

#define PRINT_HEADER_EXP(Nr, key, value, explain) printf ("    [%2d] %-20s %10p (%s)\n", Nr, key, value, explain)
#define PRINT_HEADER(Nr, key, value) printf ("    [%2d] %-20s %10p\n", Nr, key, value)
/* print section header table */
#define PRINT_SECTION(Nr, name, type, addr, off, size, es, flg, lk, inf, al) \
    do { \
        char truncated_name[256]; \
        strncpy(truncated_name, name, sizeof(truncated_name) - 1); \
        truncated_name[sizeof(truncated_name) - 1] = '\0'; \
        if (strlen(truncated_name) > truncated_length) { \
            strcpy(&truncated_name[truncated_length - 6], "[...]"); \
        } \
        printf("    [%2d] %-15s %-15s %08x %06x %06x %02x %4s %3u %3u %3u\n", \
            Nr, truncated_name, type, addr, off, size, es, flg, lk, inf, al); \
    } while (0)
#define PRINT_SECTION_TITLE(Nr, name, type, addr, off, size, es, flg, lk, inf, al) \
    printf("    [%2s] %-15s %-15s %8s %6s %6s %2s %4s %3s %3s %3s\n", \
    Nr, name, type, addr, off, size, es, flg, lk, inf, al)

/* print program header table*/
#define PRINT_PROGRAM(Nr, type, offset, virtaddr, physaddr, filesiz, memsiz, flg, align) \
    printf("    [%2d] %-15s %08x %08x %08x %08x %08x %-4s %5u\n", \
    Nr, type, offset, virtaddr, physaddr, filesiz, memsiz, flg, align)
#define PRINT_PROGRAM_TITLE(Nr, type, offset, virtaddr, physaddr, filesiz, memsiz, flg, align) \
    printf("    [%2s] %-15s %8s %8s %8s %8s %8s %-4s %5s\n", \
    Nr, type, offset, virtaddr, physaddr, filesiz, memsiz, flg, align)

/* print dynamic symbol table*/
#define PRINT_DYNSYM(Nr, value, size, type, bind, vis, ndx, name) \
    do { \
        char truncated_name[256]; \
        strncpy(truncated_name, name, sizeof(truncated_name) - 1); \
        truncated_name[sizeof(truncated_name) - 1] = '\0'; \
        if (strlen(truncated_name) > truncated_length) { \
            strcpy(&truncated_name[truncated_length - 6], "[...]"); \
        } \
        printf("    [%2d] %08x %4d %-8s %-8s %-8s %4d %-20s\n", \
               Nr, value, size, type, bind, vis, ndx, truncated_name); \
    } while (0)
#define PRINT_DYNSYM_TITLE(Nr, value, size, type, bind, vis, ndx, name) \
    printf("    [%2s] %8s %4s %-8s %-8s %-8s %4s %-20s\n", \
    Nr, value, size, type, bind, vis, ndx, name)

/* print dynamic table*/
#define PRINT_DYN(Nr, tag, type, value) \
    printf("    [%2d] %08x   %-15s   %-30s\n", \
    Nr, tag, type, value);
#define PRINT_DYN_TITLE(Nr, tag, type, value) \
    printf("    [%2s] %-10s   %-15s   %-30s\n", \
    Nr, tag, type, value);

/* print .rela */
#define PRINT_RELA(Nr, offset, info, type, value, name) \
    printf("    [%2d] %016x %016x %-18s %-10x %-16s\n", \
    Nr, offset, info, type, value, name);
#define PRINT_RELA_TITLE(Nr, offset, info, type, value, name) \
    printf("    [%2s] %-16s %-16s %-18s %-10s %-16s\n", \
    Nr, offset, info, type, value, name);

/* print pointer */
#define PRINT_POINTER32(Nr, value, name) \
    printf("    [%2d] %08x %-16s\n", \
    Nr, value, name);
#define PRINT_POINTER32_TITLE(Nr, value, name) \
    printf("    [%2s] %-08s %-16s\n", \
    Nr, value, name);

#define PRINT_POINTER64(Nr, value, name) \
    printf("    [%2d] %016x %-16s\n", \
    Nr, value, name);
#define PRINT_POINTER64_TITLE(Nr, value, name) \
    printf("    [%2s] %-016s %-16s\n", \
    Nr, value, name);

int flag2str(int flag, char *flag_str) {
    if (flag & 0x1)
        flag_str[2] = 'E';
    if (flag >> 1 & 0x1)
        flag_str[1] = 'W';
    if (flag >> 2 & 0x1)
        flag_str[0] = 'R';
    
    return 0;
}

int flag2str_sh(int flag, char *flag_str) {
    if (flag & 0x1)
        flag_str[2] = 'W';
    if (flag >> 1 & 0x1)
        flag_str[1] = 'A';
    if (flag >> 2 & 0x1)
        flag_str[0] = 'E';
    
    return 0;
}

/**
 * @description: Judge whether the option is true
 * @param {parser_opt_t} po
 * @param {PARSE_OPT_T} option
 * @return {*}
 */
int get_option(parser_opt_t *po, PARSE_OPT_T option){
    int i;
    for (i = 0; i < po->index; i++) {
        if (po->options[i] == option) {
            return 0;
        }
    }

    return -1;
}

uint32_t truncated_length;

/**
 * @description: ELF Header information
 * @param {handle_t32} h
 * @return {void}
 */
static void display_header32(Elf *h) {
    char *tmp;
    int nr = 0;
    PRINT_INFO("ELF32 Header\n");
    /* 16bit magic */
    printf("     0 ~ 15bit ----------------------------------------------\n");
    printf("     Magic: ");
    for (int i = 0; i < EI_NIDENT; i++) {
        printf(" %02x", h->data.elf32.ehdr->e_ident[i]);
    }    
    printf("\n");
    printf("            %3s %c  %c  %c  %c  %c  %c  %c  %c\n", "ELF", 'E', 'L', 'F', '|', '|', '|', '|', '|');
    printf("            %3s %10s  %c  %c  %c  %c\n", "   ", "32/64bit", '|', '|', '|', '|');
    printf("            %11s  %c  %c  %c\n", "little/big endian", '|', '|', '|');
    printf("            %20s  %c  %c\n", "os type", '|', '|');
    printf("            %23s  %c\n", "ABI version", '|');
    printf("            %26s\n", "byte index of padding bytes");
    printf("     16 ~ 63bit ---------------------------------------------\n");

    switch (h->data.elf32.ehdr->e_type) {
        case ET_NONE:
            tmp = "An unknown type";
            break;

        case ET_REL:
            tmp = "A relocatable file";
            break;

        case ET_EXEC:
            tmp = "An executable file";
            break;

        case ET_DYN:
            tmp = "A shared object";
            break;

        case ET_CORE:
            tmp = "A core file";
            break;
        
        default:
            tmp = UNKOWN;
            break;
    }
    PRINT_HEADER_EXP(nr++, "e_type:", h->data.elf32.ehdr->e_type, tmp);

    switch (h->data.elf32.ehdr->e_machine) {
        case EM_NONE:
            tmp = "An unknown machine";
            break;

        case EM_M32:
            tmp = "AT&T WE 32100";
            break;

        case EM_SPARC:
            tmp = "Sun Microsystems SPARC";
            break;

        case EM_386:
            tmp = "Intel 80386";
            break;

        case EM_68K:
            tmp = "Motorola 68000";
            break;
        
        case EM_88K:
            tmp = "Motorola 88000";
            break;

        case EM_860:
            tmp = "Intel 80860";
            break;

        case EM_MIPS:
            tmp = "MIPS RS3000 (big-endian only)";
            break;

        case EM_PARISC:
            tmp = "HP/PA";
            break;
        
        case EM_VPP500:
            tmp = "Fujitsu VPP500";
            break;

        case EM_SPARC32PLUS:
            tmp = "Sun's \"v8plus\"";
            break;

        case EM_960:
            tmp = "Intel 80960";
            break;
        
        case EM_PPC:
            tmp = "PowerPC";
            break;

        case EM_PPC64:
            tmp = "PowerPC 64-bit";
            break;

        case EM_S390:
            tmp = "IBM S/390";
            break;
#ifndef OHOS
        case EM_SPU:
            tmp = "IBM SPU/SPC";
            break;
#endif
        case EM_V800:
            tmp = "NEC V800 series";
            break;

        case EM_FR20:
            tmp = "Fujitsu FR20";
            break;

        case EM_RH32:
            tmp = "TRW RH-32";
            break;
       
        case EM_RCE:
            tmp = "Motorola RCE";
            break;

        case EM_ARM:
            tmp = "ARM";
            break;
#ifndef ANDROID        
        case EM_FAKE_ALPHA:
            tmp = "Digital Alpha";
            break;
#endif
        case EM_SH:
            tmp = "Hitachi SH";
            break;
        
        case EM_SPARCV9:
            tmp = "SPARC v9 64-bit";
            break;

        case EM_TRICORE:
            tmp = "Siemens Tricore";
            break;

        case EM_ARC:
            tmp = "Argonaut RISC Core";
            break;

        case EM_H8_300:
            tmp = "Hitachi H8/300";
            break;

        case EM_H8_300H:
            tmp = "Hitachi H8/300H";
            break;

        case EM_H8S:
            tmp = "Hitachi H8S";
            break;

        case EM_H8_500:
            tmp = "Hitachi H8/500";
            break;

        case EM_IA_64:
            tmp = "Intel Itanium";
            break;

        case EM_MIPS_X:
            tmp = "Stanford MIPS-X";
            break;

        case EM_COLDFIRE:
            tmp = "Motorola Coldfire";
            break;

        case EM_68HC12:
            tmp = "Motorola M68HC12";
            break;

        case EM_MMA:
            tmp = "Fujitsu MMA Multimedia Accelerator";
            break;

        case EM_PCP:
            tmp = "Siemens PCP";
            break;

        case EM_NCPU:
            tmp = "Sony nCPU embeeded RISC";
            break;

        case EM_NDR1:
            tmp = "Denso NDR1 microprocessor";
            break;
        
        case EM_STARCORE:
            tmp = "Motorola Start*Core processor";
            break;

        case EM_ME16:
            tmp = "Toyota ME16 processor";
            break;

        case EM_ST100:
            tmp = "STMicroelectronic ST100 processor";
            break;

        case EM_TINYJ:
            tmp = "Advanced Logic Corp. Tinyj emb.fam";
            break;

        case EM_X86_64:
            tmp = "AMD x86-64";
            break;

        case EM_PDSP:
            tmp = "Sony DSP Processor";
            break;
#if !defined(OHOS) && !defined(ANDROID)        
        case EM_PDP10:
            tmp = "Digital PDP-10";
            break;

        case EM_PDP11:
            tmp = "Digital PDP-11";
            break;
#endif
        case EM_FX66:
            tmp = "Siemens FX66 microcontroller";
            break;

        case EM_ST9PLUS:
            tmp = "STMicroelectronics ST9+ 8/16 mc";
            break;

        case EM_ST7:
            tmp = "STmicroelectronics ST7 8 bit mc";
            break;

        case EM_68HC16:
            tmp = "Motorola MC68HC16 microcontroller";
            break;

        case EM_68HC11:
            tmp = "Motorola MC68HC11 microcontroller";
            break;

        case EM_68HC08:
            tmp = "Motorola MC68HC08 microcontroller";
            break;

        case EM_68HC05:
            tmp = "Motorola MC68HC05 microcontroller";
            break;

        case EM_SVX:
            tmp = "Silicon Graphics SVx";
            break;

        case EM_ST19:
            tmp = "STMicroelectronics ST19 8 bit mc";
            break;

        case EM_VAX:
            tmp = "DEC Vax";
            break;
        
        case EM_CRIS:
            tmp = "Axis Communications 32-bit emb.proc";
            break;

        case EM_JAVELIN:
            tmp = "Infineon Technologies 32-bit emb.proc";
            break;

        case EM_FIREPATH:
            tmp = "Element 14 64-bit DSP Processor";
            break;

        case EM_ZSP:
            tmp = "LSI Logic 16-bit DSP Processor";
            break;

        case EM_MMIX:
            tmp = "Donald Knuth's educational 64-bit proc";
            break;

        case EM_HUANY:
            tmp = "Harvard University machine-independent object files";
            break;

        case EM_PRISM:
            tmp = "SiTera Prism";
            break;
        
        case EM_AVR:
            tmp = "Atmel AVR 8-bit microcontroller";
            break;
        
        case EM_FR30:
            tmp = "Fujitsu FR30";
            break;
        
        case EM_D10V:
            tmp = "Mitsubishi D10V";
            break;

        case EM_D30V:
            tmp = "Mitsubishi D30V";
            break;
        
        case EM_V850:
            tmp = "NEC v850";
            break;

        case EM_M32R:
            tmp = "Mitsubishi M32R";
            break;

        case EM_MN10300:
            tmp = "Matsushita MN10300";
            break;

        case EM_MN10200:
            tmp = "Matsushita MN10200";
            break;

        case EM_PJ:
            tmp = "picoJava";
            break;

        case EM_OPENRISC:
            tmp = "OpenRISC 32-bit embedded processor";
            break;
#ifndef ANDROID
        case EM_ARC_COMPACT:
            tmp = "ARC International ARCompact";
            break;
#endif
        case EM_XTENSA:
            tmp = "Tensilica Xtensa Architecture";
            break;

        case EM_VIDEOCORE:
            tmp = "Alphamosaic VideoCore";
            break;

        case EM_TMM_GPP:
            tmp = "Thompson Multimedia General Purpose Proc";
            break;

        case EM_NS32K:
            tmp = "National Semi. 32000";
            break;

        case EM_TPC:
            tmp = "Tenor Network TPC";
            break;

        case EM_SNP1K:
            tmp = "Trebia SNP 1000";
            break;

        case EM_ST200:
            tmp = "STMicroelectronics ST200";
            break;

        case EM_IP2K:
            tmp = "Ubicom IP2xxx";
            break;

        case EM_MAX:
            tmp = "MAX processor";
            break;

        case EM_CR:
            tmp = "National Semi. CompactRISC";
            break;

        case EM_F2MC16:
            tmp = "Fujitsu F2MC16";
            break;

        case EM_MSP430:
            tmp = "Texas Instruments msp430";
            break;

        case EM_BLACKFIN:
            tmp = "Analog Devices Blackfin DSP";
            break;

        case EM_SE_C33:
            tmp = "Seiko Epson S1C33 family";
            break;

        case EM_SEP:
            tmp = "Sharp embedded microprocessor";
            break;

        case EM_ARCA:
            tmp = "Arca RISC";
            break;

        case EM_UNICORE:
            tmp = "PKU-Unity & MPRC Peking Uni. mc series";
            break;
#ifndef ANDROID
        case EM_EXCESS:
            tmp = "eXcess configurable cpu";
            break;

        case EM_DXP:
            tmp = "Icera Semi. Deep Execution Processor";
            break;
#endif
        case EM_ALTERA_NIOS2:
            tmp = "Altera Nios II";
            break;
#ifndef ANDROID
        case EM_CRX:
            tmp = "National Semi. CompactRISC CRX";
            break;

        case EM_XGATE:
            tmp = " Motorola XGATE";
            break;

        case EM_C166:
            tmp = " Infineon C16x/XC16x";
            break;

        case EM_M16C:
            tmp = "Renesas M16C";
            break;

        case EM_DSPIC30F:
            tmp = "Microchip Technology dsPIC30F";
            break;

        case EM_CE:
            tmp = "Freescale Communication Engine RISC";
            break;

        case EM_M32C:
            tmp = "Renesas M32C";
            break;

        case EM_TSK3000:
            tmp = "Altium TSK3000";
            break;

        case EM_RS08:
            tmp = "Freescale RS08";
            break;

        case EM_SHARC:
            tmp = "Analog Devices SHARC family";
            break;

        case EM_ECOG2:
            tmp = "Cyan Technology eCOG2";
            break;

        case EM_SCORE7:
            tmp = "Sunplus S+core7 RISC";
            break;

        case EM_DSP24:
            tmp = "New Japan Radio (NJR) 24-bit DSP";
            break;

        case EM_VIDEOCORE3:
            tmp = "Broadcom VideoCore III";
            break;

        case EM_LATTICEMICO32:
            tmp = "RISC for Lattice FPGA";
            break;

        case EM_SE_C17:
            tmp = "Seiko Epson C17";
            break;

        case EM_TI_C6000:
            tmp = "Texas Instruments TMS320C6000 DSPP";
            break;

        case EM_TI_C2000:
            tmp = "Texas Instruments TMS320C2000 DSP";
            break;

        case EM_TI_C5500:
            tmp = "Texas Instruments TMS320C55x DSP";
            break;

        case EM_TI_ARP32:
            tmp = "Texas Instruments App. Specific RISC";
            break;

        case EM_TI_PRU:
            tmp = "Texas Instruments Prog. Realtime Unit";
            break;

        case EM_MMDSP_PLUS:
            tmp = "STMicroelectronics 64bit VLIW DSP";
            break;

        case EM_CYPRESS_M8C:
            tmp = "Cypress M8CP";
            break;

        case EM_R32C:
            tmp = "Renesas R32C";
            break;

        case EM_TRIMEDIA:
            tmp = "NXP Semi. TriMedia";
            break;

        case EM_QDSP6:
            tmp = "QUALCOMM DSP6";
            break;

        case EM_8051:
            tmp = "Intel 8051 and variants";
            break;

        case EM_STXP7X:
            tmp = "STMicroelectronics STxP7x";
            break;

        case EM_NDS32:
            tmp = "Andes Tech. compact code emb. RISC";
            break;

        case EM_ECOG1X:
            tmp = "Cyan Technology eCOG1X";
            break;

        case EM_MAXQ30:
            tmp = "Dallas Semi. MAXQ30 mc";
            break;

        case EM_XIMO16:
            tmp = "New Japan Radio (NJR) 16-bit DSP";
            break;

        case EM_MANIK:
            tmp = "M2000 Reconfigurable RISC";
            break;

        case EM_CRAYNV2:
            tmp = "Cray NV2 vector architecture";
            break;

        case EM_RX:
            tmp = "Renesas RX";
            break;

        case EM_METAG:
            tmp = "Imagination Tech. META";
            break;

        case EM_MCST_ELBRUS:
            tmp = "MCST Elbrus";
            break;

        case EM_ECOG16:
            tmp = "Cyan Technology eCOG16";
            break;

        case EM_CR16:
            tmp = "National Semi. CompactRISC CR16";
            break;

        case EM_ETPU:
            tmp = "Freescale Extended Time Processing Unit";
            break;

        case EM_SLE9X:
            tmp = "Infineon Tech. SLE9X";
            break;

        case EM_L10M:
            tmp = "Intel L10M";
            break;

        case EM_K10M:
            tmp = "Intel K10M";
            break;

        case EM_AARCH64:
            tmp = "ARM AARCH64";
            break;

        case EM_AVR32:
            tmp = "Amtel 32-bit microprocessor";
            break;

        case EM_STM8:
            tmp = "STMicroelectronics STM8";
            break;

        case EM_TILE64:
            tmp = "Tilera TILE64";
            break;

        case EM_TILEPRO:
            tmp = "Tilera TILEPro";
            break;

        case EM_MICROBLAZE:
            tmp = "Xilinx MicroBlaze";
            break;

        case EM_CUDA:
            tmp = "NVIDIA CUDA";
            break;

        case EM_TILEGX:
            tmp = "Tilera TILE-Gx";
            break;

        case EM_CLOUDSHIELD:
            tmp = "CloudShield";
            break;

        case EM_COREA_1ST:
            tmp = "KIPO-KAIST Core-A 1st gen";
            break;

        case EM_COREA_2ND:
            tmp = "KIPO-KAIST Core-A 2nd gen";
            break;
#ifndef OHOS
        case EM_ARCV2:
            tmp = "Synopsys ARCv2 ISA";
            break;
#endif
        case EM_OPEN8:
            tmp = "Open8 RISC";
            break;

        case EM_RL78:
            tmp = "Renesas RL78";
            break;

        case EM_VIDEOCORE5:
            tmp = "Broadcom VideoCore V";
            break;

        case EM_78KOR:
            tmp = "Renesas 78KOR";
            break;

        case EM_56800EX:
            tmp = "Freescale 56800EX DSC";
            break;

        case EM_BA1:
            tmp = "Beyond BA1";
            break;

        case EM_BA2:
            tmp = "Beyond BA2";
            break;

        case EM_XCORE:
            tmp = "XMOS xCORE";
            break;

        case EM_MCHP_PIC:
            tmp = "Microchip 8-bit PIC(r)";
            break;
#ifndef OHOS
        case EM_INTELGT:
            tmp = "Intel Graphics Technology";
            break;
#endif
        case EM_KM32:
            tmp = "KM211 KM32";
            break;

        case EM_KMX32:
            tmp = "KM211 KMX32";
            break;

        case EM_EMX16:
            tmp = "KM211 KMX16";
            break;

        case EM_EMX8:
            tmp = "KM211 KMX8";
            break;

        case EM_KVARC:
            tmp = "KM211 KVARC";
            break;

        case EM_CDP:
            tmp = "Paneve CD";
            break;

        case EM_COGE:
            tmp = "Cognitive Smart Memory Processor";
            break;

        case EM_COOL:
            tmp = "Bluechip CoolEngine";
            break;

        case EM_NORC:
            tmp = "Nanoradio Optimized RISC";
            break;

        case EM_CSR_KALIMBA:
            tmp = "CSR Kalimba";
            break;

        case EM_Z80:
            tmp = "Zilog Z80";
            break;

        case EM_VISIUM:
            tmp = "Controls and Data Services VISIUMcore";
            break;

        case EM_FT32:
            tmp = "FTDI Chip FT32";
            break;

        case EM_MOXIE:
            tmp = "Moxie processor";
            break;

        case EM_AMDGPU:
            tmp = "AMD GPU";
            break;
#endif
        case EM_RISCV:
            tmp = "RISC-V";
            break;

        case EM_BPF:
            tmp = "Linux BPF -- in-kernel virtual machine";
            break;

        case EM_CSKY:
            tmp = "C-SKY";
            break;

        default:
            tmp = UNKOWN;
            break;
    }
    PRINT_HEADER_EXP(nr++, "e_machine:", h->data.elf32.ehdr->e_machine, tmp);

    switch (h->data.elf32.ehdr->e_version) {
        case EV_NONE:
            tmp = "Invalid version";
            break;

        case EV_CURRENT:
            tmp = "Current version";
            break;

        default:
            tmp = UNKOWN;
            break;
    }
    PRINT_HEADER_EXP(nr++, "e_version:", h->data.elf32.ehdr->e_version, tmp);
    PRINT_HEADER_EXP(nr++, "e_entry:", h->data.elf32.ehdr->e_entry, "Entry point address");
    PRINT_HEADER_EXP(nr++, "e_phoff:", h->data.elf32.ehdr->e_phoff, "Start of program headers");
    PRINT_HEADER_EXP(nr++, "e_shoff:", h->data.elf32.ehdr->e_shoff, "Start of section headers");
    PRINT_HEADER(nr++, "e_flags:", h->data.elf32.ehdr->e_flags);
    PRINT_HEADER_EXP(nr++, "e_ehsize:", h->data.elf32.ehdr->e_ehsize, "Size of this header");
    PRINT_HEADER_EXP(nr++, "e_phentsize:", h->data.elf32.ehdr->e_phentsize, "Size of program headers");
    PRINT_HEADER_EXP(nr++, "e_phnum:", h->data.elf32.ehdr->e_phnum, "Number of program headers");
    PRINT_HEADER_EXP(nr++, "e_shentsize:", h->data.elf32.ehdr->e_shentsize, "Size of section headers");
    PRINT_HEADER_EXP(nr++, "e_shnum:", h->data.elf32.ehdr->e_shnum, "Number of section headers");
    PRINT_HEADER_EXP(nr++, "e_shstrndx:", h->data.elf32.ehdr->e_shstrndx, "Section header string table index");
}

static void display_header64(Elf *h) {
    char *tmp;
    int nr = 0;
    PRINT_INFO("ELF64 Header\n");
    /* 16bit magic */
    printf("     0 ~ 15bit ----------------------------------------------\n");
    printf("     Magic: ");
    for (int i = 0; i < EI_NIDENT; i++) {
        printf(" %02x", h->data.elf64.ehdr->e_ident[i]);
    }   
    printf("\n");
    printf("            %3s %c  %c  %c  %c  %c  %c  %c  %c\n", "ELF", 'E', 'L', 'F', '|', '|', '|', '|', '|');
    printf("            %3s %10s  %c  %c  %c  %c\n", "   ", "32/64bit", '|', '|', '|', '|');
    printf("            %11s  %c  %c  %c\n", "little/big endian", '|', '|', '|');
    printf("            %20s  %c  %c\n", "os type", '|', '|');
    printf("            %23s  %c\n", "ABI version", '|');
    printf("            %26s\n", "byte index of padding bytes");
    printf("     16 ~ 63bit ---------------------------------------------\n");

    switch (h->data.elf64.ehdr->e_type) {
        case ET_NONE:
            tmp = "An unknown type";
            break;

        case ET_REL:
            tmp = "A relocatable file";
            break;

        case ET_EXEC:
            tmp = "An executable file";
            break;

        case ET_DYN:
            tmp = "A shared object";
            break;

        case ET_CORE:
            tmp = "A core file";
            break;
        
        default:
            tmp = UNKOWN;
            break;
    }
    PRINT_HEADER_EXP(nr++, "e_type:", h->data.elf64.ehdr->e_type, tmp);

    switch (h->data.elf64.ehdr->e_machine) {
        case EM_NONE:
            tmp = "An unknown machine";
            break;

        case EM_M32:
            tmp = "AT&T WE 32100";
            break;

        case EM_SPARC:
            tmp = "Sun Microsystems SPARC";
            break;

        case EM_386:
            tmp = "Intel 80386";
            break;

        case EM_68K:
            tmp = "Motorola 68000";
            break;
        
        case EM_88K:
            tmp = "Motorola 88000";
            break;

        case EM_860:
            tmp = "Intel 80860";
            break;

        case EM_MIPS:
            tmp = "MIPS RS3000 (big-endian only)";
            break;

        case EM_PARISC:
            tmp = "HP/PA";
            break;
        
        case EM_VPP500:
            tmp = "Fujitsu VPP500";
            break;

        case EM_SPARC32PLUS:
            tmp = "Sun's \"v8plus\"";
            break;

        case EM_960:
            tmp = "Intel 80960";
            break;
        
        case EM_PPC:
            tmp = "PowerPC";
            break;

        case EM_PPC64:
            tmp = "PowerPC 64-bit";
            break;

        case EM_S390:
            tmp = "IBM S/390";
            break;
#ifndef OHOS
        case EM_SPU:
            tmp = "IBM SPU/SPC";
            break;
#endif        
        case EM_V800:
            tmp = "NEC V800 series";
            break;

        case EM_FR20:
            tmp = "Fujitsu FR20";
            break;

        case EM_RH32:
            tmp = "TRW RH-32";
            break;
       
        case EM_RCE:
            tmp = "Motorola RCE";
            break;

        case EM_ARM:
            tmp = "ARM";
            break;
#ifndef ANDROID        
        case EM_FAKE_ALPHA:
            tmp = "Digital Alpha";
            break;
#endif
        case EM_SH:
            tmp = "Hitachi SH";
            break;
        
        case EM_SPARCV9:
            tmp = "SPARC v9 64-bit";
            break;

        case EM_TRICORE:
            tmp = "Siemens Tricore";
            break;

        case EM_ARC:
            tmp = "Argonaut RISC Core";
            break;

        case EM_H8_300:
            tmp = "Hitachi H8/300";
            break;

        case EM_H8_300H:
            tmp = "Hitachi H8/300H";
            break;

        case EM_H8S:
            tmp = "Hitachi H8S";
            break;

        case EM_H8_500:
            tmp = "Hitachi H8/500";
            break;

        case EM_IA_64:
            tmp = "Intel Itanium";
            break;

        case EM_MIPS_X:
            tmp = "Stanford MIPS-X";
            break;

        case EM_COLDFIRE:
            tmp = "Motorola Coldfire";
            break;

        case EM_68HC12:
            tmp = "Motorola M68HC12";
            break;

        case EM_MMA:
            tmp = "Fujitsu MMA Multimedia Accelerator";
            break;

        case EM_PCP:
            tmp = "Siemens PCP";
            break;

        case EM_NCPU:
            tmp = "Sony nCPU embeeded RISC";
            break;

        case EM_NDR1:
            tmp = "Denso NDR1 microprocessor";
            break;
        
        case EM_STARCORE:
            tmp = "Motorola Start*Core processor";
            break;

        case EM_ME16:
            tmp = "Toyota ME16 processor";
            break;

        case EM_ST100:
            tmp = "STMicroelectronic ST100 processor";
            break;

        case EM_TINYJ:
            tmp = "Advanced Logic Corp. Tinyj emb.fam";
            break;

        case EM_X86_64:
            tmp = "AMD x86-64";
            break;

        case EM_PDSP:
            tmp = "Sony DSP Processor";
            break;
#if !defined(OHOS) && !defined(ANDROID)        
        case EM_PDP10:
            tmp = "Digital PDP-10";
            break;

        case EM_PDP11:
            tmp = "Digital PDP-11";
            break;
#endif
        case EM_FX66:
            tmp = "Siemens FX66 microcontroller";
            break;

        case EM_ST9PLUS:
            tmp = "STMicroelectronics ST9+ 8/16 mc";
            break;

        case EM_ST7:
            tmp = "STmicroelectronics ST7 8 bit mc";
            break;

        case EM_68HC16:
            tmp = "Motorola MC68HC16 microcontroller";
            break;

        case EM_68HC11:
            tmp = "Motorola MC68HC11 microcontroller";
            break;

        case EM_68HC08:
            tmp = "Motorola MC68HC08 microcontroller";
            break;

        case EM_68HC05:
            tmp = "Motorola MC68HC05 microcontroller";
            break;

        case EM_SVX:
            tmp = "Silicon Graphics SVx";
            break;

        case EM_ST19:
            tmp = "STMicroelectronics ST19 8 bit mc";
            break;

        case EM_VAX:
            tmp = "DEC Vax";
            break;
        
        case EM_CRIS:
            tmp = "Axis Communications 32-bit emb.proc";
            break;

        case EM_JAVELIN:
            tmp = "Infineon Technologies 32-bit emb.proc";
            break;

        case EM_FIREPATH:
            tmp = "Element 14 64-bit DSP Processor";
            break;

        case EM_ZSP:
            tmp = "LSI Logic 16-bit DSP Processor";
            break;

        case EM_MMIX:
            tmp = "Donald Knuth's educational 64-bit proc";
            break;

        case EM_HUANY:
            tmp = "Harvard University machine-independent object files";
            break;

        case EM_PRISM:
            tmp = "SiTera Prism";
            break;
        
        case EM_AVR:
            tmp = "Atmel AVR 8-bit microcontroller";
            break;
        
        case EM_FR30:
            tmp = "Fujitsu FR30";
            break;
        
        case EM_D10V:
            tmp = "Mitsubishi D10V";
            break;

        case EM_D30V:
            tmp = "Mitsubishi D30V";
            break;
        
        case EM_V850:
            tmp = "NEC v850";
            break;

        case EM_M32R:
            tmp = "Mitsubishi M32R";
            break;

        case EM_MN10300:
            tmp = "Matsushita MN10300";
            break;

        case EM_MN10200:
            tmp = "Matsushita MN10200";
            break;

        case EM_PJ:
            tmp = "picoJava";
            break;

        case EM_OPENRISC:
            tmp = "OpenRISC 32-bit embedded processor";
            break;
#ifndef ANDROID
        case EM_ARC_COMPACT:
            tmp = "ARC International ARCompact";
            break;
#endif
        case EM_XTENSA:
            tmp = "Tensilica Xtensa Architecture";
            break;

        case EM_VIDEOCORE:
            tmp = "Alphamosaic VideoCore";
            break;

        case EM_TMM_GPP:
            tmp = "Thompson Multimedia General Purpose Proc";
            break;

        case EM_NS32K:
            tmp = "National Semi. 32000";
            break;

        case EM_TPC:
            tmp = "Tenor Network TPC";
            break;

        case EM_SNP1K:
            tmp = "Trebia SNP 1000";
            break;

        case EM_ST200:
            tmp = "STMicroelectronics ST200";
            break;

        case EM_IP2K:
            tmp = "Ubicom IP2xxx";
            break;

        case EM_MAX:
            tmp = "MAX processor";
            break;

        case EM_CR:
            tmp = "National Semi. CompactRISC";
            break;

        case EM_F2MC16:
            tmp = "Fujitsu F2MC16";
            break;

        case EM_MSP430:
            tmp = "Texas Instruments msp430";
            break;

        case EM_BLACKFIN:
            tmp = "Analog Devices Blackfin DSP";
            break;

        case EM_SE_C33:
            tmp = "Seiko Epson S1C33 family";
            break;

        case EM_SEP:
            tmp = "Sharp embedded microprocessor";
            break;

        case EM_ARCA:
            tmp = "Arca RISC";
            break;

        case EM_UNICORE:
            tmp = "PKU-Unity & MPRC Peking Uni. mc series";
            break;
#ifndef ANDROID
        case EM_EXCESS:
            tmp = "eXcess configurable cpu";
            break;

        case EM_DXP:
            tmp = "Icera Semi. Deep Execution Processor";
            break;
#endif
        case EM_ALTERA_NIOS2:
            tmp = "Altera Nios II";
            break;
#ifndef ANDROID
        case EM_CRX:
            tmp = "National Semi. CompactRISC CRX";
            break;

        case EM_XGATE:
            tmp = " Motorola XGATE";
            break;

        case EM_C166:
            tmp = " Infineon C16x/XC16x";
            break;

        case EM_M16C:
            tmp = "Renesas M16C";
            break;

        case EM_DSPIC30F:
            tmp = "Microchip Technology dsPIC30F";
            break;

        case EM_CE:
            tmp = "Freescale Communication Engine RISC";
            break;

        case EM_M32C:
            tmp = "Renesas M32C";
            break;

        case EM_TSK3000:
            tmp = "Altium TSK3000";
            break;

        case EM_RS08:
            tmp = "Freescale RS08";
            break;

        case EM_SHARC:
            tmp = "Analog Devices SHARC family";
            break;

        case EM_ECOG2:
            tmp = "Cyan Technology eCOG2";
            break;

        case EM_SCORE7:
            tmp = "Sunplus S+core7 RISC";
            break;

        case EM_DSP24:
            tmp = "New Japan Radio (NJR) 24-bit DSP";
            break;

        case EM_VIDEOCORE3:
            tmp = "Broadcom VideoCore III";
            break;

        case EM_LATTICEMICO32:
            tmp = "RISC for Lattice FPGA";
            break;

        case EM_SE_C17:
            tmp = "Seiko Epson C17";
            break;

        case EM_TI_C6000:
            tmp = "Texas Instruments TMS320C6000 DSPP";
            break;

        case EM_TI_C2000:
            tmp = "Texas Instruments TMS320C2000 DSP";
            break;

        case EM_TI_C5500:
            tmp = "Texas Instruments TMS320C55x DSP";
            break;

        case EM_TI_ARP32:
            tmp = "Texas Instruments App. Specific RISC";
            break;

        case EM_TI_PRU:
            tmp = "Texas Instruments Prog. Realtime Unit";
            break;

        case EM_MMDSP_PLUS:
            tmp = "STMicroelectronics 64bit VLIW DSP";
            break;

        case EM_CYPRESS_M8C:
            tmp = "Cypress M8CP";
            break;

        case EM_R32C:
            tmp = "Renesas R32C";
            break;

        case EM_TRIMEDIA:
            tmp = "NXP Semi. TriMedia";
            break;

        case EM_QDSP6:
            tmp = "QUALCOMM DSP6";
            break;

        case EM_8051:
            tmp = "Intel 8051 and variants";
            break;

        case EM_STXP7X:
            tmp = "STMicroelectronics STxP7x";
            break;

        case EM_NDS32:
            tmp = "Andes Tech. compact code emb. RISC";
            break;

        case EM_ECOG1X:
            tmp = "Cyan Technology eCOG1X";
            break;

        case EM_MAXQ30:
            tmp = "Dallas Semi. MAXQ30 mc";
            break;

        case EM_XIMO16:
            tmp = "New Japan Radio (NJR) 16-bit DSP";
            break;

        case EM_MANIK:
            tmp = "M2000 Reconfigurable RISC";
            break;

        case EM_CRAYNV2:
            tmp = "Cray NV2 vector architecture";
            break;

        case EM_RX:
            tmp = "Renesas RX";
            break;

        case EM_METAG:
            tmp = "Imagination Tech. META";
            break;

        case EM_MCST_ELBRUS:
            tmp = "MCST Elbrus";
            break;

        case EM_ECOG16:
            tmp = "Cyan Technology eCOG16";
            break;

        case EM_CR16:
            tmp = "National Semi. CompactRISC CR16";
            break;

        case EM_ETPU:
            tmp = "Freescale Extended Time Processing Unit";
            break;

        case EM_SLE9X:
            tmp = "Infineon Tech. SLE9X";
            break;

        case EM_L10M:
            tmp = "Intel L10M";
            break;

        case EM_K10M:
            tmp = "Intel K10M";
            break;

        case EM_AARCH64:
            tmp = "ARM AARCH64";
            break;

        case EM_AVR32:
            tmp = "Amtel 32-bit microprocessor";
            break;

        case EM_STM8:
            tmp = "STMicroelectronics STM8";
            break;

        case EM_TILE64:
            tmp = "Tilera TILE64";
            break;

        case EM_TILEPRO:
            tmp = "Tilera TILEPro";
            break;

        case EM_MICROBLAZE:
            tmp = "Xilinx MicroBlaze";
            break;

        case EM_CUDA:
            tmp = "NVIDIA CUDA";
            break;

        case EM_TILEGX:
            tmp = "Tilera TILE-Gx";
            break;

        case EM_CLOUDSHIELD:
            tmp = "CloudShield";
            break;

        case EM_COREA_1ST:
            tmp = "KIPO-KAIST Core-A 1st gen";
            break;

        case EM_COREA_2ND:
            tmp = "KIPO-KAIST Core-A 2nd gen";
            break;
#ifndef OHOS
        case EM_ARCV2:
            tmp = "Synopsys ARCv2 ISA";
            break;
#endif
        case EM_OPEN8:
            tmp = "Open8 RISC";
            break;

        case EM_RL78:
            tmp = "Renesas RL78";
            break;

        case EM_VIDEOCORE5:
            tmp = "Broadcom VideoCore V";
            break;

        case EM_78KOR:
            tmp = "Renesas 78KOR";
            break;

        case EM_56800EX:
            tmp = "Freescale 56800EX DSC";
            break;

        case EM_BA1:
            tmp = "Beyond BA1";
            break;

        case EM_BA2:
            tmp = "Beyond BA2";
            break;

        case EM_XCORE:
            tmp = "XMOS xCORE";
            break;

        case EM_MCHP_PIC:
            tmp = "Microchip 8-bit PIC(r)";
            break;
#ifndef OHOS
        case EM_INTELGT:
            tmp = "Intel Graphics Technology";
            break;
#endif
        case EM_KM32:
            tmp = "KM211 KM32";
            break;

        case EM_KMX32:
            tmp = "KM211 KMX32";
            break;

        case EM_EMX16:
            tmp = "KM211 KMX16";
            break;

        case EM_EMX8:
            tmp = "KM211 KMX8";
            break;

        case EM_KVARC:
            tmp = "KM211 KVARC";
            break;

        case EM_CDP:
            tmp = "Paneve CD";
            break;

        case EM_COGE:
            tmp = "Cognitive Smart Memory Processor";
            break;

        case EM_COOL:
            tmp = "Bluechip CoolEngine";
            break;

        case EM_NORC:
            tmp = "Nanoradio Optimized RISC";
            break;

        case EM_CSR_KALIMBA:
            tmp = "CSR Kalimba";
            break;

        case EM_Z80:
            tmp = "Zilog Z80";
            break;

        case EM_VISIUM:
            tmp = "Controls and Data Services VISIUMcore";
            break;

        case EM_FT32:
            tmp = "FTDI Chip FT32";
            break;

        case EM_MOXIE:
            tmp = "Moxie processor";
            break;

        case EM_AMDGPU:
            tmp = "AMD GPU";
            break;

        case EM_RISCV:
            tmp = "RISC-V";
            break;

        case EM_BPF:
            tmp = "Linux BPF -- in-kernel virtual machine";
            break;

        case EM_CSKY:
            tmp = "C-SKY";
            break;
#endif
        default:
            tmp = UNKOWN;
            break;
    }
    PRINT_HEADER_EXP(nr++, "e_machine:", h->data.elf64.ehdr->e_machine, tmp);

    switch (h->data.elf64.ehdr->e_version) {
        case EV_NONE:
            tmp = "Invalid version";
            break;

        case EV_CURRENT:
            tmp = "Current version";
            break;

        default:
            tmp = UNKOWN;
            break;
    }
    PRINT_HEADER_EXP(nr++, "e_version:", h->data.elf64.ehdr->e_version, tmp);
    PRINT_HEADER_EXP(nr++, "e_entry:", h->data.elf64.ehdr->e_entry, "Entry point address");
    PRINT_HEADER_EXP(nr++, "e_phoff:", h->data.elf64.ehdr->e_phoff, "Start of program headers");
    PRINT_HEADER_EXP(nr++, "e_shoff:", h->data.elf64.ehdr->e_shoff, "Start of section headers");
    PRINT_HEADER(nr++, "e_flags:", h->data.elf64.ehdr->e_flags);
    PRINT_HEADER_EXP(nr++, "e_ehsize:", h->data.elf64.ehdr->e_ehsize, "Size of this header");
    PRINT_HEADER_EXP(nr++, "e_phentsize:", h->data.elf64.ehdr->e_phentsize, "Size of program headers");
    PRINT_HEADER_EXP(nr++, "e_phnum:", h->data.elf64.ehdr->e_phnum, "Number of program headers");
    PRINT_HEADER_EXP(nr++, "e_shentsize:", h->data.elf64.ehdr->e_shentsize, "Size of section headers");
    PRINT_HEADER_EXP(nr++, "e_shnum:", h->data.elf64.ehdr->e_shnum, "Number of section headers");
    PRINT_HEADER_EXP(nr++, "e_shstrndx:", h->data.elf64.ehdr->e_shstrndx, "Section header string table index");
}

/**
 * @description: Section information
 * @param {handle_t32} h
 * @return {void}
 */
static void display_section32(Elf *elf) {
    char *name;
    char *tmp;
    char flag[4];
    PRINT_INFO("Section Header Table\n");
    PRINT_SECTION_TITLE("Nr", "Name", "Type", "Addr", "Off", "Size", "Es", "Flg", "Lk", "Inf", "Al");

    for (int i = 0; i < elf->data.elf32.ehdr->e_shnum; i++) {
        name = elf->mem + elf->data.elf32.shstrtab->sh_offset + elf->data.elf32.shdr[i].sh_name;
        if (validated_offset((uintptr_t)name, (uintptr_t)elf->mem, (uintptr_t)elf->mem + elf->size)) {
            PRINT_ERROR("Corrupt file format\n");
            exit(-1);
        }

        switch (elf->data.elf32.shdr[i].sh_type) {
            case SHT_NULL:
                tmp = "SHT_NULL";
                break;
            
            case SHT_PROGBITS:
                tmp = "SHT_PROGBITS";
                break;

            case SHT_SYMTAB:
                tmp = "SHT_SYMTAB";
                break;

            case SHT_STRTAB:
                tmp = "SHT_STRTAB";
                break;

            case SHT_RELA:
                tmp = "SHT_RELA";
                break;

            case SHT_HASH:
                tmp = "SHT_HASH";
                break;

            case SHT_DYNAMIC:
                tmp = "SHT_DYNAMIC";
                break;

            case SHT_NOTE:
                tmp = "SHT_NOTE";
                break;

            case SHT_NOBITS:
                tmp = "SHT_NOBITS";
                break;

            case SHT_REL:
                tmp = "SHT_REL";
                break;

            case SHT_SHLIB:
                tmp = "SHT_SHLIB";
                break;

            case SHT_DYNSYM:
                tmp = "SHT_DYNSYM";
                break;

            case SHT_LOPROC:
                tmp = "SHT_LOPROC";
                break;

            case SHT_HIPROC:
                tmp = "SHT_HIPROC";
                break;

            case SHT_LOUSER:
                tmp = "SHT_LOUSER";
                break;

            case SHT_HIUSER:
                tmp = "SHT_HIUSER";
                break;
            
            default:
                tmp = UNKOWN;
                break;
        }

        strcpy(flag, "   ");
        flag2str_sh(elf->data.elf32.shdr[i].sh_flags, flag);
        PRINT_SECTION(i, name, tmp, elf->data.elf32.shdr[i].sh_addr, elf->data.elf32.shdr[i].sh_offset, elf->data.elf32.shdr[i].sh_size, elf->data.elf32.shdr[i].sh_entsize, \
                        flag, elf->data.elf32.shdr[i].sh_link, elf->data.elf32.shdr[i].sh_info, elf->data.elf32.shdr[i].sh_addralign);
    }
}

static void display_section64(Elf *elf) {
    char *name;
    char *tmp;
    char flag[4];
    PRINT_INFO("Section Header Table\n");
    PRINT_SECTION_TITLE("Nr", "Name", "Type", "Addr", "Off", "Size", "Es", "Flg", "Lk", "Inf", "Al");
    
    for (int i = 0; i < elf->data.elf64.ehdr->e_shnum; i++) {
        name = elf->mem + elf->data.elf64.shstrtab->sh_offset + elf->data.elf64.shdr[i].sh_name;
        if (validated_offset((uintptr_t)name, (uintptr_t)elf->mem, (uintptr_t)elf->mem + elf->size)) {
            PRINT_ERROR("Corrupt file format\n");
            exit(-1);
        }

        switch (elf->data.elf64.shdr[i].sh_type) {
            case SHT_NULL:
                tmp = "SHT_NULL";
                break;
            
            case SHT_PROGBITS:
                tmp = "SHT_PROGBITS";
                break;

            case SHT_SYMTAB:
                tmp = "SHT_SYMTAB";
                break;

            case SHT_STRTAB:
                tmp = "SHT_STRTAB";
                break;

            case SHT_RELA:
                tmp = "SHT_RELA";
                break;

            case SHT_HASH:
                tmp = "SHT_HASH";
                break;

            case SHT_DYNAMIC:
                tmp = "SHT_DYNAMIC";
                break;

            case SHT_NOTE:
                tmp = "SHT_NOTE";
                break;

            case SHT_NOBITS:
                tmp = "SHT_NOBITS";
                break;

            case SHT_REL:
                tmp = "SHT_REL";
                break;

            case SHT_SHLIB:
                tmp = "SHT_SHLIB";
                break;

            case SHT_DYNSYM:
                tmp = "SHT_DYNSYM";
                break;

            case SHT_LOPROC:
                tmp = "SHT_LOPROC";
                break;

            case SHT_HIPROC:
                tmp = "SHT_HIPROC";
                break;

            case SHT_LOUSER:
                tmp = "SHT_LOUSER";
                break;

            case SHT_HIUSER:
                tmp = "SHT_HIUSER";
                break;
            
            default:
                tmp = UNKOWN;
                break;
        }

        strcpy(flag, "   ");
        flag2str_sh(elf->data.elf64.shdr[i].sh_flags, flag);
        PRINT_SECTION(i, name, tmp, elf->data.elf64.shdr[i].sh_addr, elf->data.elf64.shdr[i].sh_offset, elf->data.elf64.shdr[i].sh_size, elf->data.elf64.shdr[i].sh_entsize, \
                        flag, elf->data.elf64.shdr[i].sh_link, elf->data.elf64.shdr[i].sh_info, elf->data.elf64.shdr[i].sh_addralign);
    }
}

/**
 * @description: Segmentation information
 * @param {handle_t32} h
 * @return {void}
 */
void display_segment32(Elf *elf) {
    char *name;
    char *tmp;
    char flag[4];
    PRINT_INFO("Program Header Table\n");
    PRINT_PROGRAM_TITLE("Nr", "Type", "Offset", "Virtaddr", "Physaddr", "Filesiz", "Memsiz", "Flg", "Align");

    for (int i = 0; i < elf->data.elf32.ehdr->e_phnum; i++) {
        switch (elf->data.elf32.phdr[i].p_type) {
            case PT_NULL:
                tmp = "PT_NULL";
                break;
            
            case PT_LOAD:
                tmp = "PT_LOAD";
                break;

            case PT_DYNAMIC:
                tmp = "PT_DYNAMIC";
                break;

            case PT_INTERP:
                tmp = "PT_INTERP";
                printf("\t\t[Requesting program interpreter: %s]\n", elf->mem + elf->data.elf32.phdr[i].p_offset);
                break;

            case PT_NOTE:
                tmp = "PT_NOTE";
                break;

            case PT_SHLIB:
                tmp = "PT_SHLIB";
                break;

            case PT_PHDR:
                tmp = "PT_PHDR";
                break;

            case PT_TLS:
                tmp = "PT_TLS";
                break;

            case PT_NUM:
                tmp = "PT_NUM";
                break;

            case PT_LOOS:
                tmp = "PT_LOOS";
                break;

            case PT_GNU_EH_FRAME:
                tmp = "PT_GNU_EH_FRAME";
                break;
            
            case PT_GNU_STACK:
                tmp = "PT_GNU_STACK";
                break;

            case PT_GNU_RELRO:
                tmp = "PT_GNU_RELRO";
                break;
#ifndef OHOS
            case PT_GNU_PROPERTY:
                tmp = "PT_GNU_PROPERTY";
                break;

            case PT_GNU_SFRAME:
                tmp = "PT_GNU_SFRAME";
                break;
#endif
            case PT_LOSUNW:
                tmp = "PT_LOSUNW";
                break;

            // case PT_SUNWBSS:
            //     tmp = "PT_SUNWBSS";
            //     break;

            case PT_SUNWSTACK:
                tmp = "PT_SUNWSTACK";
                break;

            case PT_HISUNW:
                tmp = "PT_HISUNW";
                break;

            // case PT_HIOS:
            //     tmp = "PT_HIOS";
            //     break;

            case PT_LOPROC:
                tmp = "PT_LOPROC";
                break;

            case PT_HIPROC:
                tmp = "PT_HIPROC";
                break;
            
            default:
                tmp = UNKOWN;
                break;
        }
        strcpy(flag, "   ");
        flag2str(elf->data.elf32.phdr[i].p_flags, flag);
        PRINT_PROGRAM(i, tmp, elf->data.elf32.phdr[i].p_offset, elf->data.elf32.phdr[i].p_vaddr, elf->data.elf32.phdr[i].p_paddr, elf->data.elf32.phdr[i].p_filesz, elf->data.elf32.phdr[i].p_memsz, flag, elf->data.elf32.phdr[i].p_align); 
    }


    PRINT_INFO("Section to segment mapping\n");
    Set *set = create_set();
    for (int i = 0; i < elf->data.elf32.ehdr->e_phnum; i++) {
        printf("    [%2d]", i);
        for (int j = 0; j < elf->data.elf32.ehdr->e_shnum; j++) {
            name = elf->mem + elf->data.elf32.shstrtab->sh_offset + elf->data.elf32.shdr[j].sh_name;
            if (elf->data.elf32.shdr[j].sh_addr >= elf->data.elf32.phdr[i].p_vaddr && elf->data.elf32.shdr[j].sh_addr + elf->data.elf32.shdr[j].sh_size <= elf->data.elf32.phdr[i].p_vaddr + elf->data.elf32.phdr[i].p_memsz && elf->data.elf32.shdr[j].sh_type != SHT_NULL) {
                if (elf->data.elf32.shdr[j].sh_flags >> 1 & 0x1) {
                    if (name != NULL) {
                        add_element(set, j);
                        printf(" %s", name);
                    }                    
                }
            }    
        }
        printf("\n");
    }

    PRINT_INFO("Unmapped sections\n");
    printf("   ");
    for (int j = 0; j < elf->data.elf32.ehdr->e_shnum; j++) {
        name = elf->mem + elf->data.elf32.shstrtab->sh_offset + elf->data.elf32.shdr[j].sh_name;
        if (contains_element(set, j) == false) {
            printf(" [%d]%s", j, name);
        }
    }

    printf("\n");
    free_set(set);
}

void display_segment64(Elf *elf) {
    char *name;
    char *tmp;
    char flag[4];
    PRINT_INFO("Program Header Table\n");
    PRINT_PROGRAM_TITLE("Nr", "Type", "Offset", "Virtaddr", "Physaddr", "Filesiz", "Memsiz", "Flg", "Align");

    for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
        switch (elf->data.elf64.phdr[i].p_type) {
            case PT_NULL:
                tmp = "PT_NULL";
                break;
            
            case PT_LOAD:
                tmp = "PT_LOAD";
                break;

            case PT_DYNAMIC:
                tmp = "PT_DYNAMIC";
                break;

            case PT_INTERP:
                tmp = "PT_INTERP";
                printf("\t\t[Requesting program interpreter: %s]\n", elf->mem + elf->data.elf64.phdr[i].p_offset);
                break;

            case PT_NOTE:
                tmp = "PT_NOTE";
                break;

            case PT_SHLIB:
                tmp = "PT_SHLIB";
                break;

            case PT_PHDR:
                tmp = "PT_PHDR";
                break;

            case PT_TLS:
                tmp = "PT_TLS";
                break;

            case PT_NUM:
                tmp = "PT_NUM";
                break;

            case PT_LOOS:
                tmp = "PT_LOOS";
                break;

            case PT_GNU_EH_FRAME:
                tmp = "PT_GNU_EH_FRAME";
                break;
            
            case PT_GNU_STACK:
                tmp = "PT_GNU_STACK";
                break;

            case PT_GNU_RELRO:
                tmp = "PT_GNU_RELRO";
                break;
#ifndef OHOS
            case PT_GNU_PROPERTY:
                tmp = "PT_GNU_PROPERTY";
                break;

            case PT_GNU_SFRAME:
                tmp = "PT_GNU_SFRAME";
                break;
#endif
            case PT_LOSUNW:
                tmp = "PT_LOSUNW";
                break;

            // case PT_SUNWBSS:
            //     tmp = "PT_SUNWBSS";
            //     break;

            case PT_SUNWSTACK:
                tmp = "PT_SUNWSTACK";
                break;

            case PT_HISUNW:
                tmp = "PT_HISUNW";
                break;

            // case PT_HIOS:
            //     tmp = "PT_HIOS";
            //     break;

            case PT_LOPROC:
                tmp = "PT_LOPROC";
                break;

            case PT_HIPROC:
                tmp = "PT_HIPROC";
                break;
            
            default:
                tmp = UNKOWN;
                break;
        }
        strcpy(flag, "   ");
        flag2str(elf->data.elf64.phdr[i].p_flags, flag);
        PRINT_PROGRAM(i, tmp, elf->data.elf64.phdr[i].p_offset, elf->data.elf64.phdr[i].p_vaddr, elf->data.elf64.phdr[i].p_paddr, elf->data.elf64.phdr[i].p_filesz, elf->data.elf64.phdr[i].p_memsz, flag, elf->data.elf64.phdr[i].p_align); 
    }

    PRINT_INFO("Section to segment mapping\n");
    Set *set = create_set();
    for (int i = 0; i < elf->data.elf64.ehdr->e_phnum; i++) {
        printf("    [%2d]", i);
        for (int j = 0; j < elf->data.elf64.ehdr->e_shnum; j++) {
            name = elf->mem + elf->data.elf64.shstrtab->sh_offset + elf->data.elf64.shdr[j].sh_name;
            if (elf->data.elf64.shdr[j].sh_addr >= elf->data.elf64.phdr[i].p_vaddr && elf->data.elf64.shdr[j].sh_addr + elf->data.elf64.shdr[j].sh_size <= elf->data.elf64.phdr[i].p_vaddr + elf->data.elf64.phdr[i].p_memsz && elf->data.elf64.shdr[j].sh_type != SHT_NULL) {
                if (elf->data.elf64.shdr[j].sh_flags >> 1 & 0x1) {
                    if (name != NULL) {
                        add_element(set, j);
                        printf(" %s", name);
                    }                    
                }
            }    
        }
        printf("\n");
    }

    PRINT_INFO("Unmapped sections\n");
    printf("   ");
    for (int j = 0; j < elf->data.elf64.ehdr->e_shnum; j++) {
        name = elf->mem + elf->data.elf64.shstrtab->sh_offset + elf->data.elf64.shdr[j].sh_name;
        if (contains_element(set, j) == false) {
            printf(" [%d]%s", j, name);
        }
    }

    printf("\n");
    free_set(set);
}

/**
 * @description: .dynsym information
 * @param {handle_t32} h
 * @return int error code {-1:error,0:sucess}
 */
static int display_dynsym32(Elf *elf, char *section_name, char *str_tab) {
    char *name = NULL;
    char *type;
    char *bind;
    char *other;
    // The following variables must be initialized 
    // because they need to be used to determine whether sections exist or not.
    // 以下些变量必须初始化，因为要根据他们判节是否存在
    int str_index = 0;
    int sym_index = 0;
    size_t count;
    Elf32_Sym *sym;

    for (int i = 0; i < elf->data.elf32.ehdr->e_shnum; i++) {
        name = elf->mem + elf->data.elf32.shstrtab->sh_offset + elf->data.elf32.shdr[i].sh_name;
        if (validated_offset((uintptr_t)name, (uintptr_t)elf->mem, (uintptr_t)elf->mem + elf->size)) {
            PRINT_ERROR("Corrupt file format\n");
            exit(-1);
        }

        if (!strcmp(name, str_tab)) {
            str_index = i;
        }

        if (!strcmp(name, section_name)) {
            sym_index = i;
        }
    }

    if (!str_index) {
        PRINT_DEBUG("This file does not have a %s\n", str_tab);
        return -1;
    }

    if (!sym_index) {
        PRINT_DEBUG("This file does not have a %s\n", section_name);
        return -1;
    }

    PRINT_INFO("%s table\n", section_name);
    PRINT_DYNSYM_TITLE("Nr", "Value", "Size", "Type", "Bind", "Vis", "Ndx", "Name");
    
    name = elf->mem + elf->data.elf32.shstrtab->sh_offset + elf->data.elf32.shdr[sym_index].sh_name;
    /* security check start*/
    if (validated_offset((uintptr_t)name, (uintptr_t)elf->mem, (uintptr_t)elf->mem + elf->size)) {
        PRINT_ERROR("Corrupt file format\n");
        exit(-1);
    }

    if (!strcmp(section_name, name)) {
        sym = (Elf32_Sym *)&elf->mem[elf->data.elf32.shdr[sym_index].sh_offset];
        count = elf->data.elf32.shdr[sym_index].sh_size / sizeof(Elf32_Sym);
        for(int i = 0; i < count; i++) {
            switch (ELF32_ST_TYPE(sym[i].st_info))
            {
                case STT_NOTYPE:
                    type = "NOTYPE";
                    break;
                
                case STT_OBJECT:
                    type = "OBJECT";
                    break;
                
                case STT_FUNC:
                    type = "FUNC";
                    break; 
                
                case STT_SECTION:
                    type = "SECTION";
                    break;
                
                case STT_FILE:
                    type = "FILE";
                    break;

                case STT_COMMON:
                    type = "COMMON";
                    break;

                case STT_TLS:
                    type = "TLS";
                    break;

                case STT_NUM:
                    type = "NUM";
                    break;
                
                case STT_LOOS:
                    type = "LOOS|GNU_IFUNC";
                    break;

                case STT_HIOS:
                    type = "HIOS";
                    break;

                case STT_LOPROC:
                    type = "LOPROC";
                    break;
                
                case STT_HIPROC:
                    type = "HIPROC";
                    break;                                                      
                
                default:
                    type = UNKOWN;
                    break;
            }

            switch (ELF32_ST_BIND(sym[i].st_info))
            {
                case STB_LOCAL:
                    bind = "LOCAL";
                    break;
                
                case STB_GLOBAL:
                    bind = "GLOBAL";
                    break;
                
                case STB_WEAK:
                    bind = "WEAK";
                    break; 
#ifndef ANDROID                
                case STB_NUM:
                    bind = "NUM";
                    break;
#endif               
                case STB_LOOS:
                    bind = "LOOS|GNU_UNIQUE";
                    break;

                case STB_HIOS:
                    bind = "HIOS";
                    break;

                case STB_LOPROC:
                    bind = "LOPROC";
                    break;

                case STB_HIPROC:
                    bind = "HIPROC";
                    break;
                                                    
                default:
                    bind = UNKOWN; 
                    break;
            }

            switch (ELF32_ST_VISIBILITY(sym[i].st_other))
            {
                case STV_DEFAULT:
                    other = "DEFAULT";
                    break;

                case STV_INTERNAL:
                    other = "INTERNAL";
                    break;
                
                case STV_HIDDEN:
                    other = "HIDDEN";
                    break;
                
                case STV_PROTECTED:
                    other = "PROTECTED";
                    break;

                default:
                    other = UNKOWN;
                    break;
            }
            name = elf->mem + elf->data.elf32.shdr[str_index].sh_offset + sym[i].st_name;
            PRINT_DYNSYM(i, sym[i].st_value, sym[i].st_size, type, bind, \
                other, sym[i].st_shndx, name);
        }
    }
    return 0;
}

/**
 * @description: .dynsym information
 * @param {handle_t64} h
 * @return int error code {-1:error,0:sucess}
 */
static int display_sym64(Elf *elf, char *section_name, char *str_tab) {
    char *name = NULL;
    char *type;
    char *bind;
    char *other;
    // The following variables must be initialized 
    // because they need to be used to determine whether sections exist or not.
    // 以下些变量必须初始化，因为要根据他们判节是否存在
    int str_index = 0;
    int sym_index = 0;
    size_t count;
    Elf64_Sym *sym;

    for (int i = 0; i < elf->data.elf64.ehdr->e_shnum; i++) {
        name = elf->mem + elf->data.elf64.shstrtab->sh_offset + elf->data.elf64.shdr[i].sh_name;
        if (validated_offset((uintptr_t)name, (uintptr_t)elf->mem, (uintptr_t)elf->mem + elf->size)) {
            PRINT_ERROR("Corrupt file format\n");
            exit(-1);
        }

        if (!strcmp(name, str_tab)) {
            str_index = i;
        }

        if (!strcmp(name, section_name)) {
            sym_index = i;
        }
    }

    if (!str_index) {
        PRINT_DEBUG("This file does not have a %s\n", str_tab);
        return -1;
    }

    if (!sym_index) {
        PRINT_DEBUG("This file does not have a %s\n", section_name);
        return -1;
    }

    PRINT_INFO("%s table\n", section_name);
    PRINT_DYNSYM_TITLE("Nr", "Value", "Size", "Type", "Bind", "Vis", "Ndx", "Name");
    
    name = elf->mem + elf->data.elf64.shstrtab->sh_offset + elf->data.elf64.shdr[sym_index].sh_name;
    /* security check start*/
    if (validated_offset((uintptr_t)name, (uintptr_t)elf->mem, (uintptr_t)elf->mem + elf->size)) {
        PRINT_ERROR("Corrupt file format\n");
        exit(-1);
    }

    if (!strcmp(section_name, name)) {
        sym = (Elf64_Sym *)&elf->mem[elf->data.elf64.shdr[sym_index].sh_offset];
        count = elf->data.elf64.shdr[sym_index].sh_size / sizeof(Elf64_Sym);
        for(int i = 0; i < count; i++) {
            switch (ELF64_ST_TYPE(sym[i].st_info))
            {
                case STT_NOTYPE:
                    type = "NOTYPE";
                    break;
                
                case STT_OBJECT:
                    type = "OBJECT";
                    break;
                
                case STT_FUNC:
                    type = "FUNC";
                    break; 
                
                case STT_SECTION:
                    type = "SECTION";
                    break;
                
                case STT_FILE:
                    type = "FILE";
                    break;

                case STT_COMMON:
                    type = "COMMON";
                    break;

                case STT_TLS:
                    type = "TLS";
                    break;

                case STT_NUM:
                    type = "NUM";
                    break;
                
                case STT_LOOS:
                    type = "LOOS|GNU_IFUNC";
                    break;

                case STT_HIOS:
                    type = "HIOS";
                    break;

                case STT_LOPROC:
                    type = "LOPROC";
                    break;
                
                case STT_HIPROC:
                    type = "HIPROC";
                    break;                                                      
                
                default:
                    type = UNKOWN;
                    break;
            }

            switch (ELF64_ST_BIND(sym[i].st_info))
            {
                case STB_LOCAL:
                    bind = "LOCAL";
                    break;
                
                case STB_GLOBAL:
                    bind = "GLOBAL";
                    break;
                
                case STB_WEAK:
                    bind = "WEAK";
                    break; 
#ifndef ANDROID                 
                case STB_NUM:
                    bind = "NUM";
                    break;
#endif                
                case STB_LOOS:
                    bind = "LOOS|GNU_UNIQUE";
                    break;

                case STB_HIOS:
                    bind = "HIOS";
                    break;

                case STB_LOPROC:
                    bind = "LOPROC";
                    break;

                case STB_HIPROC:
                    bind = "HIPROC";
                    break;
                                                    
                default:
                    bind = UNKOWN; 
                    break;
            }

            switch (ELF64_ST_VISIBILITY(sym[i].st_other))
            {
                case STV_DEFAULT:
                    other = "DEFAULT";
                    break;

                case STV_INTERNAL:
                    other = "INTERNAL";
                    break;
                
                case STV_HIDDEN:
                    other = "HIDDEN";
                    break;
                
                case STV_PROTECTED:
                    other = "PROTECTED";
                    break;

                default:
                    other = UNKOWN;
                    break;
            }
            name = elf->mem + elf->data.elf64.shdr[str_index].sh_offset + sym[i].st_name;
            PRINT_DYNSYM(i, sym[i].st_value, sym[i].st_size, type, bind, \
                other, sym[i].st_shndx, name);
        }
    }
    return 0;
}

/**
 * @description: Dynamic link information
 * @param {handle_t32} h
 * @return int error code {-1:error,0:sucess}
 */
static int display_dyninfo32(Elf *elf) {
    PRINT_INFO("Dynamic link information\n");
    char *name = NULL;
    char *tmp = NULL;
    int count = 0;
    int dynstr = 0;
    int dynamic = 0;
    Elf32_Dyn *dyn;
    for (int i = 0; i < elf->data.elf32.ehdr->e_shnum; i++) {
        name = elf->mem + elf->data.elf32.shstrtab->sh_offset + elf->data.elf32.shdr[i].sh_name;

        if (validated_offset((uintptr_t)name, (uintptr_t)elf->mem, (uintptr_t)elf->mem + elf->size)) {
            PRINT_ERROR("Corrupt file format\n");
            exit(-1);
        }

        if (!strcmp(name, ".dynstr")) {
            dynstr = i;
        }

        if (!strcmp(name, ".dynamic")) {
            dynamic = i;
        }
    }

    if (!dynstr) {
        PRINT_DEBUG("This file does not have a %s\n", ".dynstr");
        return -1;
    }

    if (!dynamic) {
        PRINT_DEBUG("This file does not have a %s\n", ".dynamic");
        return -1;
    }

    char value[50];
    name = "";
    dyn = (Elf32_Dyn *)&elf->mem[elf->data.elf32.shdr[dynamic].sh_offset];
    count = elf->data.elf32.shdr[dynamic].sh_size / sizeof(Elf32_Dyn);
    PRINT_INFO("Dynamic section at offset 0x%x contains %d entries\n", elf->data.elf32.shdr[dynamic].sh_offset, count);
    PRINT_DYN_TITLE("Nr", "Tag", "Type", "Name/Value");
    
    for(int i = 0; i < count; i++) {
        memset(value, 0, 50);
        snprintf(value, 50, "0x%x", dyn[i].d_un.d_val);
        name = elf->mem + elf->data.elf32.shdr[dynstr].sh_offset + dyn[i].d_un.d_val;
        switch (dyn[i].d_tag) {
            /* Legal values for d_tag (dynamic entry type).  */
            case DT_NULL:
                tmp = "DT_NULL";
                break;

            case DT_NEEDED:
                tmp = "DT_NEEDED";
                snprintf(value, 50, "Shared library: [%s]", name);
                break;
            
            case DT_PLTRELSZ:
                tmp = "DT_PLTRELSZ";
                break;

            case DT_PLTGOT:
                tmp = "DT_PLTGOT";
                break;

            case DT_HASH:
                tmp = "DT_HASH";
                break;

            case DT_STRTAB:
                tmp = "DT_STRTAB";
                break;

            case DT_SYMTAB:
                tmp = "DT_SYMTAB";
                break;

            case DT_RELA:
                tmp = "DT_RELA";
                break;

            case DT_RELASZ:
                tmp = "DT_RELASZ";
                break;

            case DT_RELAENT:
                tmp = "DT_RELAENT";
                break;

            case DT_STRSZ:
                tmp = "DT_STRSZ";
                break;

            case DT_SYMENT:
                tmp = "DT_SYMENT";
                break;

            case DT_INIT:
                tmp = "DT_INIT";
                break;

            case DT_FINI:
                tmp = "DT_FINI";
                break;

            case DT_SONAME:
                tmp = "DT_SONAME";
                snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, name);
                break;

            case DT_RPATH:
                tmp = "DT_RPATH";
                snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, name);
                break;

            case DT_SYMBOLIC:
                tmp = "DT_SYMBOLIC";
                break;

            case DT_REL:
                tmp = "DT_REL";
                break;

            case DT_RELSZ:
                tmp = "DT_RELSZ";
                break;

            case DT_RELENT:
                tmp = "DT_RELENT";
                break;
                
            case DT_PLTREL:
                tmp = "DT_PLTREL";
                break;

            case DT_DEBUG:
                tmp = "DT_DEBUG";
                break;

            case DT_TEXTREL:
                tmp = "DT_TEXTREL";
                break;

            case DT_JMPREL:
                tmp = "DT_JMPREL";
                break;

            case DT_BIND_NOW:
                tmp = "DT_BIND_NOW";
                break;

            case DT_INIT_ARRAY:
                tmp = "DT_INIT_ARRAY";
                break;

            case DT_FINI_ARRAY:
                tmp = "DT_FINI_ARRAY";
                break;

            case DT_INIT_ARRAYSZ:
                tmp = "DT_INIT_ARRAYSZ";
                break;
            
            case DT_FINI_ARRAYSZ:
                tmp = "DT_FINI_ARRAYSZ";
                break;

            case DT_RUNPATH:
                tmp = "DT_RUNPATH";
                snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, name);
                break;

            case DT_FLAGS:
                tmp = "DT_FLAGS";
                switch (dyn[i].d_un.d_val)
                {
                /* Object may use DF_ORIGIN */
                case DF_ORIGIN:
                    snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, "DF_ORIGIN");
                    break;

                /* Symbol resolutions starts here */
                case DF_SYMBOLIC:
                    snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, "DF_SYMBOLIC");
                    break;
                
                /* Object contains text relocations */
                case DF_TEXTREL:
                    snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, "DF_TEXTREL");
                    break;
                
                /* No lazy binding for this object */
                case DF_BIND_NOW:
                    snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, "DF_BIND_NOW");
                    break;

                /* Module uses the static TLS model */
                case DF_STATIC_TLS:
                    snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, "DF_STATIC_TLS");
                    break;
                
                default:
                    break;
                }

                break;
            
            case DT_ENCODING:
                tmp = "DT_ENCODING";
                break;

            case DT_PREINIT_ARRAYSZ:
                tmp = "DT_PREINIT_ARRAYSZ";
                break;
#ifndef ANDROID
            case DT_SYMTAB_SHNDX:
                tmp = "DT_SYMTAB_SHNDX";
                break;
           
            case DT_NUM:
                tmp = "DT_NUM";
                break;
#endif
            case DT_LOOS:
                tmp = "DT_LOOS";
                break;

            case DT_HIOS:
                tmp = "DT_HIOS";
                break;

            case DT_LOPROC:
                tmp = "DT_LOPROC";
                break;

            case DT_HIPROC:
                tmp = "DT_HIPROC";
                break;
#ifndef ANDROID
            case DT_PROCNUM:
                tmp = "DT_LOPROC";
                break;
#endif
            /* DT_* entries which fall between DT_VALRNGHI & DT_VALRNGLO use the
                * Dyn.d_un.d_val field of the Elf*_Dyn structure.  This follows Sun's
                * approach. */

            case DT_VALRNGLO:
                tmp = "DT_VALRNGLO";
                break;

            case DT_GNU_PRELINKED:
                tmp = "DT_GNU_PRELINKED";
                break;
            
            case DT_GNU_CONFLICTSZ:
                tmp = "DT_GNU_CONFLICTSZ";
                break;

            case DT_GNU_LIBLISTSZ:
                tmp = "DT_GNU_LIBLISTSZ";
                break;

            case DT_CHECKSUM:
                tmp = "DT_CHECKSUM";
                break;

            case DT_PLTPADSZ:
                tmp = "DT_PLTPADSZ";
                break;

            case DT_MOVEENT:
                tmp = "DT_MOVEENT";
                break;

            case DT_MOVESZ:
                tmp = "DT_MOVESZ";
                break;

            case DT_FEATURE_1:
                tmp = "DT_FEATURE_1";
                break;

            case DT_POSFLAG_1:
                tmp = "DT_POSFLAG_1";
                break;

            case DT_SYMINSZ:
                tmp = "DT_SYMINSZ";
                break;

            case DT_SYMINENT:
                tmp = "DT_SYMINENT";
                break;

            /* DT_* entries which fall between DT_ADDRRNGHI & DT_ADDRRNGLO use the
                * Dyn.d_un.d_ptr field of the Elf*_Dyn structure.
                * If any adjustment is made to the ELF object after it has been
                * built these entries will need to be adjusted.  */
            case DT_ADDRRNGLO:
                tmp = "DT_ADDRRNGLO";
                break;

            case DT_GNU_HASH:
                tmp = "DT_GNU_HASH";
                break;

            case DT_TLSDESC_PLT:
                tmp = "DT_TLSDESC_PLT";
                break;

            case DT_TLSDESC_GOT:
                tmp = "DT_TLSDESC_GOT";
                break;

            case DT_GNU_CONFLICT:
                tmp = "DT_GNU_CONFLICT";
                break;

            case DT_GNU_LIBLIST:
                tmp = "DT_GNU_LIBLIST";
                break;

            case DT_CONFIG:
                tmp = "DT_CONFIG";
                break;

            case DT_DEPAUDIT:
                tmp = "DT_DEPAUDIT";
                break;

            case DT_AUDIT:
                tmp = "DT_AUDIT";
                break;

            case DT_PLTPAD:
                tmp = "DT_PLTPAD";
                break;

            case DT_MOVETAB:
                tmp = "DT_MOVETAB";
                break;

            case DT_SYMINFO:
                tmp = "DT_SYMINFO";
                break;
                
            /* The versioning entry types.  The next are defined as part of the
                * GNU extension.  */
            case DT_VERSYM:
                tmp = "DT_VERSYM";
                break;

            case DT_RELACOUNT:
                tmp = "DT_RELACOUNT";
                break;

            case DT_RELCOUNT:
                tmp = "DT_RELCOUNT";
                break;
            
            /* These were chosen by Sun.  */
            case DT_FLAGS_1:
                tmp = "DT_FLAGS_1";
                int offset = 0;
                if (has_flag(dyn[i].d_un.d_val, DF_1_NOW)) {
                    offset += snprintf(value, 50, "%s ", "NOW");
                }
                if (has_flag(dyn[i].d_un.d_val, DF_1_PIE)) {
                    offset += snprintf(value + offset, 50, "%s ", "PIE");
                }
                else {
                    // TODO
                    snprintf(value, 50, "Known: 0x%x", dyn[i].d_un.d_val);
                }
                
                break;

            case DT_VERDEF:
                tmp = "DT_VERDEF";
                break;

            case DT_VERDEFNUM:
                tmp = "DT_VERDEFNUM";
                break;

            case DT_VERNEED:
                tmp = "DT_VERNEED";
                break;

            case DT_VERNEEDNUM:
                tmp = "DT_VERNEEDNUM";
                break;
            
            default:
                tmp = UNKOWN;
                break;
        }
        PRINT_DYN(i, dyn[i].d_tag, tmp, value);
    }

    return 0;
}

static int display_dyninfo64(Elf *elf) {
    PRINT_INFO("Dynamic link information\n");
    char *name = NULL;
    char *tmp = NULL;
    int count = 0;
    int dynstr = 0;
    int dynamic = 0;
    Elf64_Dyn *dyn;
    for (int i = 0; i < elf->data.elf64.ehdr->e_shnum; i++) {
        name = elf->mem + elf->data.elf64.shstrtab->sh_offset + elf->data.elf64.shdr[i].sh_name;
        if (validated_offset((uintptr_t)name, (uintptr_t)elf->mem, (uintptr_t)elf->mem + elf->size)) {
            PRINT_ERROR("Corrupt file format\n");
            exit(-1);
        }

        if (!strcmp(name, ".dynstr")) {
            dynstr = i;
        }

        if (!strcmp(name, ".dynamic")) {
            dynamic = i;
        }
    }

    if (!dynstr) {
        PRINT_DEBUG("This file does not have a %s\n", ".dynstr");
        return -1;
    }

    if (!dynamic) {
        PRINT_DEBUG("This file does not have a %s\n", ".dynamic");
        return -1;
    }

    char value[50];
    name = "";
    dyn = (Elf64_Dyn *)&elf->mem[elf->data.elf64.shdr[dynamic].sh_offset];
    count = elf->data.elf64.shdr[dynamic].sh_size / sizeof(Elf64_Dyn);
    PRINT_INFO("Dynamic section at offset 0x%x contains %d entries\n", elf->data.elf64.shdr[dynamic].sh_offset, count);
    PRINT_DYN_TITLE("Nr", "Tag", "Type", "Name/Value");
    
    for(int i = 0; i < count; i++) {
        memset(value, 0, 50);
        snprintf(value, 50, "0x%x", dyn[i].d_un.d_val);
        name = elf->mem + elf->data.elf64.shdr[dynstr].sh_offset + dyn[i].d_un.d_val;
        switch (dyn[i].d_tag) {
            /* Legal values for d_tag (dynamic entry type).  */
            case DT_NULL:
                tmp = "DT_NULL";
                break;

            case DT_NEEDED:
                tmp = "DT_NEEDED";
                snprintf(value, 50, "Shared library: [%s]", name);
                break;
            
            case DT_PLTRELSZ:
                tmp = "DT_PLTRELSZ";
                break;

            case DT_PLTGOT:
                tmp = "DT_PLTGOT";
                break;

            case DT_HASH:
                tmp = "DT_HASH";
                break;

            case DT_STRTAB:
                tmp = "DT_STRTAB";
                break;

            case DT_SYMTAB:
                tmp = "DT_SYMTAB";
                break;

            case DT_RELA:
                tmp = "DT_RELA";
                break;

            case DT_RELASZ:
                tmp = "DT_RELASZ";
                break;

            case DT_RELAENT:
                tmp = "DT_RELAENT";
                break;

            case DT_STRSZ:
                tmp = "DT_STRSZ";
                break;

            case DT_SYMENT:
                tmp = "DT_SYMENT";
                break;

            case DT_INIT:
                tmp = "DT_INIT";
                break;

            case DT_FINI:
                tmp = "DT_FINI";
                break;

            case DT_SONAME:
                tmp = "DT_SONAME";
                snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, name);
                break;

            case DT_RPATH:
                tmp = "DT_RPATH";
                snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, name);
                break;

            case DT_SYMBOLIC:
                tmp = "DT_SYMBOLIC";
                break;

            case DT_REL:
                tmp = "DT_REL";
                break;

            case DT_RELSZ:
                tmp = "DT_RELSZ";
                break;

            case DT_RELENT:
                tmp = "DT_RELENT";
                break;
                
            case DT_PLTREL:
                tmp = "DT_PLTREL";
                break;

            case DT_DEBUG:
                tmp = "DT_DEBUG";
                break;

            case DT_TEXTREL:
                tmp = "DT_TEXTREL";
                break;

            case DT_JMPREL:
                tmp = "DT_JMPREL";
                break;

            case DT_BIND_NOW:
                tmp = "DT_BIND_NOW";
                break;

            case DT_INIT_ARRAY:
                tmp = "DT_INIT_ARRAY";
                break;

            case DT_FINI_ARRAY:
                tmp = "DT_FINI_ARRAY";
                break;

            case DT_INIT_ARRAYSZ:
                tmp = "DT_INIT_ARRAYSZ";
                break;
            
            case DT_FINI_ARRAYSZ:
                tmp = "DT_FINI_ARRAYSZ";
                break;

            case DT_RUNPATH:
                tmp = "DT_RUNPATH";
                snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, name);
                break;

            case DT_FLAGS:
                tmp = "DT_FLAGS";
                switch (dyn[i].d_un.d_val)
                {
                /* Object may use DF_ORIGIN */
                case DF_ORIGIN:
                    snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, "DF_ORIGIN");
                    break;

                /* Symbol resolutions starts here */
                case DF_SYMBOLIC:
                    snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, "DF_SYMBOLIC");
                    break;
                
                /* Object contains text relocations */
                case DF_TEXTREL:
                    snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, "DF_TEXTREL");
                    break;
                
                /* No lazy binding for this object */
                case DF_BIND_NOW:
                    snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, "DF_BIND_NOW");
                    break;

                /* Module uses the static TLS model */
                case DF_STATIC_TLS:
                    snprintf(value, 50, "0x%x [%s]", dyn[i].d_un.d_val, "DF_STATIC_TLS");
                    break;
                
                default:
                    break;
                }
                break;
            
            case DT_ENCODING:
                tmp = "DT_ENCODING";
                break;

            case DT_PREINIT_ARRAYSZ:
                tmp = "DT_PREINIT_ARRAYSZ";
                break;
#ifndef ANDROID
            case DT_SYMTAB_SHNDX:
                tmp = "DT_SYMTAB_SHNDX";
                break;
          
            case DT_NUM:
                tmp = "DT_NUM";
                break;
#endif
            case DT_LOOS:
                tmp = "DT_LOOS";
                break;

            case DT_HIOS:
                tmp = "DT_HIOS";
                break;

            case DT_LOPROC:
                tmp = "DT_LOPROC";
                break;

            case DT_HIPROC:
                tmp = "DT_HIPROC";
                break;
#ifndef ANDROID
            case DT_PROCNUM:
                tmp = "DT_LOPROC";
                break;
#endif
            /* DT_* entries which fall between DT_VALRNGHI & DT_VALRNGLO use the
                * Dyn.d_un.d_val field of the Elf*_Dyn structure.  This follows Sun's
                * approach. */

            case DT_VALRNGLO:
                tmp = "DT_VALRNGLO";
                break;

            case DT_GNU_PRELINKED:
                tmp = "DT_GNU_PRELINKED";
                break;
            
            case DT_GNU_CONFLICTSZ:
                tmp = "DT_GNU_CONFLICTSZ";
                break;

            case DT_GNU_LIBLISTSZ:
                tmp = "DT_GNU_LIBLISTSZ";
                break;

            case DT_CHECKSUM:
                tmp = "DT_CHECKSUM";
                break;

            case DT_PLTPADSZ:
                tmp = "DT_PLTPADSZ";
                break;

            case DT_MOVEENT:
                tmp = "DT_MOVEENT";
                break;

            case DT_MOVESZ:
                tmp = "DT_MOVESZ";
                break;

            case DT_FEATURE_1:
                tmp = "DT_FEATURE_1";
                break;

            case DT_POSFLAG_1:
                tmp = "DT_POSFLAG_1";
                break;

            case DT_SYMINSZ:
                tmp = "DT_SYMINSZ";
                break;

            case DT_SYMINENT:
                tmp = "DT_SYMINENT";
                break;

            /* DT_* entries which fall between DT_ADDRRNGHI & DT_ADDRRNGLO use the
                * Dyn.d_un.d_ptr field of the Elf*_Dyn structure.
                * If any adjustment is made to the ELF object after it has been
                * built these entries will need to be adjusted.  */
            case DT_ADDRRNGLO:
                tmp = "DT_ADDRRNGLO";
                break;

            case DT_GNU_HASH:
                tmp = "DT_GNU_HASH";
                break;

            case DT_TLSDESC_PLT:
                tmp = "DT_TLSDESC_PLT";
                break;

            case DT_TLSDESC_GOT:
                tmp = "DT_TLSDESC_GOT";
                break;

            case DT_GNU_CONFLICT:
                tmp = "DT_GNU_CONFLICT";
                break;

            case DT_GNU_LIBLIST:
                tmp = "DT_GNU_LIBLIST";
                break;

            case DT_CONFIG:
                tmp = "DT_CONFIG";
                break;

            case DT_DEPAUDIT:
                tmp = "DT_DEPAUDIT";
                break;

            case DT_AUDIT:
                tmp = "DT_AUDIT";
                break;

            case DT_PLTPAD:
                tmp = "DT_PLTPAD";
                break;

            case DT_MOVETAB:
                tmp = "DT_MOVETAB";
                break;

            case DT_SYMINFO:
                tmp = "DT_SYMINFO";
                break;
                
            /* The versioning entry types.  The next are defined as part of the
                * GNU extension.  */
            case DT_VERSYM:
                tmp = "DT_VERSYM";
                break;

            case DT_RELACOUNT:
                tmp = "DT_RELACOUNT";
                break;

            case DT_RELCOUNT:
                tmp = "DT_RELCOUNT";
                break;
            
            /* These were chosen by Sun.  */
            case DT_FLAGS_1:
                tmp = "DT_FLAGS_1";
                int offset = 0;
                if (has_flag(dyn[i].d_un.d_val, DF_1_NOW)) {
                    offset += snprintf(value, 50, "%s ", "NOW");
                }
                if (has_flag(dyn[i].d_un.d_val, DF_1_PIE)) {
                    offset += snprintf(value + offset, 50, "%s ", "PIE");
                }
                else {
                    // TODO
                    snprintf(value, 50, "Known: 0x%x", dyn[i].d_un.d_val);
                }
                
                break;

            case DT_VERDEF:
                tmp = "DT_VERDEF";
                break;

            case DT_VERDEFNUM:
                tmp = "DT_VERDEFNUM";
                break;

            case DT_VERNEED:
                tmp = "DT_VERNEED";
                break;

            case DT_VERNEEDNUM:
                tmp = "DT_VERNEEDNUM";
                break;
            
            default:
                tmp = UNKOWN;
                break;
        }
        PRINT_DYN(i, dyn[i].d_tag, tmp, value);
    }
    return 0;
}

/** 
 * @brief .relation information (.rel.*)
 * 
 * @param h 
 * @param section_name 
 * @return int error code {-1:error,0:sucess}
 */
static int display_rel32(Elf *elf, char *section_name) {
    char *name = NULL;
    char *type = NULL;
    char *bind = NULL;
    char *other = NULL;
    size_t str_index = 0;
    int rela_dyn_index = 0;
    size_t count = 0;
    Elf32_Rel *rel_section;
    int has_component = 0;
    for (int i = 0; i < elf->data.elf32.ehdr->e_shnum; i++) {
        name = elf->mem + elf->data.elf32.shstrtab->sh_offset + elf->data.elf32.shdr[i].sh_name;
        if (validated_offset((uintptr_t)name, (uintptr_t)elf->mem, (uintptr_t)elf->mem + elf->size)) {
            PRINT_ERROR("Corrupt file format\n");
            return -1;
        }

        if (!strcmp(name, section_name)) {
            rela_dyn_index = i;
            has_component = 1;
        }
    }

    if (!has_component) {
        PRINT_DEBUG("This file does not have a %s\n", section_name);
        return -1;
    }
    
    if (validated_offset((uintptr_t)name, (uintptr_t)elf->mem, (uintptr_t)elf->mem + elf->size)) {
        PRINT_ERROR("Corrupt file format\n");
        return -1;
    }

    /* **********  get dyn string ********** */
    char **dyn_string = NULL;
    int string_count = 0;
    int err = get_dyn_string_table(elf, &dyn_string, &string_count);
    if (err != NO_ERR) {
        PRINT_DEBUG("get dynamic symbol string table error\n");
        return err;
    }
    char **sym_string = NULL;
    err = get_sym_string_table(elf, &sym_string, &string_count);
    if (err != NO_ERR) {
        PRINT_DEBUG("get symbol string table error\n");
    }
    /* **********  get dyn string ********** */

    for (int i = 0; i < count; i++) {
        switch (ELF32_R_TYPE(rel_section[i].r_info))
        {
            case R_X86_64_NONE:
                type = "R_X86_64_NONE";
                break;

            case R_X86_64_64:
                type = "R_X86_64_64";
                break;

            case R_X86_64_PC32:
                type = "R_X86_64_PC32";
                break;

            case R_X86_64_GOT32:
                type = "R_X86_64_GOT32";
                break;

            case R_X86_64_PLT32:
                type = "R_X86_64_PLT32";
                break;

            case R_X86_64_COPY:
                type = "R_X86_64_COPY";
                break;

            case R_X86_64_GLOB_DAT:
                type = "R_X86_64_GLOB_DAT";
                break;

            case R_X86_64_JUMP_SLOT:
                type = "R_X86_64_JUMP_SLOT";
                break;

            case R_X86_64_RELATIVE:
                type = "R_X86_64_RELATIVE";
                break;

            case R_X86_64_GOTPCREL:
                type = "R_X86_64_GOTPCREL";
                break;

            case R_X86_64_32:
                type = "R_X86_64_32";
                break;

            case R_X86_64_32S:
                type = "R_X86_64_32S";
                break;

            case R_X86_64_16:
                type = "R_X86_64_16";
                break;

            case R_X86_64_PC16:
                type = "R_X86_64_PC16";
                break;

            case R_X86_64_8:
                type = "R_X86_64_8";
                break;

            case R_X86_64_PC8:
                type = "R_X86_64_PC8";
                break;

            case R_X86_64_DTPMOD64:
                type = "R_X86_64_DTPMOD64";
                break;

            case R_X86_64_DTPOFF64:
                type = "R_X86_64_DTPOFF64";
                break;

            case R_X86_64_TPOFF64:
                type = "R_X86_64_TPOFF64";
                break;

            case R_X86_64_TLSGD:
                type = "R_X86_64_TLSGD";
                break;

            case R_X86_64_TLSLD:
                type = "R_X86_64_TLSLD";
                break;

            case R_X86_64_DTPOFF32:
                type = "R_X86_64_DTPOFF32";
                break;

            case R_X86_64_GOTTPOFF:
                type = "R_X86_64_GOTTPOFF";
                break;

            case R_X86_64_TPOFF32:
                type = "R_X86_64_TPOFF32";
                break;

            case R_X86_64_PC64:
                type = "R_X86_64_PC64";
                break;

            case R_X86_64_GOTOFF64:
                type = "R_X86_64_GOTOFF64";
                break;

            case R_X86_64_GOTPC32:
                type = "R_X86_64_GOTPC32";
                break;

            case R_X86_64_GOT64:
                type = "R_X86_64_GOT64";
                break;

            case R_X86_64_GOTPCREL64:
                type = "R_X86_64_GOTPCREL64";
                break;

            case R_X86_64_GOTPC64:
                type = "R_X86_64_GOTPC64";
                break;

            case R_X86_64_GOTPLT64:
                type = "R_X86_64_GOTPLT64";
                break;

            case R_X86_64_PLTOFF64:
                type = "R_X86_64_PLTOFF64";
                break;

            case R_X86_64_SIZE32:
                type = "R_X86_64_SIZE32";
                break;

            case R_X86_64_SIZE64:
                type = "R_X86_64_SIZE64";
                break;

            case R_X86_64_GOTPC32_TLSDESC:
                type = "R_X86_64_GOTPC32_TLSDESC";
                break;

            case R_X86_64_TLSDESC_CALL:
                type = "R_X86_64_TLSDESC_CALL";
                break;

            case R_X86_64_TLSDESC:
                type = "R_X86_64_TLSDESC";
                break;

            case R_X86_64_IRELATIVE:
                type = "R_X86_64_IRELATIVE";
                break;

            case R_X86_64_RELATIVE64:
                type = "R_X86_64_RELATIVE64";
                break;

            case R_X86_64_GOTPCRELX:
                type = "R_X86_64_GOTPCRELX";
                break;

            case R_X86_64_REX_GOTPCRELX:
                type = "R_X86_64_REX_GOTPCRELX";
                break;
#ifndef ANDROID
            case R_X86_64_NUM:
                type = "R_X86_64_NUM";
                break;
         
            /* 动态链接重定位 */
            case R_AARCH64_P32_COPY:
                type = "R_AARCH64_P32_COPY";
                break;
            case R_AARCH64_P32_GLOB_DAT:
                type = "R_AARCH64_P32_GLOB_DAT";
                break;
            case R_AARCH64_P32_JUMP_SLOT:
                type = "R_AARCH64_P32_JUMP_SLOT";
                break;
            case R_AARCH64_P32_RELATIVE:
                type = "R_AARCH64_P32_RELATIVE";
                break;
            
            /* TLS相关重定位 */
            case R_AARCH64_P32_TLS_DTPMOD:
                type = "R_AARCH64_P32_TLS_DTPMOD";
                break;
            case R_AARCH64_P32_TLS_DTPREL:
                type = "R_AARCH64_P32_TLS_DTPREL";
                break;
            case R_AARCH64_P32_TLS_TPREL:
                type = "R_AARCH64_P32_TLS_TPREL";
                break;
            case R_AARCH64_P32_TLSDESC:
                type = "R_AARCH64_P32_TLSDESC";
                break;
            
            /* 间接函数重定位 */
            case R_AARCH64_P32_IRELATIVE:
                type = "R_AARCH64_P32_IRELATIVE";
                break;
#endif            
            default:
                break;
        }
        
        str_index = ELF32_R_SYM(rel_section[i].r_info);
        if (str_index > string_count) {
            PRINT_WARNING("Unknown file format or too many strings\n");
            break;
        }

        if (strlen(dyn_string[str_index]) == 0) {
            /* .o file .rel.text */
            PRINT_RELA(i, rel_section[i].r_offset, rel_section[i].r_info, type, str_index, sym_string[str_index]);
        } else
            PRINT_RELA(i, rel_section[i].r_offset, rel_section[i].r_info, type, str_index, dyn_string[str_index]); 
        
    }

    if (dyn_string) free(dyn_string);
    if (sym_string) free(sym_string);
}

/** 
 * @brief .relation information (.rel.*)
 * 
 * @param h 
 * @param section_name 
 * @return int error code {-1:error,0:sucess}
 */
static int display_rel64(Elf *elf, char *section_name) {
    char *name = NULL;
    char *type = NULL;
    char *bind = NULL;
    char *other = NULL;
    size_t str_index = 0;
    int rela_dyn_index = 0;
    size_t count = 0;
    Elf64_Rel *rel_section;
    int has_component = 0;
    for (int i = 0; i < elf->data.elf64.ehdr->e_shnum; i++) {
        name = elf->mem + elf->data.elf64.shstrtab->sh_offset + elf->data.elf64.shdr[i].sh_name;
        if (validated_offset((uintptr_t)name, (uintptr_t)elf->mem, (uintptr_t)elf->mem + elf->size)) {
            PRINT_ERROR("Corrupt file format\n");
            return -1;
        }

        if (!strcmp(name, section_name)) {
            rela_dyn_index = i;
            has_component = 1;
        }
    }

    if (!has_component) {
        PRINT_DEBUG("This file does not have a %s\n", section_name);
        return -1;
    }
    
    if (validated_offset((uintptr_t)name, (uintptr_t)elf->mem, (uintptr_t)elf->mem + elf->size)) {
        PRINT_ERROR("Corrupt file format\n");
        return -1;
    }

    /* **********  get dyn string ********** */
    char **dyn_string = NULL;
    int string_count = 0;
    int err = get_dyn_string_table(elf, &dyn_string, &string_count);
    if (err != NO_ERR) {
        PRINT_DEBUG("get dynamic symbol string table error\n");
        return err;
    }
    char **sym_string = NULL;
    err = get_sym_string_table(elf, &sym_string, &string_count);
    if (err != NO_ERR) {
        PRINT_DEBUG("get symbol string table error\n");
    }
    /* **********  get dyn string ********** */

    rel_section = (Elf64_Rel *)&elf->mem[elf->data.elf64.shdr[rela_dyn_index].sh_offset];
    count = elf->data.elf64.shdr[rela_dyn_index].sh_size / sizeof(Elf64_Rel);
    PRINT_INFO("Relocation section '%s' at offset 0x%x contains %d entries:\n", section_name, elf->data.elf64.shdr[rela_dyn_index].sh_offset, count);
    PRINT_RELA_TITLE("Nr", "Addr", "Info", "Type", "Sym.Index", "Sym.Name");
    for (int i = 0; i < count; i++) {
        switch (ELF64_R_TYPE(rel_section[i].r_info))
        {
            case R_X86_64_NONE:
                type = "R_X86_64_NONE";
                break;

            case R_X86_64_64:
                type = "R_X86_64_64";
                break;

            case R_X86_64_PC32:
                type = "R_X86_64_PC32";
                break;

            case R_X86_64_GOT32:
                type = "R_X86_64_GOT32";
                break;

            case R_X86_64_PLT32:
                type = "R_X86_64_PLT32";
                break;

            case R_X86_64_COPY:
                type = "R_X86_64_COPY";
                break;

            case R_X86_64_GLOB_DAT:
                type = "R_X86_64_GLOB_DAT";
                break;

            case R_X86_64_JUMP_SLOT:
                type = "R_X86_64_JUMP_SLOT";
                break;

            case R_X86_64_RELATIVE:
                type = "R_X86_64_RELATIVE";
                break;

            case R_X86_64_GOTPCREL:
                type = "R_X86_64_GOTPCREL";
                break;

            case R_X86_64_32:
                type = "R_X86_64_32";
                break;

            case R_X86_64_32S:
                type = "R_X86_64_32S";
                break;

            case R_X86_64_16:
                type = "R_X86_64_16";
                break;

            case R_X86_64_PC16:
                type = "R_X86_64_PC16";
                break;

            case R_X86_64_8:
                type = "R_X86_64_8";
                break;

            case R_X86_64_PC8:
                type = "R_X86_64_PC8";
                break;

            case R_X86_64_DTPMOD64:
                type = "R_X86_64_DTPMOD64";
                break;

            case R_X86_64_DTPOFF64:
                type = "R_X86_64_DTPOFF64";
                break;

            case R_X86_64_TPOFF64:
                type = "R_X86_64_TPOFF64";
                break;

            case R_X86_64_TLSGD:
                type = "R_X86_64_TLSGD";
                break;

            case R_X86_64_TLSLD:
                type = "R_X86_64_TLSLD";
                break;

            case R_X86_64_DTPOFF32:
                type = "R_X86_64_DTPOFF32";
                break;

            case R_X86_64_GOTTPOFF:
                type = "R_X86_64_GOTTPOFF";
                break;

            case R_X86_64_TPOFF32:
                type = "R_X86_64_TPOFF32";
                break;

            case R_X86_64_PC64:
                type = "R_X86_64_PC64";
                break;

            case R_X86_64_GOTOFF64:
                type = "R_X86_64_GOTOFF64";
                break;

            case R_X86_64_GOTPC32:
                type = "R_X86_64_GOTPC32";
                break;

            case R_X86_64_GOT64:
                type = "R_X86_64_GOT64";
                break;

            case R_X86_64_GOTPCREL64:
                type = "R_X86_64_GOTPCREL64";
                break;

            case R_X86_64_GOTPC64:
                type = "R_X86_64_GOTPC64";
                break;

            case R_X86_64_GOTPLT64:
                type = "R_X86_64_GOTPLT64";
                break;

            case R_X86_64_PLTOFF64:
                type = "R_X86_64_PLTOFF64";
                break;

            case R_X86_64_SIZE32:
                type = "R_X86_64_SIZE32";
                break;

            case R_X86_64_SIZE64:
                type = "R_X86_64_SIZE64";
                break;

            case R_X86_64_GOTPC32_TLSDESC:
                type = "R_X86_64_GOTPC32_TLSDESC";
                break;

            case R_X86_64_TLSDESC_CALL:
                type = "R_X86_64_TLSDESC_CALL";
                break;

            case R_X86_64_TLSDESC:
                type = "R_X86_64_TLSDESC";
                break;

            case R_X86_64_IRELATIVE:
                type = "R_X86_64_IRELATIVE";
                break;

            case R_X86_64_RELATIVE64:
                type = "R_X86_64_RELATIVE64";
                break;

            case R_X86_64_GOTPCRELX:
                type = "R_X86_64_GOTPCRELX";
                break;

            case R_X86_64_REX_GOTPCRELX:
                type = "R_X86_64_REX_GOTPCRELX";
                break;
#ifndef ANDROID
            case R_X86_64_NUM:
                type = "R_X86_64_NUM";
                break;

            /* LP64 AArch64 relocs.  */
            case R_AARCH64_ABS64:
                type = "R_AARCH64_ABS64";
                break;
            case R_AARCH64_ABS32:
                type = "R_AARCH64_ABS32";
                break;
            case R_AARCH64_ABS16:
                type = "R_AARCH64_ABS16";
                break;
            case R_AARCH64_PREL64:
                type = "R_AARCH64_PREL64";
                break;
            case R_AARCH64_PREL32:
                type = "R_AARCH64_PREL32";
                break;
            case R_AARCH64_PREL16:
                type = "R_AARCH64_PREL16";
                break;
            case R_AARCH64_MOVW_UABS_G0:
                type = "R_AARCH64_MOVW_UABS_G0";
                break;
            case R_AARCH64_MOVW_UABS_G0_NC:
                type = "R_AARCH64_MOVW_UABS_G0_NC";
                break;
            case R_AARCH64_MOVW_UABS_G1:
                type = "R_AARCH64_MOVW_UABS_G1";
                break;
            case R_AARCH64_MOVW_UABS_G1_NC:
                type = "R_AARCH64_MOVW_UABS_G1_NC";
                break;
            case R_AARCH64_MOVW_UABS_G2:
                type = "R_AARCH64_MOVW_UABS_G2";
                break;
            case R_AARCH64_MOVW_UABS_G2_NC:
                type = "R_AARCH64_MOVW_UABS_G2_NC";
                break;
            case R_AARCH64_MOVW_UABS_G3:
                type = "R_AARCH64_MOVW_UABS_G3";
                break;
            case R_AARCH64_MOVW_SABS_G0:
                type = "R_AARCH64_MOVW_SABS_G0";
                break;
            case R_AARCH64_MOVW_SABS_G1:
                type = "R_AARCH64_MOVW_SABS_G1";
                break;
            case R_AARCH64_MOVW_SABS_G2:
                type = "R_AARCH64_MOVW_SABS_G2";
                break;
            case R_AARCH64_LD_PREL_LO19:
                type = "R_AARCH64_LD_PREL_LO19";
                break;
            case R_AARCH64_ADR_PREL_LO21:
                type = "R_AARCH64_ADR_PREL_LO21";
                break;
            case R_AARCH64_ADR_PREL_PG_HI21:
                type = "R_AARCH64_ADR_PREL_PG_HI21";
                break;
            case R_AARCH64_ADR_PREL_PG_HI21_NC:
                type = "R_AARCH64_ADR_PREL_PG_HI21_NC";
                break;
            case R_AARCH64_ADD_ABS_LO12_NC:
                type = "R_AARCH64_ADD_ABS_LO12_NC";
                break;
            case R_AARCH64_LDST8_ABS_LO12_NC:
                type = "R_AARCH64_LDST8_ABS_LO12_NC";
                break;
#endif
            case R_AARCH64_TSTBR14:
                type = "R_AARCH64_TSTBR14";
                break;
            case R_AARCH64_CONDBR19:
                type = "R_AARCH64_CONDBR19";
                break;
            case R_AARCH64_JUMP26:
                type = "R_AARCH64_JUMP26";
                break;
#ifndef ANDROID
            case R_AARCH64_CALL26:
                type = "R_AARCH64_CALL26";
                break;
            case R_AARCH64_LDST16_ABS_LO12_NC:
                type = "R_AARCH64_LDST16_ABS_LO12_NC";
                break;
            case R_AARCH64_LDST32_ABS_LO12_NC:
                type = "R_AARCH64_LDST32_ABS_LO12_NC";
                break;
            case R_AARCH64_LDST64_ABS_LO12_NC:
                type = "R_AARCH64_LDST64_ABS_LO12_NC";
                break;
            case R_AARCH64_MOVW_PREL_G0:
                type = "R_AARCH64_MOVW_PREL_G0";
                break;
            case R_AARCH64_MOVW_PREL_G0_NC:
                type = "R_AARCH64_MOVW_PREL_G0_NC";
                break;
            case R_AARCH64_MOVW_PREL_G1:
                type = "R_AARCH64_MOVW_PREL_G1";
                break;
            case R_AARCH64_MOVW_PREL_G1_NC:
                type = "R_AARCH64_MOVW_PREL_G1_NC";
                break;
            case R_AARCH64_MOVW_PREL_G2:
                type = "R_AARCH64_MOVW_PREL_G2";
                break;
            case R_AARCH64_MOVW_PREL_G2_NC:
                type = "R_AARCH64_MOVW_PREL_G2_NC";
                break;
            case R_AARCH64_MOVW_PREL_G3:
                type = "R_AARCH64_MOVW_PREL_G3";
                break;
            case R_AARCH64_LDST128_ABS_LO12_NC:
                type = "R_AARCH64_LDST128_ABS_LO12_NC";
                break;
            case R_AARCH64_MOVW_GOTOFF_G0:
                type = "R_AARCH64_MOVW_GOTOFF_G0";
                break;
            case R_AARCH64_MOVW_GOTOFF_G0_NC:
                type = "R_AARCH64_MOVW_GOTOFF_G0_NC";
                break;
            case R_AARCH64_MOVW_GOTOFF_G1:
                type = "R_AARCH64_MOVW_GOTOFF_G1";
                break;
            case R_AARCH64_MOVW_GOTOFF_G1_NC:
                type = "R_AARCH64_MOVW_GOTOFF_G1_NC";
                break;
            case R_AARCH64_MOVW_GOTOFF_G2:
                type = "R_AARCH64_MOVW_GOTOFF_G2";
                break;
            case R_AARCH64_MOVW_GOTOFF_G2_NC:
                type = "R_AARCH64_MOVW_GOTOFF_G2_NC";
                break;
            case R_AARCH64_MOVW_GOTOFF_G3:
                type = "R_AARCH64_MOVW_GOTOFF_G3";
                break;
            case R_AARCH64_GOTREL64:
                type = "R_AARCH64_GOTREL64";
                break;
            case R_AARCH64_GOTREL32:
                type = "R_AARCH64_GOTREL32";
                break;
            case R_AARCH64_GOT_LD_PREL19:
                type = "R_AARCH64_GOT_LD_PREL19";
                break;
            case R_AARCH64_LD64_GOTOFF_LO15:
                type = "R_AARCH64_LD64_GOTOFF_LO15";
                break;
            case R_AARCH64_ADR_GOT_PAGE:
                type = "R_AARCH64_ADR_GOT_PAGE";
                break;
            case R_AARCH64_LD64_GOT_LO12_NC:
                type = "R_AARCH64_LD64_GOT_LO12_NC";
                break;
            case R_AARCH64_LD64_GOTPAGE_LO15:
                type = "R_AARCH64_LD64_GOTPAGE_LO15";
                break;
            case R_AARCH64_TLSGD_ADR_PREL21:
                type = "R_AARCH64_TLSGD_ADR_PREL21";
                break;
            case R_AARCH64_TLSGD_ADR_PAGE21:
                type = "R_AARCH64_TLSGD_ADR_PAGE21";
                break;
            case R_AARCH64_TLSGD_ADD_LO12_NC:
                type = "R_AARCH64_TLSGD_ADD_LO12_NC";
                break;
            case R_AARCH64_TLSGD_MOVW_G1:
                type = "R_AARCH64_TLSGD_MOVW_G1";
                break;
            case R_AARCH64_TLSGD_MOVW_G0_NC:
                type = "R_AARCH64_TLSGD_MOVW_G0_NC";
                break;
            case R_AARCH64_TLSLD_ADR_PREL21:
                type = "R_AARCH64_TLSLD_ADR_PREL21";
                break;
            case R_AARCH64_TLSLD_ADR_PAGE21:
                type = "R_AARCH64_TLSLD_ADR_PAGE21";
                break;
            case R_AARCH64_TLSLD_ADD_LO12_NC:
                type = "R_AARCH64_TLSLD_ADD_LO12_NC";
                break;
            case R_AARCH64_TLSLD_MOVW_G1:
                type = "R_AARCH64_TLSLD_MOVW_G1";
                break;
            case R_AARCH64_TLSLD_MOVW_G0_NC:
                type = "R_AARCH64_TLSLD_MOVW_G0_NC";
                break;
            case R_AARCH64_TLSLD_LD_PREL19:
                type = "R_AARCH64_TLSLD_LD_PREL19";
                break;
            case R_AARCH64_TLSLD_MOVW_DTPREL_G2:
                type = "R_AARCH64_TLSLD_MOVW_DTPREL_G2";
                break;
            case R_AARCH64_TLSLD_MOVW_DTPREL_G1:
                type = "R_AARCH64_TLSLD_MOVW_DTPREL_G1";
                break;
            /* TLS Local Dynamic (TLSLD) relocations */
            case R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC:
                type = "R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC";
                break;
            case R_AARCH64_TLSLD_MOVW_DTPREL_G0:
                type = "R_AARCH64_TLSLD_MOVW_DTPREL_G0";
                break;
            case R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC:
                type = "R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC";
                break;
            case R_AARCH64_TLSLD_ADD_DTPREL_HI12:
                type = "R_AARCH64_TLSLD_ADD_DTPREL_HI12";
                break;
            case R_AARCH64_TLSLD_ADD_DTPREL_LO12:
                type = "R_AARCH64_TLSLD_ADD_DTPREL_LO12";
                break;
            case R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC:
                type = "R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC";
                break;
            case R_AARCH64_TLSLD_LDST8_DTPREL_LO12:
                type = "R_AARCH64_TLSLD_LDST8_DTPREL_LO12";
                break;
            case R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC:
                type = "R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC";
                break;
            case R_AARCH64_TLSLD_LDST16_DTPREL_LO12:
                type = "R_AARCH64_TLSLD_LDST16_DTPREL_LO12";
                break;
            case R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC:
                type = "R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC";
                break;
            case R_AARCH64_TLSLD_LDST32_DTPREL_LO12:
                type = "R_AARCH64_TLSLD_LDST32_DTPREL_LO12";
                break;
            case R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC:
                type = "R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC";
                break;
            case R_AARCH64_TLSLD_LDST64_DTPREL_LO12:
                type = "R_AARCH64_TLSLD_LDST64_DTPREL_LO12";
                break;
            case R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC:
                type = "R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC";
                break;
            /* TLS Initial Exec (TLSIE) relocations */
            case R_AARCH64_TLSIE_MOVW_GOTTPREL_G1:
                type = "R_AARCH64_TLSIE_MOVW_GOTTPREL_G1";
                break;
            case R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC:
                type = "R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC";
                break;
            case R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21:
                type = "R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21";
                break;
            case R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC:
                type = "R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC";
                break;
            case R_AARCH64_TLSIE_LD_GOTTPREL_PREL19:
                type = "R_AARCH64_TLSIE_LD_GOTTPREL_PREL19";
                break;
            /* TLS Local Exec (TLSLE) relocations */
            case R_AARCH64_TLSLE_MOVW_TPREL_G2:
                type = "R_AARCH64_TLSLE_MOVW_TPREL_G2";
                break;
            case R_AARCH64_TLSLE_MOVW_TPREL_G1:
                type = "R_AARCH64_TLSLE_MOVW_TPREL_G1";
                break;
            case R_AARCH64_TLSLE_MOVW_TPREL_G1_NC:
                type = "R_AARCH64_TLSLE_MOVW_TPREL_G1_NC";
                break;
            case R_AARCH64_TLSLE_MOVW_TPREL_G0:
                type = "R_AARCH64_TLSLE_MOVW_TPREL_G0";
                break;
            case R_AARCH64_TLSLE_MOVW_TPREL_G0_NC:
                type = "R_AARCH64_TLSLE_MOVW_TPREL_G0_NC";
                break;
            case R_AARCH64_TLSLE_ADD_TPREL_HI12:
                type = "R_AARCH64_TLSLE_ADD_TPREL_HI12";
                break;
            case R_AARCH64_TLSLE_ADD_TPREL_LO12:
                type = "R_AARCH64_TLSLE_ADD_TPREL_LO12";
                break;
            case R_AARCH64_TLSLE_ADD_TPREL_LO12_NC:
                type = "R_AARCH64_TLSLE_ADD_TPREL_LO12_NC";
                break;
            case R_AARCH64_TLSLE_LDST8_TPREL_LO12:
                type = "R_AARCH64_TLSLE_LDST8_TPREL_LO12";
                break;
            case R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC:
                type = "R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC";
                break;
            case R_AARCH64_TLSLE_LDST16_TPREL_LO12:
                type = "R_AARCH64_TLSLE_LDST16_TPREL_LO12";
                break;
            case R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC:
                type = "R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC";
                break;
            case R_AARCH64_TLSLE_LDST32_TPREL_LO12:
                type = "R_AARCH64_TLSLE_LDST32_TPREL_LO12";
                break;
            case R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC:
                type = "R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC";
                break;
            case R_AARCH64_TLSLE_LDST64_TPREL_LO12:
                type = "R_AARCH64_TLSLE_LDST64_TPREL_LO12";
                break;
            case R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC:
                type = "R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC";
                break;
            /* TLSDESC relocations */
            case R_AARCH64_TLSDESC_LD_PREL19:
                type = "R_AARCH64_TLSDESC_LD_PREL19";
                break;
            case R_AARCH64_TLSDESC_ADR_PREL21:
                type = "R_AARCH64_TLSDESC_ADR_PREL21";
                break;
            case R_AARCH64_TLSDESC_ADR_PAGE21:
                type = "R_AARCH64_TLSDESC_ADR_PAGE21";
                break;
            case R_AARCH64_TLSDESC_LD64_LO12:
                type = "R_AARCH64_TLSDESC_LD64_LO12";
                break;
            case R_AARCH64_TLSDESC_ADD_LO12:
                type = "R_AARCH64_TLSDESC_ADD_LO12";
                break;
            case R_AARCH64_TLSDESC_OFF_G1:
                type = "R_AARCH64_TLSDESC_OFF_G1";
                break;
            case R_AARCH64_TLSDESC_OFF_G0_NC:
                type = "R_AARCH64_TLSDESC_OFF_G0_NC";
                break;
            case R_AARCH64_TLSDESC_LDR:
                type = "R_AARCH64_TLSDESC_LDR";
                break;
            case R_AARCH64_TLSDESC_ADD:
                type = "R_AARCH64_TLSDESC_ADD";
                break;
            case R_AARCH64_TLSDESC_CALL:
                type = "R_AARCH64_TLSDESC_CALL";
                break;
            /* 128-bit TLS relocations */
            case R_AARCH64_TLSLE_LDST128_TPREL_LO12:
                type = "R_AARCH64_TLSLE_LDST128_TPREL_LO12";
                break;
            case R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC:
                type = "R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC";
                break;
            case R_AARCH64_TLSLD_LDST128_DTPREL_LO12:
                type = "R_AARCH64_TLSLD_LDST128_DTPREL_LO12";
                break;
            case R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC:
                type = "R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC";
                break;
#endif
            /* Dynamic relocations */
            case R_AARCH64_COPY:
                type = "R_AARCH64_COPY";
                break;
            case R_AARCH64_GLOB_DAT:
                type = "R_AARCH64_GLOB_DAT";
                break;
            case R_AARCH64_JUMP_SLOT:
                type = "R_AARCH64_JUMP_SLOT";
                break;
            case R_AARCH64_RELATIVE:
                type = "R_AARCH64_RELATIVE";
                break;
            case R_AARCH64_TLS_DTPMOD:
                type = "R_AARCH64_TLS_DTPMOD";
                break;
            case R_AARCH64_TLS_DTPREL:
                type = "R_AARCH64_TLS_DTPREL";
                break;
            case R_AARCH64_TLS_TPREL:
                type = "R_AARCH64_TLS_TPREL";
                break;
            case R_AARCH64_TLSDESC:
                type = "R_AARCH64_TLSDESC";
                break;
#ifndef OHOS
            case R_AARCH64_IRELATIVE:
                type = "R_AARCH64_IRELATIVE";
                break;
#endif            
            default:
                break;
        }
        
        str_index = ELF64_R_SYM(rel_section[i].r_info);
        if (str_index > string_count) {
            PRINT_WARNING("Unknown file format or too many strings\n");
            break;
        }

        if (strlen(dyn_string[str_index]) == 0) {
            /* .o file .rel.text */
            PRINT_RELA(i, rel_section[i].r_offset, rel_section[i].r_info, type, str_index, sym_string[str_index]);
        } else
            PRINT_RELA(i, rel_section[i].r_offset, rel_section[i].r_info, type, str_index, dyn_string[str_index]);

    }
    if (dyn_string) free(dyn_string);
    if (sym_string) free(sym_string);
}

/** 
 * @brief .relation information (.rela.*)
 * 
 * @param h 
 * @param section_name 
 * @return int error code {-1:error,0:sucess}
 */
static int display_rela32(Elf *elf, char *section_name) {
    char *name = NULL;
    char *type = NULL;
    char *bind = NULL;
    char *other = NULL;
    size_t str_index = 0;
    int rela_dyn_index = 0;
    size_t count = 0;
    Elf32_Rela *rela_dyn;
    int has_component = 0;
    for (int i = 0; i < elf->data.elf32.ehdr->e_shnum; i++) {
        name = elf->mem + elf->data.elf32.shstrtab->sh_offset + elf->data.elf32.shdr[i].sh_name;
        if (validated_offset((uintptr_t)name, (uintptr_t)elf->mem, (uintptr_t)elf->mem + elf->size)) {
            PRINT_ERROR("Corrupt file format\n");
            return -1;
        }

        if (!strcmp(name, section_name)) {
            rela_dyn_index = i;
            has_component = 1;
        }
    }

    if (!has_component) {
        PRINT_DEBUG("This file does not have a %s\n", section_name);
        return -1;
    }
    
    if (validated_offset((uintptr_t)name, (uintptr_t)elf->mem, (uintptr_t)elf->mem + elf->size)) {
        PRINT_ERROR("Corrupt file format\n");
        return -1;
    }

    /* **********  get dyn string ********** */
    char **dyn_string = NULL;
    int string_count = 0;
    int err = get_dyn_string_table(elf, &dyn_string, &string_count);
    if (err != NO_ERR) {
        PRINT_DEBUG("get dynamic symbol string table error\n");
        return err;
    }
    char **sym_string = NULL;
    err = get_sym_string_table(elf, &sym_string, &string_count);
    if (err != NO_ERR) {
        PRINT_DEBUG("get symbol string table error\n");
    }
    /* **********  get dyn string ********** */
    
    rela_dyn = (Elf32_Rela *)&elf->mem[elf->data.elf32.shdr[rela_dyn_index].sh_offset];
    count = elf->data.elf32.shdr[rela_dyn_index].sh_size / sizeof(Elf32_Rela);
    PRINT_INFO("Relocation section '%s' at offset 0x%x contains %d entries:\n", section_name, elf->data.elf32.shdr[rela_dyn_index].sh_offset, count);
    PRINT_RELA_TITLE("Nr", "Addr", "Info", "Type", "Sym.Index", "Sym.Name + Addend");
    for (int i = 0; i < count; i++) {
        switch (ELF32_R_TYPE(rela_dyn[i].r_info))
        {
            case R_X86_64_NONE:
                type = "R_X86_64_NONE";
                break;

            case R_X86_64_64:
                type = "R_X86_64_64";
                break;

            case R_X86_64_PC32:
                type = "R_X86_64_PC32";
                break;

            case R_X86_64_GOT32:
                type = "R_X86_64_GOT32";
                break;

            case R_X86_64_PLT32:
                type = "R_X86_64_PLT32";
                break;

            case R_X86_64_COPY:
                type = "R_X86_64_COPY";
                break;

            case R_X86_64_GLOB_DAT:
                type = "R_X86_64_GLOB_DAT";
                break;

            case R_X86_64_JUMP_SLOT:
                type = "R_X86_64_JUMP_SLOT";
                break;

            case R_X86_64_RELATIVE:
                type = "R_X86_64_RELATIVE";
                break;

            case R_X86_64_GOTPCREL:
                type = "R_X86_64_GOTPCREL";
                break;

            case R_X86_64_32:
                type = "R_X86_64_32";
                break;

            case R_X86_64_32S:
                type = "R_X86_64_32S";
                break;

            case R_X86_64_16:
                type = "R_X86_64_16";
                break;

            case R_X86_64_PC16:
                type = "R_X86_64_PC16";
                break;

            case R_X86_64_8:
                type = "R_X86_64_8";
                break;

            case R_X86_64_PC8:
                type = "R_X86_64_PC8";
                break;

            case R_X86_64_DTPMOD64:
                type = "R_X86_64_DTPMOD64";
                break;

            case R_X86_64_DTPOFF64:
                type = "R_X86_64_DTPOFF64";
                break;

            case R_X86_64_TPOFF64:
                type = "R_X86_64_TPOFF64";
                break;

            case R_X86_64_TLSGD:
                type = "R_X86_64_TLSGD";
                break;

            case R_X86_64_TLSLD:
                type = "R_X86_64_TLSLD";
                break;

            case R_X86_64_DTPOFF32:
                type = "R_X86_64_DTPOFF32";
                break;

            case R_X86_64_GOTTPOFF:
                type = "R_X86_64_GOTTPOFF";
                break;

            case R_X86_64_TPOFF32:
                type = "R_X86_64_TPOFF32";
                break;

            case R_X86_64_PC64:
                type = "R_X86_64_PC64";
                break;

            case R_X86_64_GOTOFF64:
                type = "R_X86_64_GOTOFF64";
                break;

            case R_X86_64_GOTPC32:
                type = "R_X86_64_GOTPC32";
                break;

            case R_X86_64_GOT64:
                type = "R_X86_64_GOT64";
                break;

            case R_X86_64_GOTPCREL64:
                type = "R_X86_64_GOTPCREL64";
                break;

            case R_X86_64_GOTPC64:
                type = "R_X86_64_GOTPC64";
                break;

            case R_X86_64_GOTPLT64:
                type = "R_X86_64_GOTPLT64";
                break;

            case R_X86_64_PLTOFF64:
                type = "R_X86_64_PLTOFF64";
                break;

            case R_X86_64_SIZE32:
                type = "R_X86_64_SIZE32";
                break;

            case R_X86_64_SIZE64:
                type = "R_X86_64_SIZE64";
                break;

            case R_X86_64_GOTPC32_TLSDESC:
                type = "R_X86_64_GOTPC32_TLSDESC";
                break;

            case R_X86_64_TLSDESC_CALL:
                type = "R_X86_64_TLSDESC_CALL";
                break;

            case R_X86_64_TLSDESC:
                type = "R_X86_64_TLSDESC";
                break;

            case R_X86_64_IRELATIVE:
                type = "R_X86_64_IRELATIVE";
                break;

            case R_X86_64_RELATIVE64:
                type = "R_X86_64_RELATIVE64";
                break;

            case R_X86_64_GOTPCRELX:
                type = "R_X86_64_GOTPCRELX";
                break;

            case R_X86_64_REX_GOTPCRELX:
                type = "R_X86_64_REX_GOTPCRELX";
                break;
#ifndef ANDROID
            case R_X86_64_NUM:
                type = "R_X86_64_NUM";
                break;
            
            /* 动态链接重定位 */
            case R_AARCH64_P32_COPY:
                type = "R_AARCH64_P32_COPY";
                break;
            case R_AARCH64_P32_GLOB_DAT:
                type = "R_AARCH64_P32_GLOB_DAT";
                break;
            case R_AARCH64_P32_JUMP_SLOT:
                type = "R_AARCH64_P32_JUMP_SLOT";
                break;
            case R_AARCH64_P32_RELATIVE:
                type = "R_AARCH64_P32_RELATIVE";
                break;
            
            /* TLS相关重定位 */
            case R_AARCH64_P32_TLS_DTPMOD:
                type = "R_AARCH64_P32_TLS_DTPMOD";
                break;
            case R_AARCH64_P32_TLS_DTPREL:
                type = "R_AARCH64_P32_TLS_DTPREL";
                break;
            case R_AARCH64_P32_TLS_TPREL:
                type = "R_AARCH64_P32_TLS_TPREL";
                break;
            case R_AARCH64_P32_TLSDESC:
                type = "R_AARCH64_P32_TLSDESC";
                break;
            
            /* 间接函数重定位 */
            case R_AARCH64_P32_IRELATIVE:
                type = "R_AARCH64_P32_IRELATIVE";
                break;
#endif            
            default:
                break;
        }
        
        str_index = ELF32_R_SYM(rela_dyn[i].r_info);
        if (str_index > string_count) {
            PRINT_WARNING("Unknown file format or too many strings\n");
            break;
        }

        char tmp_name[MAX_PATH_LEN] = {0};
        if (strlen(dyn_string[str_index]) == 0) {
            /* .rela.dyn */
            if (str_index == 0) {
                snprintf(tmp_name, MAX_PATH_LEN, "%x", rela_dyn[i].r_addend);
            } 
            /* .o file .rela.text */
            else {
                snprintf(tmp_name, MAX_PATH_LEN, "%s %d", sym_string[str_index], rela_dyn[i].r_addend);
            }
        }
        /* .rela.plt */
        else if (rela_dyn[i].r_addend >= 0)
            snprintf(tmp_name, MAX_PATH_LEN, "%s + %d", dyn_string[str_index], rela_dyn[i].r_addend);
        else
            snprintf(tmp_name, MAX_PATH_LEN, "%s %d", dyn_string[str_index], rela_dyn[i].r_addend);
        PRINT_RELA(i, rela_dyn[i].r_offset, rela_dyn[i].r_info, type, str_index, tmp_name);
    }
    if (dyn_string) free(dyn_string);
    if (sym_string) free(sym_string);
}

/** 
 * @brief .relation information
 * 
 * @param h 
 * @param section_name 
 * @return int error code {-1:error,0:sucess}
 */
static int display_rela64(Elf *elf, char *section_name) {
    char *name = NULL;
    char *type = NULL;
    char *bind = NULL;
    char *other = NULL;
    size_t str_index = 0;
    int rela_dyn_index = 0;
    size_t count = 0;
    Elf64_Rela *rela_dyn;
    int has_component = 0;
    for (int i = 0; i < elf->data.elf64.ehdr->e_shnum; i++) {
        name = elf->mem + elf->data.elf64.shstrtab->sh_offset + elf->data.elf64.shdr[i].sh_name;
        if (validated_offset((uintptr_t)name, (uintptr_t)elf->mem, (uintptr_t)elf->mem + elf->size)) {
            PRINT_ERROR("Corrupt file format\n");
            return -1;
        }

        if (!strcmp(name, section_name)) {
            rela_dyn_index = i;
            has_component = 1;
        }
    }

    if (!has_component) {
        PRINT_DEBUG("This file does not have a %s\n", section_name);
        return -1;
    }
    
    if (validated_offset((uintptr_t)name, (uintptr_t)elf->mem, (uintptr_t)elf->mem + elf->size)) {
        PRINT_ERROR("Corrupt file format\n");
        return -1;
    }

    /* **********  get dyn string ********** */
    char **dyn_string = NULL;
    int string_count = 0;
    int err = get_dyn_string_table(elf, &dyn_string, &string_count);
    if (err != NO_ERR) {
        PRINT_DEBUG("get dynamic symbol string table error\n");
        return err;
    }
    char **sym_string = NULL;
    err = get_sym_string_table(elf, &sym_string, &string_count);
    if (err != NO_ERR) {
        PRINT_DEBUG("get symbol string table error\n");
    }
    /* **********  get dyn string ********** */
    
    rela_dyn = (Elf64_Rela *)&elf->mem[elf->data.elf64.shdr[rela_dyn_index].sh_offset];
    count = elf->data.elf64.shdr[rela_dyn_index].sh_size / sizeof(Elf64_Rela);
    PRINT_INFO("Relocation section '%s' at offset 0x%x contains %d entries:\n", section_name, elf->data.elf64.shdr[rela_dyn_index].sh_offset, count);
    PRINT_RELA_TITLE("Nr", "Addr", "Info", "Type", "Sym.Index", "Sym.Name + Addend");

    for (int i = 0; i < count; i++) {
        switch (ELF64_R_TYPE(rela_dyn[i].r_info))
        {
            case R_X86_64_NONE:
                type = "R_X86_64_NONE";
                break;

            case R_X86_64_64:
                type = "R_X86_64_64";
                break;

            case R_X86_64_PC32:
                type = "R_X86_64_PC32";
                break;

            case R_X86_64_GOT32:
                type = "R_X86_64_GOT32";
                break;

            case R_X86_64_PLT32:
                type = "R_X86_64_PLT32";
                break;

            case R_X86_64_COPY:
                type = "R_X86_64_COPY";
                break;

            case R_X86_64_GLOB_DAT:
                type = "R_X86_64_GLOB_DAT";
                break;

            case R_X86_64_JUMP_SLOT:
                type = "R_X86_64_JUMP_SLOT";
                break;

            case R_X86_64_RELATIVE:
                type = "R_X86_64_RELATIVE";
                break;

            case R_X86_64_GOTPCREL:
                type = "R_X86_64_GOTPCREL";
                break;

            case R_X86_64_32:
                type = "R_X86_64_32";
                break;

            case R_X86_64_32S:
                type = "R_X86_64_32S";
                break;

            case R_X86_64_16:
                type = "R_X86_64_16";
                break;

            case R_X86_64_PC16:
                type = "R_X86_64_PC16";
                break;

            case R_X86_64_8:
                type = "R_X86_64_8";
                break;

            case R_X86_64_PC8:
                type = "R_X86_64_PC8";
                break;

            case R_X86_64_DTPMOD64:
                type = "R_X86_64_DTPMOD64";
                break;

            case R_X86_64_DTPOFF64:
                type = "R_X86_64_DTPOFF64";
                break;

            case R_X86_64_TPOFF64:
                type = "R_X86_64_TPOFF64";
                break;

            case R_X86_64_TLSGD:
                type = "R_X86_64_TLSGD";
                break;

            case R_X86_64_TLSLD:
                type = "R_X86_64_TLSLD";
                break;

            case R_X86_64_DTPOFF32:
                type = "R_X86_64_DTPOFF32";
                break;

            case R_X86_64_GOTTPOFF:
                type = "R_X86_64_GOTTPOFF";
                break;

            case R_X86_64_TPOFF32:
                type = "R_X86_64_TPOFF32";
                break;

            case R_X86_64_PC64:
                type = "R_X86_64_PC64";
                break;

            case R_X86_64_GOTOFF64:
                type = "R_X86_64_GOTOFF64";
                break;

            case R_X86_64_GOTPC32:
                type = "R_X86_64_GOTPC32";
                break;

            case R_X86_64_GOT64:
                type = "R_X86_64_GOT64";
                break;

            case R_X86_64_GOTPCREL64:
                type = "R_X86_64_GOTPCREL64";
                break;

            case R_X86_64_GOTPC64:
                type = "R_X86_64_GOTPC64";
                break;

            case R_X86_64_GOTPLT64:
                type = "R_X86_64_GOTPLT64";
                break;

            case R_X86_64_PLTOFF64:
                type = "R_X86_64_PLTOFF64";
                break;

            case R_X86_64_SIZE32:
                type = "R_X86_64_SIZE32";
                break;

            case R_X86_64_SIZE64:
                type = "R_X86_64_SIZE64";
                break;

            case R_X86_64_GOTPC32_TLSDESC:
                type = "R_X86_64_GOTPC32_TLSDESC";
                break;

            case R_X86_64_TLSDESC_CALL:
                type = "R_X86_64_TLSDESC_CALL";
                break;

            case R_X86_64_TLSDESC:
                type = "R_X86_64_TLSDESC";
                break;

            case R_X86_64_IRELATIVE:
                type = "R_X86_64_IRELATIVE";
                break;

            case R_X86_64_RELATIVE64:
                type = "R_X86_64_RELATIVE64";
                break;

            case R_X86_64_GOTPCRELX:
                type = "R_X86_64_GOTPCRELX";
                break;

            case R_X86_64_REX_GOTPCRELX:
                type = "R_X86_64_REX_GOTPCRELX";
                break;
#ifndef ANDROID
            case R_X86_64_NUM:
                type = "R_X86_64_NUM";
                break;

            /* LP64 AArch64 relocs.  */
            case R_AARCH64_ABS64:
                type = "R_AARCH64_ABS64";
                break;
            case R_AARCH64_ABS32:
                type = "R_AARCH64_ABS32";
                break;
            case R_AARCH64_ABS16:
                type = "R_AARCH64_ABS16";
                break;
            case R_AARCH64_PREL64:
                type = "R_AARCH64_PREL64";
                break;
            case R_AARCH64_PREL32:
                type = "R_AARCH64_PREL32";
                break;
            case R_AARCH64_PREL16:
                type = "R_AARCH64_PREL16";
                break;
            case R_AARCH64_MOVW_UABS_G0:
                type = "R_AARCH64_MOVW_UABS_G0";
                break;
            case R_AARCH64_MOVW_UABS_G0_NC:
                type = "R_AARCH64_MOVW_UABS_G0_NC";
                break;
            case R_AARCH64_MOVW_UABS_G1:
                type = "R_AARCH64_MOVW_UABS_G1";
                break;
            case R_AARCH64_MOVW_UABS_G1_NC:
                type = "R_AARCH64_MOVW_UABS_G1_NC";
                break;
            case R_AARCH64_MOVW_UABS_G2:
                type = "R_AARCH64_MOVW_UABS_G2";
                break;
            case R_AARCH64_MOVW_UABS_G2_NC:
                type = "R_AARCH64_MOVW_UABS_G2_NC";
                break;
            case R_AARCH64_MOVW_UABS_G3:
                type = "R_AARCH64_MOVW_UABS_G3";
                break;
            case R_AARCH64_MOVW_SABS_G0:
                type = "R_AARCH64_MOVW_SABS_G0";
                break;
            case R_AARCH64_MOVW_SABS_G1:
                type = "R_AARCH64_MOVW_SABS_G1";
                break;
            case R_AARCH64_MOVW_SABS_G2:
                type = "R_AARCH64_MOVW_SABS_G2";
                break;
            case R_AARCH64_LD_PREL_LO19:
                type = "R_AARCH64_LD_PREL_LO19";
                break;
            case R_AARCH64_ADR_PREL_LO21:
                type = "R_AARCH64_ADR_PREL_LO21";
                break;
            case R_AARCH64_ADR_PREL_PG_HI21:
                type = "R_AARCH64_ADR_PREL_PG_HI21";
                break;
            case R_AARCH64_ADR_PREL_PG_HI21_NC:
                type = "R_AARCH64_ADR_PREL_PG_HI21_NC";
                break;
            case R_AARCH64_ADD_ABS_LO12_NC:
                type = "R_AARCH64_ADD_ABS_LO12_NC";
                break;
            case R_AARCH64_LDST8_ABS_LO12_NC:
                type = "R_AARCH64_LDST8_ABS_LO12_NC";
                break;
#endif
            case R_AARCH64_TSTBR14:
                type = "R_AARCH64_TSTBR14";
                break;
            case R_AARCH64_CONDBR19:
                type = "R_AARCH64_CONDBR19";
                break;
            case R_AARCH64_JUMP26:
                type = "R_AARCH64_JUMP26";
                break;
#ifndef ANDROID
            case R_AARCH64_CALL26:
                type = "R_AARCH64_CALL26";
                break;
            case R_AARCH64_LDST16_ABS_LO12_NC:
                type = "R_AARCH64_LDST16_ABS_LO12_NC";
                break;
            case R_AARCH64_LDST32_ABS_LO12_NC:
                type = "R_AARCH64_LDST32_ABS_LO12_NC";
                break;
            case R_AARCH64_LDST64_ABS_LO12_NC:
                type = "R_AARCH64_LDST64_ABS_LO12_NC";
                break;
            case R_AARCH64_MOVW_PREL_G0:
                type = "R_AARCH64_MOVW_PREL_G0";
                break;
            case R_AARCH64_MOVW_PREL_G0_NC:
                type = "R_AARCH64_MOVW_PREL_G0_NC";
                break;
            case R_AARCH64_MOVW_PREL_G1:
                type = "R_AARCH64_MOVW_PREL_G1";
                break;
            case R_AARCH64_MOVW_PREL_G1_NC:
                type = "R_AARCH64_MOVW_PREL_G1_NC";
                break;
            case R_AARCH64_MOVW_PREL_G2:
                type = "R_AARCH64_MOVW_PREL_G2";
                break;
            case R_AARCH64_MOVW_PREL_G2_NC:
                type = "R_AARCH64_MOVW_PREL_G2_NC";
                break;
            case R_AARCH64_MOVW_PREL_G3:
                type = "R_AARCH64_MOVW_PREL_G3";
                break;
            case R_AARCH64_LDST128_ABS_LO12_NC:
                type = "R_AARCH64_LDST128_ABS_LO12_NC";
                break;
            case R_AARCH64_MOVW_GOTOFF_G0:
                type = "R_AARCH64_MOVW_GOTOFF_G0";
                break;
            case R_AARCH64_MOVW_GOTOFF_G0_NC:
                type = "R_AARCH64_MOVW_GOTOFF_G0_NC";
                break;
            case R_AARCH64_MOVW_GOTOFF_G1:
                type = "R_AARCH64_MOVW_GOTOFF_G1";
                break;
            case R_AARCH64_MOVW_GOTOFF_G1_NC:
                type = "R_AARCH64_MOVW_GOTOFF_G1_NC";
                break;
            case R_AARCH64_MOVW_GOTOFF_G2:
                type = "R_AARCH64_MOVW_GOTOFF_G2";
                break;
            case R_AARCH64_MOVW_GOTOFF_G2_NC:
                type = "R_AARCH64_MOVW_GOTOFF_G2_NC";
                break;
            case R_AARCH64_MOVW_GOTOFF_G3:
                type = "R_AARCH64_MOVW_GOTOFF_G3";
                break;
            case R_AARCH64_GOTREL64:
                type = "R_AARCH64_GOTREL64";
                break;
            case R_AARCH64_GOTREL32:
                type = "R_AARCH64_GOTREL32";
                break;
            case R_AARCH64_GOT_LD_PREL19:
                type = "R_AARCH64_GOT_LD_PREL19";
                break;
            case R_AARCH64_LD64_GOTOFF_LO15:
                type = "R_AARCH64_LD64_GOTOFF_LO15";
                break;
            case R_AARCH64_ADR_GOT_PAGE:
                type = "R_AARCH64_ADR_GOT_PAGE";
                break;
            case R_AARCH64_LD64_GOT_LO12_NC:
                type = "R_AARCH64_LD64_GOT_LO12_NC";
                break;
            case R_AARCH64_LD64_GOTPAGE_LO15:
                type = "R_AARCH64_LD64_GOTPAGE_LO15";
                break;
            case R_AARCH64_TLSGD_ADR_PREL21:
                type = "R_AARCH64_TLSGD_ADR_PREL21";
                break;
            case R_AARCH64_TLSGD_ADR_PAGE21:
                type = "R_AARCH64_TLSGD_ADR_PAGE21";
                break;
            case R_AARCH64_TLSGD_ADD_LO12_NC:
                type = "R_AARCH64_TLSGD_ADD_LO12_NC";
                break;
            case R_AARCH64_TLSGD_MOVW_G1:
                type = "R_AARCH64_TLSGD_MOVW_G1";
                break;
            case R_AARCH64_TLSGD_MOVW_G0_NC:
                type = "R_AARCH64_TLSGD_MOVW_G0_NC";
                break;
            case R_AARCH64_TLSLD_ADR_PREL21:
                type = "R_AARCH64_TLSLD_ADR_PREL21";
                break;
            case R_AARCH64_TLSLD_ADR_PAGE21:
                type = "R_AARCH64_TLSLD_ADR_PAGE21";
                break;
            case R_AARCH64_TLSLD_ADD_LO12_NC:
                type = "R_AARCH64_TLSLD_ADD_LO12_NC";
                break;
            case R_AARCH64_TLSLD_MOVW_G1:
                type = "R_AARCH64_TLSLD_MOVW_G1";
                break;
            case R_AARCH64_TLSLD_MOVW_G0_NC:
                type = "R_AARCH64_TLSLD_MOVW_G0_NC";
                break;
            case R_AARCH64_TLSLD_LD_PREL19:
                type = "R_AARCH64_TLSLD_LD_PREL19";
                break;
            case R_AARCH64_TLSLD_MOVW_DTPREL_G2:
                type = "R_AARCH64_TLSLD_MOVW_DTPREL_G2";
                break;
            case R_AARCH64_TLSLD_MOVW_DTPREL_G1:
                type = "R_AARCH64_TLSLD_MOVW_DTPREL_G1";
                break;
            /* TLS Local Dynamic (TLSLD) relocations */
            case R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC:
                type = "R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC";
                break;
            case R_AARCH64_TLSLD_MOVW_DTPREL_G0:
                type = "R_AARCH64_TLSLD_MOVW_DTPREL_G0";
                break;
            case R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC:
                type = "R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC";
                break;
            case R_AARCH64_TLSLD_ADD_DTPREL_HI12:
                type = "R_AARCH64_TLSLD_ADD_DTPREL_HI12";
                break;
            case R_AARCH64_TLSLD_ADD_DTPREL_LO12:
                type = "R_AARCH64_TLSLD_ADD_DTPREL_LO12";
                break;
            case R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC:
                type = "R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC";
                break;
            case R_AARCH64_TLSLD_LDST8_DTPREL_LO12:
                type = "R_AARCH64_TLSLD_LDST8_DTPREL_LO12";
                break;
            case R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC:
                type = "R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC";
                break;
            case R_AARCH64_TLSLD_LDST16_DTPREL_LO12:
                type = "R_AARCH64_TLSLD_LDST16_DTPREL_LO12";
                break;
            case R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC:
                type = "R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC";
                break;
            case R_AARCH64_TLSLD_LDST32_DTPREL_LO12:
                type = "R_AARCH64_TLSLD_LDST32_DTPREL_LO12";
                break;
            case R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC:
                type = "R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC";
                break;
            case R_AARCH64_TLSLD_LDST64_DTPREL_LO12:
                type = "R_AARCH64_TLSLD_LDST64_DTPREL_LO12";
                break;
            case R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC:
                type = "R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC";
                break;
            /* TLS Initial Exec (TLSIE) relocations */
            case R_AARCH64_TLSIE_MOVW_GOTTPREL_G1:
                type = "R_AARCH64_TLSIE_MOVW_GOTTPREL_G1";
                break;
            case R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC:
                type = "R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC";
                break;
            case R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21:
                type = "R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21";
                break;
            case R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC:
                type = "R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC";
                break;
            case R_AARCH64_TLSIE_LD_GOTTPREL_PREL19:
                type = "R_AARCH64_TLSIE_LD_GOTTPREL_PREL19";
                break;
            /* TLS Local Exec (TLSLE) relocations */
            case R_AARCH64_TLSLE_MOVW_TPREL_G2:
                type = "R_AARCH64_TLSLE_MOVW_TPREL_G2";
                break;
            case R_AARCH64_TLSLE_MOVW_TPREL_G1:
                type = "R_AARCH64_TLSLE_MOVW_TPREL_G1";
                break;
            case R_AARCH64_TLSLE_MOVW_TPREL_G1_NC:
                type = "R_AARCH64_TLSLE_MOVW_TPREL_G1_NC";
                break;
            case R_AARCH64_TLSLE_MOVW_TPREL_G0:
                type = "R_AARCH64_TLSLE_MOVW_TPREL_G0";
                break;
            case R_AARCH64_TLSLE_MOVW_TPREL_G0_NC:
                type = "R_AARCH64_TLSLE_MOVW_TPREL_G0_NC";
                break;
            case R_AARCH64_TLSLE_ADD_TPREL_HI12:
                type = "R_AARCH64_TLSLE_ADD_TPREL_HI12";
                break;
            case R_AARCH64_TLSLE_ADD_TPREL_LO12:
                type = "R_AARCH64_TLSLE_ADD_TPREL_LO12";
                break;
            case R_AARCH64_TLSLE_ADD_TPREL_LO12_NC:
                type = "R_AARCH64_TLSLE_ADD_TPREL_LO12_NC";
                break;
            case R_AARCH64_TLSLE_LDST8_TPREL_LO12:
                type = "R_AARCH64_TLSLE_LDST8_TPREL_LO12";
                break;
            case R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC:
                type = "R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC";
                break;
            case R_AARCH64_TLSLE_LDST16_TPREL_LO12:
                type = "R_AARCH64_TLSLE_LDST16_TPREL_LO12";
                break;
            case R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC:
                type = "R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC";
                break;
            case R_AARCH64_TLSLE_LDST32_TPREL_LO12:
                type = "R_AARCH64_TLSLE_LDST32_TPREL_LO12";
                break;
            case R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC:
                type = "R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC";
                break;
            case R_AARCH64_TLSLE_LDST64_TPREL_LO12:
                type = "R_AARCH64_TLSLE_LDST64_TPREL_LO12";
                break;
            case R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC:
                type = "R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC";
                break;
            /* TLSDESC relocations */
            case R_AARCH64_TLSDESC_LD_PREL19:
                type = "R_AARCH64_TLSDESC_LD_PREL19";
                break;
            case R_AARCH64_TLSDESC_ADR_PREL21:
                type = "R_AARCH64_TLSDESC_ADR_PREL21";
                break;
            case R_AARCH64_TLSDESC_ADR_PAGE21:
                type = "R_AARCH64_TLSDESC_ADR_PAGE21";
                break;
            case R_AARCH64_TLSDESC_LD64_LO12:
                type = "R_AARCH64_TLSDESC_LD64_LO12";
                break;
            case R_AARCH64_TLSDESC_ADD_LO12:
                type = "R_AARCH64_TLSDESC_ADD_LO12";
                break;
            case R_AARCH64_TLSDESC_OFF_G1:
                type = "R_AARCH64_TLSDESC_OFF_G1";
                break;
            case R_AARCH64_TLSDESC_OFF_G0_NC:
                type = "R_AARCH64_TLSDESC_OFF_G0_NC";
                break;
            case R_AARCH64_TLSDESC_LDR:
                type = "R_AARCH64_TLSDESC_LDR";
                break;
            case R_AARCH64_TLSDESC_ADD:
                type = "R_AARCH64_TLSDESC_ADD";
                break;
            case R_AARCH64_TLSDESC_CALL:
                type = "R_AARCH64_TLSDESC_CALL";
                break;
            /* 128-bit TLS relocations */
            case R_AARCH64_TLSLE_LDST128_TPREL_LO12:
                type = "R_AARCH64_TLSLE_LDST128_TPREL_LO12";
                break;
            case R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC:
                type = "R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC";
                break;
            case R_AARCH64_TLSLD_LDST128_DTPREL_LO12:
                type = "R_AARCH64_TLSLD_LDST128_DTPREL_LO12";
                break;
            case R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC:
                type = "R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC";
                break;
#endif
            /* Dynamic relocations */
            case R_AARCH64_COPY:
                type = "R_AARCH64_COPY";
                break;
            case R_AARCH64_GLOB_DAT:
                type = "R_AARCH64_GLOB_DAT";
                break;
            case R_AARCH64_JUMP_SLOT:
                type = "R_AARCH64_JUMP_SLOT";
                break;
            case R_AARCH64_RELATIVE:
                type = "R_AARCH64_RELATIVE";
                break;
            case R_AARCH64_TLS_DTPMOD:
                type = "R_AARCH64_TLS_DTPMOD";
                break;
            case R_AARCH64_TLS_DTPREL:
                type = "R_AARCH64_TLS_DTPREL";
                break;
            case R_AARCH64_TLS_TPREL:
                type = "R_AARCH64_TLS_TPREL";
                break;
            case R_AARCH64_TLSDESC:
                type = "R_AARCH64_TLSDESC";
                break;
#ifndef OHOS
            case R_AARCH64_IRELATIVE:
                type = "R_AARCH64_IRELATIVE";
                break;
#endif            
            default:
                break;
        }

        str_index = ELF64_R_SYM(rela_dyn[i].r_info);
        if (str_index > string_count) {
            PRINT_WARNING("Unknown file format or too many strings\n");
            break;
        }
        char tmp_name[MAX_PATH_LEN] = {0};
        if (strlen(dyn_string[str_index]) == 0) {
            /* .rela.dyn */
            if (str_index == 0) {
                snprintf(tmp_name, MAX_PATH_LEN, "%x", rela_dyn[i].r_addend);
            } 
            /* .o file .rela.text */
            else {
                snprintf(tmp_name, MAX_PATH_LEN, "%s %d", sym_string[str_index], rela_dyn[i].r_addend);
            }
        }
        /* .rela.plt */
        else if (rela_dyn[i].r_addend >= 0)
            snprintf(tmp_name, MAX_PATH_LEN, "%s + %d", dyn_string[str_index], rela_dyn[i].r_addend);
        else
            snprintf(tmp_name, MAX_PATH_LEN, "%s %d", dyn_string[str_index], rela_dyn[i].r_addend);

        PRINT_RELA(i, rela_dyn[i].r_offset, rela_dyn[i].r_info, type, str_index, tmp_name);
    }

    if (dyn_string) free(dyn_string);
    if (sym_string) free(sym_string);
}

/** 
 * @brief 显示ELF相关节包含的指针
 * display .init_array .finit_array .ctors .dtors	
 * @param h 
 * @param section_name 
 * @return int error code {-1:error,0:sucess}
 */
static int display_pointer32(Elf *elf, int num, ...) {
    char *name = NULL;
    int index[10];
    int strtab_index = 0;
    size_t count = 0;

    for (int i = 0; i < 10; i++) {
        index[i] = 0;
    }

    for (int i = 0; i < elf->data.elf32.ehdr->e_shnum; i++) {
        name = elf->mem + elf->data.elf32.shstrtab->sh_offset + elf->data.elf32.shdr[i].sh_name;
        if (validated_offset((uintptr_t)name, (uintptr_t)elf->mem, (uintptr_t)elf->mem + elf->size)) {
            PRINT_ERROR("Corrupt file format\n");
            return -1;
        }

        va_list args;                       // 定义一个 va_list 类型的变量
        va_start(args, num);                // 初始化可变参数列表

        for (int j = 0; j < num; j++) {
            char *section_name = va_arg(args, char *); // 从可变参数列表中获取参数值
            if (!strcmp(name, section_name)) {
                index[j] = i;
            }
        }

        va_end(args);                       // 结束可变参数列表的使用

        // 判断是否存在符号表
        // determine whether there is a symbol table
        if (!strcmp(name, ".strtab")) {
            strtab_index = i;
        }
    }

    va_list args;
    va_start(args, num);

    for (int j = 0; j < num; j++) {
        char *section_name = va_arg(args, char *);
        if (index[j] == 0) {
            PRINT_DEBUG("This file does not have a %s\n", section_name);
        } else {
            uint32_t offset = elf->data.elf32.shdr[index[j]].sh_offset;
            size_t size = elf->data.elf32.shdr[index[j]].sh_size;
            uint32_t *addr = (uint32_t *)(elf->mem + offset);
            int count = size / sizeof(uint32_t);
            PRINT_INFO("%s section at offset 0x%x contains %d pointers:\n", section_name, offset, count);
            PRINT_POINTER32_TITLE("Nr", "Pointer", "Symbol");
            for (int i = 0; i < count; i++) {
                if (strtab_index) {
                                        int find_sym = 0;
                    char *name = NULL;
                    for (int k = 0; k < elf->data.elf32.sym_count; k++) {
                        if (elf->data.elf32.sym_entry[k].st_value == addr[k]) {
                            name = elf->mem + elf->data.elf32.strtab->sh_offset + elf->data.elf32.sym_entry[k].st_name;
                            find_sym = 1;
                            break;
                        }
                    }
                    if (!find_sym) {
                        for (int k = 0; k < elf->data.elf32.dynsym_count; k++) {
                            if (elf->data.elf32.dynsym_entry[k].st_value == addr[k]) {
                                name = elf->mem + elf->data.elf32.dynstrtab->sh_offset + elf->data.elf32.dynsym_entry[k].st_name;
                                find_sym = 1;
                                break;
                            }
                        }
                    }
                    
                    if (find_sym) {
                        PRINT_POINTER32(i, addr[i], name);
                    } else {
                        PRINT_POINTER32(i, addr[i], "0");
                    }
                } else {
                    PRINT_POINTER32(i, addr[i], "0");
                }
            }
        }
    }

    va_end(args);
}

/** 
 * @brief 显示ELF相关节包含的指针
 * display .init_array .finit_array .ctors .dtors	
 * @param h 
 * @param section_name 
 * @return int error code {-1:error,0:sucess}
 */
static int display_pointer64(Elf *elf, int num, ...) {
    char *name = NULL;
    int index[10];
    int strtab_index = 0;
    size_t count = 0;

    for (int i = 0; i < 10; i++) {
        index[i] = 0;
    }

    for (int i = 0; i < elf->data.elf64.ehdr->e_shnum; i++) {
        name = elf->mem + elf->data.elf64.shstrtab->sh_offset + elf->data.elf64.shdr[i].sh_name;
        if (validated_offset((uintptr_t)name, (uintptr_t)elf->mem, (uintptr_t)elf->mem + elf->size)) {
            PRINT_ERROR("Corrupt file format\n");
            return -1;
        }

        va_list args;                       // 定义一个 va_list 类型的变量
        va_start(args, num);                // 初始化可变参数列表

        for (int j = 0; j < num; j++) {
            char *section_name = va_arg(args, char *); // 从可变参数列表中获取参数值
            if (!strcmp(name, section_name)) {
                index[j] = i;
            }
        }

        va_end(args);                       // 结束可变参数列表的使用

        // 判断是否存在符号表
        // determine whether there is a symbol table
        if (!strcmp(name, ".strtab")) {
            strtab_index = i;
        }
    }

    va_list args;
    va_start(args, num);

    for (int j = 0; j < num; j++) {
        char *section_name = va_arg(args, char *);
        if (index[j] == 0) {
            PRINT_DEBUG("This file does not have a %s\n", section_name);
        } else {
            uint64_t offset = elf->data.elf64.shdr[index[j]].sh_offset;
            size_t size = elf->data.elf64.shdr[index[j]].sh_size;
            uint64_t *addr = (uint64_t *)(elf->mem + offset);
            int count = size / sizeof(uint64_t);
            PRINT_INFO("%s section at offset 0x%x contains %d pointers:\n", section_name, offset, count);
            PRINT_POINTER64_TITLE("Nr", "Pointer", "Symbol");
            for (int i = 0; i < count; i++) {
                if (strtab_index) {
                    int find_sym = 0;
                    char *name = NULL;
                    for (int k = 0; k < elf->data.elf64.sym_count; k++) {
                        if (elf->data.elf64.sym_entry[k].st_value == addr[k]) {
                            name = elf->mem + elf->data.elf64.strtab->sh_offset + elf->data.elf64.sym_entry[k].st_name;
                            find_sym = 1;
                            break;
                        }
                    }
                    if (!find_sym) {
                        for (int k = 0; k < elf->data.elf64.dynsym_count; k++) {
                            if (elf->data.elf64.dynsym_entry[k].st_value == addr[k]) {
                                name = elf->mem + elf->data.elf64.dynstrtab->sh_offset + elf->data.elf64.dynsym_entry[k].st_name;
                                find_sym = 1;
                                break;
                            }
                        }
                    }
                    
                    if (find_sym) {
                        PRINT_POINTER64(i, addr[i], name);
                    } else {
                        PRINT_POINTER64(i, addr[i], "0");
                    }
                } else {
                    PRINT_POINTER64(i, addr[i], "0");
                }
            }
        }
    }

    va_end(args);
}

/**
 * @brief 显示gnu hash表
 * show hash table
 * @param h
 * @return int error code {-1:error,0:sucess}
 */
int display_hash32(Elf *elf) {
    char *name = NULL;
    int hash_index = 0;

    for (int i = 0; i < elf->data.elf32.ehdr->e_shnum; i++) {
        name = elf->mem + elf->data.elf32.shstrtab->sh_offset + elf->data.elf32.shdr[i].sh_name;
        if (validated_offset((uintptr_t)name, (uintptr_t)elf->mem, (uintptr_t)elf->mem + elf->size)) {
            PRINT_ERROR("Corrupt file format\n");
            exit(-1);
        }

        if (!strcmp(name, ".gnu.hash")) {
            hash_index = i;
        }
    }

    if (!hash_index) {
        PRINT_DEBUG("This file does not have a %s\n", ".gnu.hash");
        return -1;
    }
    
    name = elf->mem + elf->data.elf32.shdr[hash_index].sh_offset;
    /* security check start*/
    if (validated_offset((uintptr_t)name, (uintptr_t)elf->mem, (uintptr_t)elf->mem + elf->size)) {
        PRINT_ERROR("Corrupt file format\n");
        exit(-1);
    }

    char **dyn_string = NULL;
    int string_count = 0;
    int err = get_dyn_string_table(elf, &dyn_string, &string_count);
    if (err != NO_ERR) {
        PRINT_DEBUG("get dynamic symbol string table error\n");
        return err;
    }
    free(dyn_string);

    gnuhash_t *hash = (gnuhash_t *)&elf->mem[elf->data.elf32.shdr[hash_index].sh_offset];
    PRINT_INFO(".gnu.hash table at offset 0x%x\n", elf->data.elf32.shdr[hash_index].sh_offset);
    printf("    |-------------Header-------------|\n");
    printf("    |nbuckets:             0x%08x|\n", hash->nbuckets);
    printf("    |symndx:               0x%08x|\n", hash->symndx);
    printf("    |maskbits:             0x%08x|\n", hash->maskbits);
    printf("    |shift:                0x%08x|\n", hash->shift);
    
    printf("    |-----------Bloom filter---------|\n");
    uint32_t *bloomfilter = hash->buckets;
    int i;
    for (i = 0; i < hash->maskbits; i++) {
        printf("    |           0x%08x           |\n", bloomfilter[i]);
    }

    printf("    |-----------Hash Buckets---------|\n");
    uint32_t *buckets = &bloomfilter[i];
    for (i = 0; i < hash->nbuckets; i++) {
        printf("    |           0x%08x           |\n", buckets[i]);
    }

    printf("    |-----------Hash Chain-----------|\n");
    uint32_t *value = &buckets[i];
    for (i = 0; i < string_count - hash->symndx; i++) {
        printf("    |           0x%08x           |\n", value[i]);
    }
    printf("    |--------------------------------|\n");
}

/**
 * @brief 显示gnu hash表
 * show hash table
 * @param h
 * @return int error code {-1:error,0:sucess}
 */
int display_hash64(Elf *elf) {
    char *name = NULL;
    int hash_index = 0;

    for (int i = 0; i < elf->data.elf64.ehdr->e_shnum; i++) {
        name = elf->mem + elf->data.elf64.shstrtab->sh_offset + elf->data.elf64.shdr[i].sh_name;
        if (validated_offset((uintptr_t)name, (uintptr_t)elf->mem, (uintptr_t)elf->mem + elf->size)) {
            PRINT_ERROR("Corrupt file format\n");
            exit(-1);
        }

        if (!strcmp(name, ".gnu.hash")) {
            hash_index = i;
        }
    }

    if (!hash_index) {
        PRINT_DEBUG("This file does not have a %s\n", ".gnu.hash");
        return -1;
    }
    
    name = elf->mem + elf->data.elf64.shdr[hash_index].sh_offset;
    /* security check start*/
    if (validated_offset((uintptr_t)name, (uintptr_t)elf->mem, (uintptr_t)elf->mem + elf->size)) {
        PRINT_ERROR("Corrupt file format\n");
        exit(-1);
    }

    char **dyn_string = NULL;
    int string_count = 0;
    int err = get_dyn_string_table(elf, &dyn_string, &string_count);
    if (err != NO_ERR) {
        PRINT_DEBUG("get dynamic symbol string table error\n");
        return err;
    }
    free(dyn_string);

    gnuhash_t *hash = (gnuhash_t *)&elf->mem[elf->data.elf64.shdr[hash_index].sh_offset];
    PRINT_INFO(".gnu.hash table at offset 0x%x\n", elf->data.elf64.shdr[hash_index].sh_offset);
    printf("    |-------------Header-------------|\n");
    printf("    |nbuckets:             0x%08x|\n", hash->nbuckets);
    printf("    |symndx:               0x%08x|\n", hash->symndx);
    printf("    |maskbits:             0x%08x|\n", hash->maskbits);
    printf("    |shift:                0x%08x|\n", hash->shift);
    
    printf("    |-----------Bloom filter---------|\n");
    uint64_t *bloomfilter = (uint64_t *)hash->buckets;
    int i;
    for (i = 0; i < hash->maskbits; i++) {
        printf("    |       0x%016x       |\n", bloomfilter[i]);
    }

    printf("    |-----------Hash Buckets---------|\n");
    uint32_t *buckets = (uint32_t *)&bloomfilter[i];
    for (i = 0; i < hash->nbuckets; i++) {
        printf("    |           0x%08x           |\n", buckets[i]);
    }

    printf("    |-----------Hash Chain-----------|\n");
    uint32_t *value = &buckets[i];
    for (i = 0; i < string_count - hash->symndx; i++) {
        printf("    |           0x%08x           |\n", value[i]);
    }
    printf("    |--------------------------------|\n");
}

int parse(Elf *elf, parser_opt_t *po, uint32_t length) {
    if (!length) {
        truncated_length = 15;
    } else {
        truncated_length = length;
    }

    /* 32bit */
    if (elf->class == ELFCLASS32) {
        /* ELF Header Information */
        if (!get_option(po, HEADERS) || !get_option(po, ALL))    
            display_header32(elf);
        
        /* Section Information */
        if (!get_option(po, SECTIONS) || !get_option(po, ALL))
            display_section32(elf);

        /* Segmentation Information */
        if (!get_option(po, SEGMENTS) || !get_option(po, ALL))
            display_segment32(elf);

        /* .dynsym information */
        if (!get_option(po, DYNSYM) || !get_option(po, ALL)){
            display_dynsym32(elf, ".dynsym", ".dynstr");
        }

        /* .symtab information */
        if (!get_option(po, SYMTAB) || !get_option(po, ALL)){
            display_dynsym32(elf, ".symtab", ".strtab");
        }

        /* .dynamic Infomation */
        if (!get_option(po, LINK) || !get_option(po, ALL))
            display_dyninfo32(elf);  

        /* .rela.dyn .rela.plt Infomation */
        if (!get_option(po, RELA) || !get_option(po, ALL)) {
            for (int i = 0; i < elf->data.elf32.ehdr->e_shnum; i++) {
                char *section_name = elf->mem + elf->data.elf32.shstrtab->sh_offset + elf->data.elf32.shdr[i].sh_name;
                if (compare_firstN_chars(section_name, ".rela", 5)) {
                    display_rela32(elf, section_name);
                } else if (compare_firstN_chars(section_name, ".rel", 4)){
                    display_rel32(elf, section_name);
                }
            }
        }

        /* elf pointer */
        if (!get_option(po, POINTER) || !get_option(po, ALL)) {
            display_pointer32(elf, 5, ".init_array", ".fini_array", ".ctors", ".dtors", ".eh_frame_hdr");  
        }

        /* elf .gnu.hash */
        if (!get_option(po, GNUHASH) || !get_option(po, ALL)) {
            display_hash32(elf);
        }       
    }

    /* 64bit */
    if (elf->class == ELFCLASS64) {
        /* ELF Header Information */
        if (!get_option(po, HEADERS) || !get_option(po, ALL)) 
            display_header64(elf);

        /* Section Information */
        if (!get_option(po, SECTIONS) || !get_option(po, ALL))
            display_section64(elf);

        /* Segmentation Information */
        if (!get_option(po, SEGMENTS) || !get_option(po, ALL))
            display_segment64(elf);

        /* .dynsym information */
        if (!get_option(po, DYNSYM) || !get_option(po, ALL)){
            display_sym64(elf, ".dynsym", ".dynstr");
        }

        /* .symtab information */
        if (!get_option(po, SYMTAB) || !get_option(po, ALL)){
            display_sym64(elf, ".symtab", ".strtab");
        }

        /* .dynamic Infomation */
        if (!get_option(po, LINK) || !get_option(po, ALL))
            display_dyninfo64(elf);      

        /* .rela.dyn .rela.plt Infomation */
        if (!get_option(po, RELA) || !get_option(po, ALL)) {
            for (int i = 0; i < elf->data.elf64.ehdr->e_shnum; i++) {
                char *section_name = elf->mem + elf->data.elf64.shstrtab->sh_offset + elf->data.elf64.shdr[i].sh_name;
                if (compare_firstN_chars(section_name, ".rela", 5)) {
                    display_rela64(elf, section_name);
                } else if (compare_firstN_chars(section_name, ".rel", 4)){
                    display_rel64(elf, section_name);
                }
            }
        }
        
        /* elf pointer */
        if (!get_option(po, POINTER) || !get_option(po, ALL)) {
            display_pointer64(elf, 5, ".init_array", ".fini_array", ".ctors", ".dtors", ".eh_frame_hdr");
        }

        /* elf .gnu.hash */
        if (!get_option(po, GNUHASH) || !get_option(po, ALL)) {
            display_hash64(elf);
        }
    } else {
        return ERR_ELF_CLASS;
    }

    return NO_ERR;
}
