// dynamic link
// gcc testapi.c ../src/lib//elfutil.h -L../src/lib -lelfutil -o testapi
// static link
// gcc testapi.c ../src/lib/elfutil.h ../src/lib/elfutil.c ../src/lib/manager.c ../src/lib/util.c -g -fsanitize=address -o testapi
// run
// LD_LIBRARY_PATH=../src/ ./test ../src/elfspirit

#include <stdio.h>
#include "../src/lib/elfutil.h"

int main(int argc, char const *argv[])
{	

	Elf elf;
	init(argv[1], &elf);
	// /* testcase: get section information... */
	// printf("testcase 1: get section information...\n");
	// int addr = get_section_addr_by_name(&elf, ".bss");
	// int offset = get_section_offset_by_name(&elf, ".bss");
	// int size = get_section_size_by_name(&elf, ".bss");
	// printf("before: addr=%x, offset=%x, size=%x\n", addr, offset, size);
	// set_section_size_by_name(&elf, ".bss", 0x1234);
	// size = get_section_size_by_name(&elf, ".bss");
	// printf("after: addr=%x, offset=%x, size=%x\n", addr, offset, size);
	// printf("\n");

	// /* testcase: get segmentation information... */
	// printf("testcase 2: get segmentation information...\n");
	// int filesz = get_segment_filesz_by_index(&elf, 1);
	// printf("before: size=%x\n", filesz);
	// set_segment_filesz_by_index(&elf, 1, 0x8888);
	// filesz = get_segment_filesz_by_index(&elf, 1);
	// printf("after: size=%x\n", filesz);
	// printf("\n");

	// /* testcase: get section index in segmentation... */
	// printf("testcase 3: get section index of segment...\n");
	// int a[5] = {0};
	// int count=0;
	// count = get_section_index_in_segment(&elf, ".debug_info", a, sizeof(a)/sizeof(a[0]));
	// for (int i = 0; i < count; i++)
	// 	printf("a[%d]=%d\n", i, a[i]);

	/* testacse: expand segment... */
	// printf("testcase 4: expand segment...\n");
	// uint64_t offset = expand_segment_t(&elf, 1024);
	// if (offset == FALSE) {
	// 	printf("error!\n");
	// } else {
	// 	printf("offset=%x, size=%x\n", offset, 1024);
	// }

	/* testacse: set new section name... */
	// char *src_name = "strcmp";
	// char *dst_name = "strncmp";
	// int code = set_dynsym_name(&elf, src_name, dst_name);
	// if (code == TRUE) {
	// 	printf("change name %s to %s success\n", src_name, dst_name);
	// }

	/* testcase: set dynamic segment */
	// set_dynseg_tag_by_tag(&elf, DT_NULL, DT_NEEDED);

	/* testcase7 */
	// uint64_t offset = 0;
	// uint64_t addr = 0;
	// expand_segment_load(&elf, 5, 0x850, &offset, &addr);
	// printf("offset=0x%x, addr=0x%x\n", offset, addr);
	// int err = strip_t(&elf);
	// int err = delete_section_by_name(&elf, ".strtab");

	int err = add_elf_header((uint8_t *)argv[1], (uint8_t *)"x86", 64, (uint8_t *)"little", 0);
	print_error(err);
		
	finit(&elf);
	return 0;
}