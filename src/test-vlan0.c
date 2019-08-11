#include "vlan.h"
#include "cmdline.h"

#include <stdio.h>
#include <assert.h>

void dump_vlan(struct vlan_arr *arr) {
	char tmp[4096];
	int trunc = (sizeof(tmp) == vlan_dump(arr, tmp, sizeof(tmp)));
	printf("%s%s\n", tmp, trunc ? "..." : "");
}

int main(int argc, char *argv[])
{
	struct vlan_arr *arr, *arr0;

	parse_cmdline(argc, argv);

	char *argv2[2];
	argv2[0] = argv[0];
	argv2[1] = "--debug-all";
	parse_cmdline(2, argv2);

	arr = vlan_alloc("test0");
	vlan_set(arr, 32);
	vlan_set(arr, 1);
	vlan_set(arr, 16);
	dump_vlan(arr);
	vlan_free(arr);

	arr = vlan_alloc("test1");
	vlan_set(arr, 31);
	vlan_set(arr, 1);
	vlan_set(arr, 15);
	dump_vlan(arr);
	vlan_free(arr);

	arr = vlan_alloc("test2");
	vlan_set(arr, 1);
	vlan_set(arr, 31);
	vlan_set(arr, 15);
	dump_vlan(arr);
	vlan_free(arr);

	arr = vlan_alloc("test3");
	vlan_set(arr, 1024);
	vlan_set(arr, 1056);
	vlan_set(arr, 1040);
	dump_vlan(arr);
	vlan_free(arr);

	arr = vlan_alloc("test4");
	vlan_set(arr, 1024);
	vlan_set(arr, 1088);
	vlan_set(arr, 1056);
	dump_vlan(arr);
	vlan_free(arr);

	arr = vlan_alloc("test5");
	vlan_set(arr, 2048);
	vlan_set(arr, 1024);
	vlan_set(arr, 1088);
	vlan_set(arr, 1056);
	dump_vlan(arr);
	vlan_free(arr);

	arr = vlan_alloc("test6");
	vlan_set(arr, 2048);
	vlan_set(arr, 1024);
	vlan_set(arr, 1);
	dump_vlan(arr);
	vlan_free(arr);

	arr = vlan_alloc("test7");
	for (int i = 0; i < 64; i++)
		vlan_set(arr, i*32+1);
	vlan_test(arr, 30*32);
	dump_vlan(arr);
	vlan_free(arr);

	arr = vlan_alloc("test8a");
	for (int i = 0; i < 64; i++)
		vlan_set(arr, i*32+1);
	for (int i = 1; i < 4094; i++) {
		int wasset = vlan_test(arr, i);
		if (i % 32 == 1 && i < 64*32+1)
			assert(wasset);
		else
			assert(!wasset);
	}
	arr0 = vlan_clone(arr, "test8b");
	for (int i = 1; i < 4094; i++) {
		int wasset = vlan_test(arr0, i);
		if (i % 32 == 1 && i < 64*32+1)
			assert(wasset);
		else
			assert(!wasset);
	}
	for (int i = 0; i < 64; i++) {
		int wasset = vlan_unset(arr0, i*32+1);
		assert(wasset);
	}
	for (int i = 0; i < 64; i++) {
		int wasset = vlan_test(arr0, i*32+1);
		assert(!wasset);
	}
	{
		int wasset = vlan_test(arr0, 18*32);
		assert(!wasset);
	}
	dump_vlan(arr);
	dump_vlan(arr0);
	vlan_free(arr);
	vlan_free(arr0);

	int step = 48;
	int cnt = 16;
	arr = vlan_alloc("test9a");
	for (int i = 0; i < cnt; i++)
		vlan_set(arr, i*step+1);
	for (int i = 1; i < 4094; i++) {
		int wasset = vlan_test(arr, i);
		if (i % step == 1 && i < step*cnt+1)
			assert(wasset);
		else
			assert(!wasset);
	}
	arr0 = vlan_clone(arr, "test9b");
	for (int i = 1; i < 4094; i++) {
		int wasset = vlan_test(arr0, i);
		if (i % step == 1 && i < step*cnt+1)
			assert(wasset);
		else
			assert(!wasset);
	}
	for (int i = 0; i < cnt; i++) {
		int wasset = vlan_unset(arr0, i*step+1);
		assert(wasset);
	}
	for (int i = 0; i < cnt; i++) {
		int wasset = vlan_test(arr0, i*step+1);
		assert(!wasset);
	}
	for (int i = 0; i < cnt; i++) {
		int wasset0 = vlan_test(arr, i*step);
		assert(!wasset0);
		int wasset1 = vlan_test(arr, (cnt - 1)*step+1);
		assert(wasset1);
	}
	dump_vlan(arr);
	dump_vlan(arr0);
	vlan_free(arr);
	vlan_free(arr0);

}

