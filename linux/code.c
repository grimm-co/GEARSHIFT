#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdint.h>

typedef struct {
	uint32_t entry_0;
	uint32_t entry_1;
	uint32_t entry_2;
	uint64_t entry_3;
} V2;
typedef struct {
	char* entry_0;
	uint64_t entry_1;
	V2* entry_2;
	V2* entry_3;
} V1;
typedef struct {
	uint32_t entry_0;
	uint32_t entry_1;
	V1* entry_2;
} VRDI0;


typedef int(*func)(void* a, ...);

int main(int argc, char** argv) {
	void* handler = dlopen("/mnt/d/CTF/research/gearshift/linux/case1", RTLD_LAZY);
	void* base = *((void**)handler);
	func f = (func)(base + 0x88e);

	FILE* h = fopen(argv[1], "r");

	VRDI0* VRDI;
	VRDI = (VRDI0*)malloc(16);
	fread((char*)&VRDI->entry_0, 1, 4, h);
	fread((char*)&VRDI->entry_1, 1, 4, h);
	VRDI->entry_2 = (V1*)malloc(32);
	VRDI->entry_2->entry_0 = (char*)malloc(7);
	VRDI->entry_2->entry_0[6] = 0;
	fread(VRDI->entry_2->entry_0, 1, 6, h);
	fread((char*)&VRDI->entry_2->entry_1, 1, 8, h);
	VRDI->entry_2->entry_2 = (V2*)malloc(20);
	fread((char*)&VRDI->entry_2->entry_2->entry_0, 1, 4, h);
	fread((char*)&VRDI->entry_2->entry_2->entry_1, 1, 4, h);
	fread((char*)&VRDI->entry_2->entry_2->entry_2, 1, 4, h);
	fread((char*)&VRDI->entry_2->entry_2->entry_3, 1, 8, h);
	VRDI->entry_2->entry_3 = (V2*)malloc(20);
	fread((char*)&VRDI->entry_2->entry_3->entry_0, 1, 4, h);
	fread((char*)&VRDI->entry_2->entry_3->entry_1, 1, 4, h);
	fread((char*)&VRDI->entry_2->entry_3->entry_2, 1, 4, h);
	fread((char*)&VRDI->entry_2->entry_3->entry_3, 1, 8, h);
	

	int res = f((void*)VRDI);
	printf("Result: %d\n", res);
}
