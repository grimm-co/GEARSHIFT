#include <iostream>
#include <windows.h>

typedef HMODULE(__stdcall* load_lib_func)(const std::string);

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
} VRCX0;


int target_func(char*);
typedef int(__stdcall* atoi32)(...);

int main(int argc, char** argv) {
	std::cout << "HI" << std::endl;
	LPCWSTR path = L"D:\\CTF\\research\\gearshift\\windows\\peldr64.dll";
	HMODULE h = LoadLibrary(path);
	if (!h) {
		std::cout << "Load Library failed " << GetLastError() << std::endl;
	}

	LPCSTR func = "load_library";
	load_lib_func f = (load_lib_func)GetProcAddress(h, func);
	if (!f) {
		std::cout << "Get function failed " << GetLastError() << std::endl;
	}

	const std::string exepath = "D:\\CTF\\research\\gearshift\\windows\\case1.exe";
	HMODULE sice = f(exepath);
	if (!sice) {
		std::cout << "Returned 0" << std::endl;
	}
	std::cout << sice << std::endl;

	target_func(argv[1]);
}

__declspec(noinline) int target_func(char* fpath) {
	FILE* h = 0;
	
	fopen_s(&h, fpath, "r");
	VRCX0* VRCX;
	VRCX = (VRCX0*)malloc(16);
	fread((char*)&VRCX->entry_0, 1, 4, h);
	fread((char*)&VRCX->entry_1, 1, 4, h);
	VRCX->entry_2 = (V1*)malloc(32);
	VRCX->entry_2->entry_0 = (char*)malloc(7);
	VRCX->entry_2->entry_0[6] = 0;
	fread(VRCX->entry_2->entry_0, 1, 6, h);
	fread((char*)&VRCX->entry_2->entry_1, 1, 8, h);
	VRCX->entry_2->entry_2 = (V2*)malloc(20);
	fread((char*)&VRCX->entry_2->entry_2->entry_0, 1, 4, h);
	fread((char*)&VRCX->entry_2->entry_2->entry_1, 1, 4, h);
	fread((char*)&VRCX->entry_2->entry_2->entry_2, 1, 4, h);
	fread((char*)&VRCX->entry_2->entry_2->entry_3, 1, 8, h);
	VRCX->entry_2->entry_3 = (V2*)malloc(20);
	fread((char*)&VRCX->entry_2->entry_3->entry_0, 1, 4, h);
	fread((char*)&VRCX->entry_2->entry_3->entry_1, 1, 4, h);
	fread((char*)&VRCX->entry_2->entry_3->entry_2, 1, 4, h);
	fread((char*)&VRCX->entry_2->entry_3->entry_3, 1, 8, h);
	
	atoi32 aa = (atoi32)0x401631;
	int res = aa(VRCX);
	free(VRCX->entry_2->entry_0);
	printf("Result: %d\n", res);
	fclose(h);
	return res;
}