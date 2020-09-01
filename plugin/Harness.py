# @category: GEARSHIFT.internal

linux_template = """#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdint.h>

{structs}

typedef int(*func)(void* a, ...);

int main(int argc, char** argv) {{
	void* handler = dlopen("{process_path}", RTLD_LAZY);
	void* base = *((void**)handler);
	func f = (func)(base + {func_offset});

	FILE* h = fopen(argv[1], "r");

{code}

	int res = f((void*){args});

{cleanup}

	printf("Result: %d\\n", res);
}}
"""

peldr_path = "D:/CTF/research/gearshift/windows/peldr64.dll"

windows_template = """#include <iostream>
#include <windows.h>

typedef HMODULE(__stdcall* load_lib_func)(const std::string);

{structs}

int target_func(char*);
typedef int(__stdcall* atoi32)(...);

int main(int argc, char** argv) {{
	std::cout << "HI" << std::endl;
	LPCWSTR path = L"{peldr_path}";
	HMODULE h = LoadLibrary(path);
	if (!h) {{
		std::cout << "Load Library failed " << GetLastError() << std::endl;
	}}

	LPCSTR func = "load_library";
	load_lib_func f = (load_lib_func)GetProcAddress(h, func);
	if (!f) {{
		std::cout << "Get function failed " << GetLastError() << std::endl;
	}}

	const std::string exepath = "{process_path}";
	HMODULE sice = f(exepath);
	if (!sice) {{
		std::cout << "Returned 0" << std::endl;
	}}
	std::cout << sice << std::endl;

	target_func(argv[1]);
}}

__declspec(noinline) int target_func(char* fpath) {{
	FILE* h = 0;
	
	fopen_s(&h, fpath, "r");

{code}

	atoi32 aa = (atoi32){func_addr};
	int res = aa({args});

{cleanup}

	printf("Result: %d\\n", res);
	fclose(h);
	return res;
}}"""

def generate_linux_harness(struct_defs, ppath, func_off, code, cleanup, args):
	return linux_template.format(structs=struct_defs, process_path=ppath, func_offset=func_off, code="\t" + code.replace("\n", "\n\t"), cleanup="\t" + cleanup.replace("\n", "\n\t"), args=args)

def generate_windows_harness(struct_defs, ppath, func_addr, code, cleanup, args):
	return windows_template.format(peldr_path=peldr_path, structs=struct_defs, process_path=ppath, func_addr=func_addr, args=args, code="\t" + code.replace("\n", "\n\t"), cleanup="\t" + cleanup.replace("\n", "\n\t"))