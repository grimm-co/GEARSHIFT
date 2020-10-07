# @category: GEARSHIFT.internal

linux_template = """#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdint.h>

{structs}

typedef int(*func)(void* a, ...);

int main(int argc, char** argv) {{
	void* handle = dlopen("{process_path}", RTLD_LAZY);
        // In glibc, the handle points to the library base address
	void* base = *((void**)handle);
	func f = (func)(base + {func_offset});

	FILE* h = fopen(argv[1], "r");

{code}

	int res = f((void*){args});

{cleanup}

	printf("Result: %d\\n", res);
}}
"""

peldr_path = "D:/CTF/research/gearshift/windows/peldr64.dll"

windows_template = """#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <windows.h>

{structs}

typedef int(*func)(void* a, ...);

int main(int argc, char** argv) {{
	HMODULE h = LoadLibraryA("{process_path}");
	if (!h) {{
		printf("Load Library failed: %d\n", GetLastError());
                exit(1);
	}}

        // On Windows, the handle is the library base address
        void* base = (void*)h;
	func f = (func)(base + {func_offset});

	FILE* h;
        fopen_s(&h, argv[1], "r");

{code}

	int res = f((void*){args});

{cleanup}

	printf("Result: %d\\n", res);
}}
"""

def generate_linux_harness(struct_defs, ppath, func_off, code, cleanup, args):
	return linux_template.format(structs=struct_defs, process_path=ppath, func_offset=func_off, code="\t" + code.replace("\n", "\n\t"), cleanup="\t" + cleanup.replace("\n", "\n\t"), args=args)

def generate_windows_harness(struct_defs, ppath, func_addr, code, cleanup, args):
	return windows_template.format(peldr_path=peldr_path, structs=struct_defs, process_path=ppath, func_addr=func_addr, args=args, code="\t" + code.replace("\n", "\n\t"), cleanup="\t" + cleanup.replace("\n", "\n\t"))
