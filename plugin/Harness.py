#!/usr/bin/env python3
# @category: GEARSHIFT.internal

linux_template = r"""#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdint.h>

{structs}

typedef int(*func)(void* a, ...);

int main(int argc, char** argv) {{
        if (argc < 2) {{
                if (argc < 1) {{
                        printf("Usage: ./gearshift_harness_linux input_file\n");
                }} else {{
                        printf("Usage: %s input_file\n", argv[0]);
                }}
                printf("\n");
                printf("\tinput_file - data to put into the arguments\n");
                printf("\n");
                return 1;
        }}
	void* handle = dlopen("{process_path}", RTLD_LAZY);
        if (handle == NULL) {{
                printf("Unable to open {process_path}. Exiting.\n");
                return 2;
        }}
	// In glibc, the handle points to the library base address
	char* base = *((char**)handle);
	func f = (func)(base + 0x{func_offset:x});

	FILE* h = fopen(argv[1], "r");
        if (h == NULL) {{
                printf("Unable to open %s. Exiting.\n", argv[1]);
                return 3;
        }}

{code}

	int res = f((void*){args});

{cleanup}

	printf("Result: %d\n", res);
}}
"""

windows_template = r"""#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <windows.h>

{structs}

typedef int(*func)(void* a, ...);

int main(int argc, char** argv) {{
        if (argc < 2) {{
                if (argc < 1) {{
                        printf("Usage: gearshift_harness_windows input_file\n");
                }} else {{
                        printf("Usage: %s input_file\n", argv[0]);
                }}
                printf("\n");
                printf("\tinput_file - data to put into the arguments\n");
                printf("\n");
                return 1;
        }}
	HMODULE lib = LoadLibraryA("{process_path}");
	if (!lib) {{
		printf("Load Library failed: %d\n", GetLastError());
		exit(1);
	}}

	// On Windows, the handle is the library base address
	char* base = (char*)lib;
	func f = (func)(base + 0x{func_offset:x});

	FILE* h;
	fopen_s(&h, argv[1], "r");

{code}

	int res = f((void*){args});

{cleanup}

	printf("Result: %d\n", res);
}}
"""

def generate_linux_harness(struct_defs, ppath, func_off, code, cleanup, args):
	return linux_template.format(structs=struct_defs, process_path=ppath, func_offset=func_off, code="\t" + code.replace("\n", "\n\t"), cleanup="\t" + cleanup.replace("\n", "\n\t"), args=args)

def generate_windows_harness(struct_defs, ppath, func_off, code, cleanup, args):
	return windows_template.format(structs=struct_defs, process_path=ppath, func_offset=func_off, code="\t" + code.replace("\n", "\n\t"), cleanup="\t" + cleanup.replace("\n", "\n\t"), args=args)
