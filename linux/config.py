import os
import lief

x8664_args = ["VRDI", "VRSI", "VRDX"]
function_offset = 0x88e
ghidra_path = "/mnt/d/Programs/ghidra_9.1.2_PUBLIC"
ghidra_project_path = "/mnt/d/Programs/ghidra_9.1.2_PUBLIC/Projects"
project_name = "CTF"
process_name = "case1"
work_dir = "/mnt/d/CTF/research/gearshift/linux"
output_source = "code.c"
plugin_path = "/mnt/d/CTF/research/gearshift/SymbolicVSA.java"

process_path = os.path.join(work_dir, process_name)

template = """#include <stdio.h>
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
	printf("Result: %d\\n", res);
}}
"""

#D:\Programs\ghidra_9.1.2_PUBLIC\support\analyzeHeadless "D:\Programs\ghidra_9.1.2_PUBLIC\Projects" CTF -process case1.exe -postScript "D:\CTF\research\gearshift\SymbolicVSA.java"
if __name__ == "__main__":
	command = "{}/support/analyzeHeadless {} {} -process {} -postScript {}".format(ghidra_path, ghidra_project_path, project_name, process_name, plugin_path)
	print(command)
	os.system(command)
	os.system("python3 parser.py")
