import os

x8664_args = ["VRCX", "VRDX", "VR8"]
function_offset = 0x1631
ghidra_path = "D:\\Programs\\ghidra_9.1.2_PUBLIC"
ghidra_project_path = "D:\\Programs\\ghidra_9.1.2_PUBLIC\\Projects"
project_name = "CTF"
process_name = "case1.exe"
process_path = "D:\\CTF\\research\\gearshift\\windows\\case1.exe"
output_source = "code.c"
path_to_peldr = "D:\\CTF\\research\\gearshift\\windows\\peldr64.dll"
plugin_path = "D:\\CTF\\research\\gearshift\\SymbolicVSA.java"

template_win = """#include <iostream>
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

#D:\Programs\ghidra_9.1.2_PUBLIC\support\analyzeHeadless "D:\Programs\ghidra_9.1.2_PUBLIC\Projects" CTF -process case1.exe -postScript "D:\CTF\research\gearshift\SymbolicVSA.java"
if __name__ == "__main__":
	command = "{}\\support\\analyzeHeadless {} {} -process {} -postScript {}".format(ghidra_path, ghidra_project_path, project_name, process_name, plugin_path)
	print(command)
	os.system(command)
	os.system("python parser.py")
