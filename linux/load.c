#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

typedef int(*func)(void* a, ...);

int main() {
	void* handler = dlopen("./case1", RTLD_LAZY);
	void* base = *((void**)handler);
	func f = (func)(base + 0x88e);
}
