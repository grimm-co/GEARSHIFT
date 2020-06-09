# Symbolic Data Flow Analysis on Ghidra's P-Code IL

This code performs symbolic data flow analysis through P-Code's SSA (Static Single Assignment) form, and records loads and stores performed on the parameters to a function to identify its struct. Works on all architectures supported by Ghidra.

### Running

After Ghidra's auto-analysis for a binary, navigate to the function you want to be analyzed, then run the python plugin file `go.py` as a Ghidra plugin through either Ghidra's script manager or Python console. Make sure the other python files are in Ghidra's script path as well.

### Current results (very much a work in progress)

In a toy program with the following structs

```c
typedef struct {
  char haha;
  int L;
  int L2;
  int L3;
} dec2;

typedef struct {
  char* buf;
  int length;
  dec2* lol;
  dec2* lol2;
} dec;

typedef struct {
  int return_code;
  int return_value;
  dec* buf;
} hack;
```

These loads and stores were identified:

```
Forwards analysis atoi32
STORE: *(ARG0 + (const, 0x4, 8))
LOAD: *(ARG0 + (const, 0x8, 8))
LOAD: *(*(ARG0 + (const, 0x8, 8)))
LOAD: (uint8_t)(*(*(*(ARG0 + (const, 0x8, 8)))))
LOAD: (uint8_t)(*(*(*(ARG0 + (const, 0x8, 8)))))
LOAD: (uint8_t)(*(*(*(ARG0 + (const, 0x8, 8)))))
LOAD: (uint32_t)(*(ARG0 + (const, 0x4, 8)))
STORE: *(ARG0 + (const, 0x4, 8))
LOAD: *(ARG0 + (const, 0x8, 8))
LOAD: *(*(ARG0 + (const, 0x8, 8)) + (const, 0x10, 8))
STORE: *(*(*(ARG0 + (const, 0x8, 8)) + (const, 0x10, 8)) + (const, 0x4, 8))
LOAD: *(ARG0 + (const, 0x8, 8))
LOAD: *(*(ARG0 + (const, 0x8, 8)) + (const, 0x10, 8))
STORE: *(*(*(ARG0 + (const, 0x8, 8)) + (const, 0x10, 8)) + (const, 0x8, 8))
LOAD: *(ARG0 + (const, 0x8, 8))
LOAD: *(*(ARG0 + (const, 0x8, 8)) + (const, 0x10, 8))
STORE: *(*(*(ARG0 + (const, 0x8, 8)) + (const, 0x10, 8)) + (const, 0xc, 8))
LOAD: *(ARG0 + (const, 0x8, 8))
LOAD: *(*(ARG0 + (const, 0x8, 8)) + (const, 0x10, 8))
STORE: *(*(*(ARG0 + (const, 0x8, 8)) + (const, 0x10, 8)))
LOAD: *(ARG0 + (const, 0x8, 8))
Forwards analysis sub_atoi32
LOAD: *(ARG0 + (const, 0x18, 8))
STORE: *(*(ARG0 + (const, 0x18, 8)) + (const, 0x4, 8))
LOAD: *(ARG0 + (const, 0x18, 8))
STORE: *(*(ARG0 + (const, 0x18, 8)) + (const, 0x8, 8))
LOAD: *(ARG0 + (const, 0x18, 8))
STORE: *(*(ARG0 + (const, 0x18, 8)) + (const, 0xc, 8))
LOAD: *(ARG0 + (const, 0x18, 8))
STORE: *(*(ARG0 + (const, 0x18, 8)))
LOAD: *(ARG0 + (const, 0x8, 8))
LOAD: (uint32_t)(*(*(ARG0 + (const, 0x8, 8)) + (const, 0x8, 8)))
STORE: *(ARG0)
LOAD: (uint32_t)(*(ARG0 + (const, 0x4, 8)))
LOAD: (uint32_t)(*(ARG0 + (const, 0x4, 8)))
STORE: *(ARG0)
LOAD: (uint32_t)(*(ARG0 + (const, 0x4, 8)))
STORE: *(ARG0 + (const, 0x4, 8))
STORE: *(ARG1 + (const, 0x4, 8))
LOAD: *(ARG1 + (const, 0x8, 8))
LOAD: *(*(ARG1 + (const, 0x8, 8)) + (const, 0x10, 8))
STORE: *(*(*(ARG1 + (const, 0x8, 8)) + (const, 0x10, 8)) + (const, 0x4, 8))
LOAD: *(ARG1 + (const, 0x8, 8))
LOAD: *(*(ARG1 + (const, 0x8, 8)) + (const, 0x10, 8))
STORE: *(*(*(ARG1 + (const, 0x8, 8)) + (const, 0x10, 8)) + (const, 0x8, 8))
LOAD: *(ARG1 + (const, 0x8, 8))
LOAD: *(*(ARG1 + (const, 0x8, 8)) + (const, 0x10, 8))
STORE: *(*(*(ARG1 + (const, 0x8, 8)) + (const, 0x10, 8)) + (const, 0xc, 8))
LOAD: *(ARG1 + (const, 0x8, 8))
LOAD: *(*(ARG1 + (const, 0x8, 8)) + (const, 0x10, 8))
STORE: *(*(*(ARG1 + (const, 0x8, 8)) + (const, 0x10, 8)))
LOAD: *(ARG1 + (const, 0x8, 8))
LOAD: *(*(ARG1 + (const, 0x8, 8)) + (const, 0x18, 8))
STORE: *(*(*(ARG1 + (const, 0x8, 8)) + (const, 0x18, 8)) + (const, 0x4, 8))
LOAD: *(ARG1 + (const, 0x8, 8))
LOAD: *(*(ARG1 + (const, 0x8, 8)) + (const, 0x18, 8))
STORE: *(*(*(ARG1 + (const, 0x8, 8)) + (const, 0x18, 8)) + (const, 0x8, 8))
LOAD: *(ARG1 + (const, 0x8, 8))
LOAD: *(*(ARG1 + (const, 0x8, 8)) + (const, 0x18, 8))
STORE: *(*(*(ARG1 + (const, 0x8, 8)) + (const, 0x18, 8)) + (const, 0xc, 8))
LOAD: *(ARG1 + (const, 0x8, 8))
LOAD: *(*(ARG1 + (const, 0x8, 8)) + (const, 0x18, 8))
STORE: *(*(*(ARG1 + (const, 0x8, 8)) + (const, 0x18, 8)))
```

Results are stored in a binary expression tree, which can then be converted into struct representation.

Struct representation recovered using `stable2`:

```c
struct S4 {
	char entry_1
	char entry_2[3] NOT ACCESSED
	uint32_t entry_3
	uint32_t entry_4
	uint32_t entry_5
}
struct S3 {
	char entry_1
	char entry_2[3] NOT ACCESSED
	uint32_t entry_3
	uint32_t entry_4
	uint32_t entry_5
}
struct S2 {
	char entry_1
}
struct S1 {
	S2* entry_1
	uint32_t entry_2
	uint32_t entry_3 NOT ACCESSED
	S3* entry_4
	S4* entry_5
}
struct S0 {
	uint32_t entry_1
	uint32_t entry_2
	S1* entry_3
}
```

### TODO

#### Array identification and length identification?
