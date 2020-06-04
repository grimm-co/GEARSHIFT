# Symbolic Data Flow Analysis on Ghidra's P-Code IL

This code performs symbolic data flow analysis through P-Code's SSA (Static Single Assignment) form, and records loads and stores performed on the parameters to a function to identify its struct. Works on all architectures supported by Ghidra.

### Running

After Ghidra's auto-analysis for a binary, navigate to the function you want to be analyzed, then run the python plugin file as a Ghidra plugin through either Ghidra's script manager or Python console.

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

### TODO

#### Inter-procedural analysis

There are two major types of analysis we want to do: FORWARD and BACKWARD

- To identify the struct usage of a parameter to a function, we do FORWARD analysis on the passed parameter
- To identify the types of the fields stored into a member of a parameter, we do BACKWARDs analysis on the value stored
- To identify the types of the fields loaded from a member of a parameter struct, we do FORWARD analysis on the loaded value
- When a stored value is derived from another function call, we must perform backwards analysis on all the return value of that function
- When a loaded value is passed into another function call, we must perform forwards analysis on that parameter to determine its struct type

#### Function analysis caching

We should never run forward analysis on the same function twice. This is because we should already know the loads and stores performed on the argument after running it once.

For backward analysis, we are able to cache the results of the first run by using placeholder parameter inputs, and the return types based on these placeholders. Therefore, the next run, we just DFS to replace all the placeholder inputs with our actual parameters and then we have obtained the return type.
