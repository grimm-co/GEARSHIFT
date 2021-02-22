# GEARSHIFT
GEARSHIFT is a tool that performs structure recovery for a specified function
within a stripped binary.  It also generates a fuzz harness that can be used
to call functions in a shared object (.so) or dynamically linked library (.dll)
file.

The name comes from it leveraging a mix of reverse and forward engineering.

## Installation

To install the Ghidra script, copy the python files to one of your Ghidra
script directories:

1. In Ghidra, open the Script Manager (Window > Script Manager)
2. Click the "Script Directories" button to view the list of directories
3. Note the name of a directory. If there isn't one you can edit, add a new directory.
4. Copy all the python files in `plugin/` to the chosen directory.
5. Click the "Refresh Script List" button. The scripts should appear in the GEARSHIFT folder in the Script Manager.

## Usage

1. Select a function whose arguments you want to analyze.
2. From the Script Manager, under GEARSHIFT, select go.py and click Run.
3. Any structs that are identified from the arguments of the function will be
   defined in Data Type Manager under $binary_name > struct.
4. The script will generate harness code and print out the names of the files
   it generated
5. Compile the harness (must be compiled with `-ldl` flag for shared objects)
6. Run the harness, passing it the file name of your input file as the only
argument

## Example Programs

The `example/` directory contains example programs that can be used to try out
the tool. Compile the example programs as follows:
```
$ cd example
$ make
```

## Limitations
The harnesses generated by GEARSHIFT currently depend on the `LoadLibrary` and
`dlopen` functions, which are unable to load executable files. If your target
is an executable rather than a shared library, you may need to write your own
harness, but you can use the generated code to create the input datastructure.

If your target is an ELF executable, you may be able to fool `dlopen` into
loading your binary by removing the PIE flag. The LIEF Project (versions >= 0.11.0)
can be used to do so [as described
here](https://lief.quarkslab.com/doc/latest/tutorials/08_elf_bin2lib.html#warning-for-glic-2-29-users).
However, this may completely break your binary, depending on what relocations
and other loader features it uses.

## Leveraged technologies
The current tool is implemented as a Ghidra script. It leverages Ghidra's
intermediate language and data dependency analysis to discover struct fields,
and outputs its results to the Ghidra Data Type Manager. See
[the associated blog post](https://blog.grimm-co.com/2020/11/automated-struct-identification-with.html)
for more information.

## References of interest:

- http://conferences.sigcomm.org/sigcomm/2010/papers/apsys/p13.pdf
- https://pdfs.semanticscholar.org/1600/f73baa952cdf433f0ed6333815d3668f8f24.pdf
- https://research.cs.wisc.edu/wpis/papers/cc04.pdf

