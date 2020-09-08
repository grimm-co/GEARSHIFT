# GEARSHIFT
GEARSHIFT is a tool that attempts to create a fuzz harness for a specified address in a stripped binary. It is so named because it will likely leverage a mix of reverse and forward engineering.

## Installation

To install the Ghidra script, copy the python files to one of your Ghidra
script directories:

1. In Ghidra, open the Script Manager (Window > Script Manager)
2. Click the "Script Directories" button to view the list of directories
3. Note the name of a directory. If there isn't one you can edit, add a new directory.
4. Copy all the python files in `final/` to the chosen directory.
5. Click the "Refresh Script List" button. The scripts should appear in the GEARSHIFT folder in the Script Manager.

## Usage

1. Select a function whose arguments you want to analyze.
2. From the Script Manager, under GEARSHIFT, select go.py and click Run.
3. Any structs that are identified from the arguments of the function will be
   defined in Data Type Manager under $binary_name > struct.

## Example Programs

The `example/` directory contains example programs that can be used to try out
the tool. Compile the example programs as follows:
```
cd example
make
```

## Leveraged technologies
The current tool is implemented as a Ghidra script. It leverages Ghidra's intermediate language and data dependency analysis to discover struct fields, and outputs its results to the Ghidra Data Type Manager. See [the blog post](post/Using-Ghidra-for-Automated-Struct-Identification.md) for more information.

## References of interest:

- http://conferences.sigcomm.org/sigcomm/2010/papers/apsys/p13.pdf
- https://pdfs.semanticscholar.org/1600/f73baa952cdf433f0ed6333815d3668f8f24.pdf
- https://research.cs.wisc.edu/wpis/papers/cc04.pdf

