#!/usr/bin/env python3
# GEARSHIFT struct identifier
# @category: GEARSHIFT

from __future__ import print_function
import time
import os.path

from ghidra.app.decompiler import *
from ghidra.program.model import address
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.data import Undefined
from ghidra.program.model.symbol import SourceType
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.program.model.pcode import HighFunctionDBUtil

import PCodeInterpreter
import Node
import Struct
from Harness import *

# Global config
ARCH_BITS = currentProgram.getDefaultPointerSize() * 8

decompInterface = ghidra.app.decompiler.DecompInterface()
decompInterface.openProgram(currentProgram)
PCodeInterpreter.decompInterface = decompInterface
PCodeInterpreter.monitor = monitor
PCodeInterpreter.currentProgram = currentProgram
PCodeInterpreter.ARCH_BITS = ARCH_BITS
Node.ARCH_BITS = ARCH_BITS
Struct.ARCH_BITS = ARCH_BITS
Struct.struct_counter = 0
Struct.currentProgram = currentProgram

"""
NOTES on interprocedural analysis
There are two major types of analysis we want to do: FORWARD and BACKWARD
- To identify the struct usage of a parameter to a function, we do FORWARD analysis on the passed parameter
- To identify the types of the fields stored into a member of a parameter, we do BACKWARDs analysis on the value stored
- To identify the types of the fields loaded from a member of a parameter struct, we do FORWARD analysis on the loaded value
- When a stored value is derived from another function call, we must perform backwards analysis on all the return value of that function
- When a loaded value is passed into another function call, we must perform forwards analysis on that parameter to determine its struct type
Example backward analysis: https://www.riverloopsecurity.com/blog/2019/05/pcode/

NOTES on caching
We should never run forward analysis on the same function twice. This is because we should already know the loads and stores performed on the argument after running it once.
For backward analysis, we are able to cache the results of the first run by using placeholder parameter inputs, and the return types based on these placeholders. Therefore, the next run, we just DFS to replace all the placeholder inputs with our actual parameters and then we have obtained the return type.

TODO: test recursive function analysis

To identify arrays, we use the idea of loop variants. A loop variant is the output from a multiequal pcode op. When running analysis multiple times with different loop variant initial conditions, the loop variant changes each run. The loads or stores that change are likely array loads and stores. Using the differences in struct accesses, we can infer which ones are arrays, and the stride of the array.
"""

start = time.time()

# get current function
listing = currentProgram.getListing()
currentFunction = listing.getFunctionContaining(currentAddress)
entryPoint = currentFunction.getEntryPoint()
base_address = currentProgram.getImageBase().getOffset()
function_offset = entryPoint.getOffset() - currentProgram.getImageBase().getOffset()
program_path = currentProgram.getExecutablePath()

pci = PCodeInterpreter.PCodeInterpreter()
pci.currentProgram = currentProgram
argument_varnodes = PCodeInterpreter.analyzeFunctionForward(currentFunction, pci)

important_stores = []
important_loads = []
argument_node_objs = []
for i in argument_varnodes:
	argument_node_objs += pci.lookup_node(i)
argument_structs = [None] * len(argument_varnodes)

for i in pci.stores:
	if i.contains(argument_node_objs):
		important_stores.append(i)
for i in pci.loads:
	if i.contains(argument_node_objs):
		important_loads.append(i)

print("Start creating struct")

args = []
for i in range(len(argument_structs)):
	args.append(Struct.Struct(0))

used_hash = set()
used_expressions = []
for i in (important_stores + important_loads):
	simplified = i.simplify()
	if hash(simplified) in used_hash:
		continue
	try:
		substruct, offset, grand = simplified.create_struct(args, simplified.byte_length)
		if i in pci.arrays and not grand[0].is_array:
			grand[0].make_array()
		used_expressions.append(simplified)
		used_hash.add(hash(simplified))
	except ValueError as e:
		print(e)

print("Done interpolating structs")

# Apply data type to original function
orig_params = currentFunction.getParameters()
assert len(orig_params) == len(args)
struct_code = []
for i in range(len(args)):
	code = args[i].pretty_print()
	struct_code.append(code)
	print(code)
	dt = args[i].get_dtype()
	print(dt)
	orig_params[i].setDataType(dt, SourceType.USER_DEFINED)

# Apply data types to subcall functions
for i in range(currentFunction.getParameterCount()):
	used_hash.add(hash("ARG{}".format(i)))
for func in pci.subcall_parameter_cache:
	params = pci.subcall_parameter_cache[func]
	for param_idx in range(len(params)):
		seen = set()
		for j in params[param_idx]:
			simplified = j.simplify()
			h = hash(simplified)
			if h in used_hash and h not in seen:
				seen.add(h)
				arg_idx = simplified.find_base_idx2()
				t, off = simplified.traverse_struct(args[arg_idx])
				if isinstance(t, Struct.Struct):
					print("Applying type {} to function {} parameter {}".format(t.name, func, param_idx))
					func.getParameters()[param_idx].setDataType(t.get_dtype(), SourceType.USER_DEFINED)

code, cleanup, arg_names = Struct.generate_struct_reader(args)
struct_defs = "".join(struct_code)

linux_harness = generate_linux_harness(struct_defs, program_path, function_offset, code, cleanup, arg_names)
windows_harness = generate_windows_harness(struct_defs, program_path, function_offset, code, cleanup, arg_names)

linux_filename = os.path.abspath('gearshift_harness_linux.c')
windows_filename = os.path.abspath('gearshift_harness_windows.c')

print("writing linux harness to", linux_filename)
with open(linux_filename, 'w') as harness:
    harness.write(linux_harness)
print("writing windows harness to", windows_filename)
with open(windows_filename, 'w') as harness:
    harness.write(windows_harness)

end = time.time()
print("DONE - Took:", (end - start))
