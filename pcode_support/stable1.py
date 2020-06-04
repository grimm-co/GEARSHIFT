from ghidra.app.decompiler import *
from ghidra.program.model import address
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.pcode import Varnode
from ghidra.program.model.data import Undefined
from ghidra.program.model.symbol import SourceType
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.program.model.pcode import HighFunctionDBUtil

# get current function
listing = currentProgram.getListing()
currentFunction = listing.getFunctionContaining(currentAddress)
entryPoint = currentFunction.getEntryPoint()

# decompile current function and obtain HighFunction
decompInterface = ghidra.app.decompiler.DecompInterface()
decompInterface.openProgram(currentProgram)

# Abstract binary operation tree that stores the symbolic expression
# Operations:
# Addition (+)
# Subtraction (-)
# Multiplication (*)
# Division (/)
# Shifts (<<, >>)
# Bitwise operations
# Dereference (*()) - This is unary operation
# Resize (RESIZE) - This is unary operation
# CYCLE - This indicates that the current value is a cycle
# TODO: pretty print cycles properly
class Node:
	# TODO: add data length tracking support
	def __init__(self, operation, left, right, byte_length):
		self.left = left
		self.right = right
		self.operation = operation
		self.byte_length = byte_length
		pass

	def __str__(self):
		if self.is_leaf():
			return str(self.operation)
		elif self.operation == "*()":
			return "*({})".format(str(self.left))
		elif self.operation == "RESIZE":
			return "(uint{}_t)({})".format(self.byte_length * 8, str(self.left))
		else:
			return str(self.left) + " " + self.operation + " " + str(self.right)

	def __repr__(self):
		return self.__str__()

	def is_leaf(self):
		return self.left is None and self.right is None

	def add(self, value):
		return Node("+", self, value, self.byte_length)

	def sub(self, value):
		return Node("-", self, value, self.byte_length)

	def mult(self, value):
		return Node("*", self, value, self.byte_length)

	def div(self, value):
		return Node("/", self, value, self.byte_length)

	def shl(self, value):
		return Node("<<", self, value, self.byte_length)

	def shr(self, value):
		return Node(">>", self, value, self.byte_length)

	def bitwise_xor(self, value):
		return Node("^", self, value, self.byte_length)

	def bitwise_or(self, value):
		return Node("|", self, value, self.byte_length)

	def bitwise_and(self, value):
		return Node("&", self, value, self.byte_length)

	def ptr_deref(self):
		return Node("*()", self, None, self.byte_length)

	def resize(self, new_length):
		return Node("RESIZE", self, None, new_length)

class PCodeInterpreter:

	def __init__(self):
		self.nodes = {}
		self.danger_cycle = []
		self.function_cache = {}

	def process(self, instruction, depth):
		opcode = instruction.getOpcode()
		output = instruction.getOutput()
		inputs = instruction.getInputs()

		# if output is not None:
		# 	print "Instruction", output.getPCAddress(), instruction, depth
		# else:
		# 	print "Instruction", inputs[0].getPCAddress(), instruction, depth

		if opcode == PcodeOp.INT_ADD:
			self.int_add(inputs, output)
		elif opcode == PcodeOp.INT_RIGHT:
			self.int_right(inputs, output)
		elif opcode == PcodeOp.INT_LEFT:
			self.int_left(inputs, output)
		elif opcode == PcodeOp.INT_AND:
			self.int_and(inputs, output)
		elif opcode == PcodeOp.INT_SUB:
			self.int_sub(inputs, output)
		elif opcode == PcodeOp.INT_OR:
			self.int_or(inputs, output)
		elif opcode == PcodeOp.PTRSUB:
			self.ptrsub(inputs, output)
		elif opcode == PcodeOp.STORE:
			self.store(inputs, output)
		elif opcode == PcodeOp.LOAD:
			self.load(inputs, output)
		elif opcode == PcodeOp.SUBPIECE:
			self.subpiece(inputs, output)
		elif opcode == PcodeOp.CAST:
			self.cast(inputs, output)
		elif opcode == PcodeOp.MULTIEQUAL:
			self.multiequal(inputs, output)
		elif opcode == PcodeOp.INT_SEXT:
			self.int_sext(inputs, output)
		elif opcode == PcodeOp.INT_MULT:
			self.int_mult(inputs, output)
		elif opcode == PcodeOp.PTRADD:
			self.ptradd(inputs, output)
		elif opcode == PcodeOp.CALL:
			self.call(inputs, output)
		elif opcode == PcodeOp.COPY:
			self.copy(inputs, output)
		elif opcode == PcodeOp.INDIRECT:
			self.indirect(inputs, output)
		else:
			# print "Unsupported Opcode:", instruction.getMnemonic()
			pass

	def int_add(self, inputs, output):
		assert len(inputs) == 2
		assert output is not None
		a = inputs[0]
		b = inputs[1]
		if (a.isConstant() and b.isConstant()) or a.isConstant():
			raise Exception("INT_ADD error")
		result = self.lookup_node(a).add(b)
		assert result.byte_length == output.getSize()
		self.store_node(output, result)

	def int_right(self, inputs, output):
		assert len(inputs) == 2
		assert output is not None
		a = inputs[0]
		b = inputs[1]
		result = self.lookup_node(a).shr(b)
		assert result.byte_length == output.getSize()
		self.store_node(output, result)

	def int_left(self, inputs, output):
		assert len(inputs) == 2
		assert output is not None
		a = inputs[0]
		b = inputs[1]
		result = self.lookup_node(a).shl(b)
		assert result.byte_length == output.getSize()
		self.store_node(output, result)

	def int_and(self, inputs, output):
		assert len(inputs) == 2
		assert output is not None
		a = inputs[0]
		b = inputs[1]
		result = self.lookup_node(a).bitwise_and(b)
		assert result.byte_length == output.getSize()
		self.store_node(output, result)

	def int_sub(self, inputs, output):
		assert len(inputs) == 2
		assert output is not None
		a = inputs[0]
		b = inputs[1]
		result = self.lookup_node(a).sub(b)
		assert result.byte_length == output.getSize()
		self.store_node(output, result)

	def int_or(self, inputs, output):
		assert len(inputs) == 2
		assert output is not None
		a = inputs[0]
		b = inputs[1]
		result = self.lookup_node(a).bitwise_or(b)
		assert result.byte_length == output.getSize()
		self.store_node(output, result)

	def ptrsub(self, inputs, output):
		assert len(inputs) == 2
		assert output is not None
		a = inputs[0]
		b = inputs[1]
		if a.isConstant() or not b.isConstant():
			raise Exception("PTRSUB error")
		result = self.lookup_node(a).add(b)
		self.store_node(output, result)

	def store(self, inputs, output):
		assert len(inputs) == 3
		# TODO: record struct store and perform backwards analysis on the stored value to find its type
		print "STORE:", self.lookup_node(inputs[1]).ptr_deref()

	def load(self, inputs, output):
		assert len(inputs) == 2 and output is not None
		value = self.lookup_node(inputs[1]).ptr_deref()
		if value.byte_length != output.getSize():
			value = value.resize(output.getSize())
		assert value.byte_length == output.getSize()
		self.store_node(output, value)
		# TODO: record struct load and perform forwards analysis on the loaded value to find out its type
		print "LOAD:", value

	def subpiece(self, inputs, output):
		assert len(inputs) == 2 and output is not None
		value = self.lookup_node(inputs[0]).shr(self.lookup_node(inputs[1]).mult(8))
		if value.byte_length != output.getSize():
			value = value.resize(output.getSize())
		self.store_node(output, value)

	def cast(self, inputs, output):
		assert len(inputs) == 1 and output is not None
		value = self.lookup_node(inputs[0])
		assert value.byte_length == output.getSize()
		self.store_node(output, value)

	def multiequal(self, inputs, output):
		assert output is not None and len(inputs) >= 2
		possibilities = []
		for i in inputs:
			result = self.lookup_node(i)

			possibilities.append(result)
		# TODO: support multiequal list values everywhere, right now we only use one value lol
		self.store_node(output, possibilities[0])

	def int_sext(self, inputs, output):
		assert output is not None and len(inputs) == 1
		self.store_node(output, self.nodes[inputs[0]].resize(output.getSize()))

	def int_mult(self, inputs, output):
		assert output is not None and len(inputs) == 2
		a = inputs[0]
		b = inputs[1]
		result = self.lookup_node(a).mult(b)
		assert output.getSize() == result.byte_length
		self.store_node(output, result)

	def ptradd(self, inputs, output):
		assert output is not None and len(inputs) == 3
		assert inputs[2].isConstant() and not inputs[0].isConstant()
		a = self.lookup_node(inputs[0])
		b = inputs[1]
		c = inputs[2]
		if b.isConstant():
			temp = Node(Varnode(c.getAddress().getNewAddress(b.getOffset() * c.getOffset()), output.getSize()), None, None, output.getSize())
		else:
			temp = self.lookup_node(b).mult(c)
		result = a.add(temp)
		assert output.getSize() == result.byte_length
		# TODO: maybe use this as struct information?
		self.store_node(output, result)

	def call(self, inputs, output):
		assert len(inputs) >= 1
		# First we have to analyze function forward with input arguments
		# If output exists, then we have to analyze backwards to obtain ret value types
		pc_varnode = inputs[0]
		assert pc_varnode.isAddress()
		pc_addr = pc_varnode.getAddress()
		temp = FlatProgramAPI(currentProgram)
		called_func = temp.getFunctionAt(pc_addr)
		# print("START CALL RECURSIVE FORWARD ANALYSIS")
		# Note: the function analysis parameter's varnodes are DIFFERENT that the varnodes from our current state. Thus we replace the varnode -> Node map in the function with the calling parameters
		parameter_varnodes = analyzeFunctionForward(called_func, self)
		# print("END CALL RECURSIVE FORWARD ANALYSIS")

		if output is not None: # This means we want to backwards interpolate the return type
			# print("START CALL RECURSIVE BACKWARDS ANALYSIS")

			#TODO: cache function analysis types
			checkFixFunctionType(called_func, output, inputs[1:])
			ret_type, subfunc_parameter_varnodes = analyzeFunctionBackward(called_func, self, init_param=inputs[1:])

			# print("END CALL RECURSIVE BACKWARDS ANALYSIS")

			# TODO: support multiple return type analysis (similar to multiequal), right now we use one
			self.store_node(output, ret_type[0])

	def copy(self, inputs, output):
		assert len(inputs) == 1 and output is not None
		result = self.lookup_node(inputs[0])
		self.store_node(output, result)

	def indirect(self, inputs, output):
		# TODO: model more effectively in the future? Not sure what inputs[1] does
		value = self.lookup_node(inputs[0])
		assert value.byte_length == output.getSize()
		self.store_node(output, value)

	# maps a Ghidra Varnode object to a binary tree object that represents its expression
	def lookup_node(self, varnode):
		# Detect cycle
		if varnode in self.nodes and self.nodes[varnode] == "CYCLE":
			# print("Cycle detected")
			self.nodes[varnode] = Node("CYCLE", None, None, varnode.getSize())
		if varnode.isConstant():
			# create constant node
			return Node(varnode, None, None, varnode.getSize())
		elif varnode.isAddress():
			return Node(varnode, None, None, varnode.getSize())
		elif varnode not in self.nodes:
			# We have to detect cycles here, by temporarily storing None, and if the returned value is None, we know there is cycle
			self.store_node(varnode, "CYCLE")
			self.get_node_definition(varnode)
			return self.lookup_node(varnode)
		return self.nodes[varnode]

	# recursively backwards traces for node's definition
	def get_node_definition(self, varnode):
		# TODO: maybe we should reset PCodeInterpreter state for this?

		defining_instruction = varnode.getDef()
		if defining_instruction is None:
			# TODO: fix this? I'm not sure what causes this error
			print("WARNING: Orphaned varnode? - assuming multiequal analyzation error and skipping")
			self.nodes[varnode] = Node("ORPHANED", None, None, varnode.getSize())
			return
		self.process(defining_instruction, -1)

	# stores mapping between Ghidra varnode and binary tree obj
	def store_node(self, varnode, nodeobj):
		self.nodes[varnode] = nodeobj

	# returns a copy of the current state
	def deep_copy(self):
		pass

# Make sure func signature matches the call
def checkFixFunctionType(func, ret_varnode, parameters):
	# sig = func.getSignature()
	# sig.setReturnType(Undefined.getUndefinedDataType(0x4))
	# ApplyFunctionSignatureCmd(func.getEntryPoint(), sig, SourceType.USER_DEFINED).applyTo(currentProgram)
	decompileResults = decompInterface.decompileFunction(func, 30, monitor)
	hf = None
	if decompileResults.decompileCompleted():
		hf = decompileResults.getHighFunction()

	func_proto = hf.getFunctionPrototype()
	#  Check return types
	for i in hf.getPcodeOps():
		if i.getOpcode() == PcodeOp.RETURN:
			if len(i.getInputs()) < 2:
				print func, "has no return value, fixing type..."
				sig = func.getSignature()
				sig.setReturnType(Undefined.getUndefinedDataType(ret_varnode.getSize()))
				ApplyFunctionSignatureCmd(func.getEntryPoint(), sig, SourceType.USER_DEFINED).applyTo(currentProgram)
				checkFixFunctionType(func, ret_varnode, parameters)

	# Check arguments
	if func_proto.getNumParams() != len(parameters):
		print func, "call signature wrong, fixing..."
		HighFunctionDBUtil().commitParamsToDatabase(hf, True, SourceType.USER_DEFINED)
		if func_proto.getNumParams() != len(parameters):
			print func, "fix did not work..."
			raise Exception("Function call signature different")
		else:
			raise Exception("Good, fix worked!")

	argument_varnodes = []
	for i in range(func_proto.getNumParams()):
		cur = func_proto.getParam(i).getRepresentative()
		if cur.getSize() != parameters[i].getSize():
			raise Exception("Func parameter size mismatch")

# This function performs backwards analysis on the function return type with base case of function parameters
# init_param replaces the parameters of the current func to be analyzed in terms the passed parameter expressions
def analyzeFunctionBackward(func, pci, init_param=None):
	print "Backwards analysis", func.getName()
	
	decompileResults = decompInterface.decompileFunction(func, 30, monitor)
	hf = None
	if decompileResults.decompileCompleted():
		hf = decompileResults.getHighFunction()

	func_proto = hf.getFunctionPrototype()
	# Grab return varnodes
	return_varnodes = []
	for i in hf.getPcodeOps():
		if i.getOpcode() == PcodeOp.RETURN:
			assert len(i.getInputs()) >= 2
			return_varnodes.append(i.getInputs()[1])

	# Grab argument varnodes as base case
	argument_varnodes = []
	for i in range(func_proto.getNumParams()):
		argument_varnodes.append(func_proto.getParam(i).getRepresentative())

	# Sets argument as base cases
	for arg in range(len(argument_varnodes)):
		if init_param is None:
			pci.nodes[argument_varnodes[arg]] = Node("ARG"  + str(arg), None, None, argument_varnodes[arg].getSize())
		else:
			pci.nodes[argument_varnodes[arg]] = init_param[arg]

	return_types = []
	for i in return_varnodes:
		result = pci.lookup_node(i)
		return_types.append(result)
	return return_types, argument_varnodes

def traverseForward(cur, depth, pci, visited):
	if cur is None:
		return
	children = cur.getDescendants()
	for child in children:
		pci.process(child, depth)
		# TODO: path loop condition based on changes in state
		if child.getOutput() is not None and child.getOutput() not in visited:
			visited.add(child.getOutput())
			traverseForward(child.getOutput(), depth + 1, pci, visited)

# This function performs forward analysis on function parameters to determine its type (struct, array, or primitive)
def analyzeFunctionForward(func, pci):
	print "Forwards analysis", func.getName()
	decompileResults = decompInterface.decompileFunction(func, 30, monitor)
	hf = None
	if decompileResults.decompileCompleted():
		hf = decompileResults.getHighFunction()

	# get the varnode of function parameters
	func_proto = hf.getFunctionPrototype()
	argument_varnodes = []
	for i in range(func_proto.getNumParams()):
		argument_varnodes.append(func_proto.getParam(i).getRepresentative())

	visited = set()

	# print("Return Node:", ret_varnode)
	for arg in range(len(argument_varnodes)):
		pci.nodes[argument_varnodes[arg]] = Node("ARG"  + str(arg), None, None, argument_varnodes[arg].getSize())

	# recursively traverse the varnode descendants to get reaching definitions
	for i in argument_varnodes:
		traverseForward(i, 0, pci, visited)

	return argument_varnodes

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
We should never run forward analysis on the same function twice. This is because we should already know the types of the arguments from the first forward analysis run. We just need to use that information for building the struct.
For backward analysis, we are able to cache the results of the first run by using placeholder parameter inputs, and the return types based on these placeholders. Therefore, the next run, we just DFS to replace all the placeholder inputs with our actual parameters and then we have obtained the return type.

TODO: test recursive function analysis
"""

pci = PCodeInterpreter()
# print(analyzeFunctionBackward(currentFunction, pci))
analyzeFunctionForward(currentFunction, pci)

# execfile("D:\\CTF\\research\\gearshift\\pcode_trace\\sice.py")