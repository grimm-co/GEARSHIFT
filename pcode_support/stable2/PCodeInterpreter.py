from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.pcode import Varnode
from ghidra.program.flatapi import FlatProgramAPI
from Node import Node
from Struct import Struct

forward_cache = {}
backward_cache = {}
highfunction_cache = {}

class PCodeInterpreter:
	def __init__(self):
		self.nodes = {}
		self.danger_cycle = []
		self.stores = []
		self.loads = []

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
		elif opcode == PcodeOp.INT_XOR:
			self.int_xor(inputs, output)
		elif opcode == PcodeOp.INT_NEGATE:
			self.int_negate(inputs, output)
		elif opcode == PcodeOp.INT_EQUAL:
			self.int_equal(inputs, output)
		elif opcode == PcodeOp.INT_NOTEQUAL:
			self.int_notequal(inputs, output)
		elif opcode == PcodeOp.INT_LESS:
			self.int_less(inputs, output)
		elif opcode == PcodeOp.INT_LESSEQUAL:
			self.int_lessequal(inputs, output)
		elif opcode == PcodeOp.INT_SLESS:
			self.int_sless(inputs, output)
		elif opcode == PcodeOp.INT_SLESSEQUAL:
			self.int_slessequal(inputs, output)
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
		elif opcode == PcodeOp.INT_ZEXT:
			self.int_zext(inputs, output)
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
		elif opcode == PcodeOp.RETURN:
			pass
		elif opcode == PcodeOp.CBRANCH:
			pass
		else:
			print "Unsupported Opcode:", instruction.getMnemonic()

	def int_add(self, inputs, output):
		assert len(inputs) == 2 and output is not None
		a = inputs[0]
		b = inputs[1]
		if (a.isConstant() and b.isConstant()) or a.isConstant():
			raise Exception("INT_ADD error")
		result = self.lookup_node(a).add(self.lookup_node(b))
		assert result.byte_length == output.getSize()
		self.store_node(output, result)

	def int_right(self, inputs, output):
		assert len(inputs) == 2 and output is not None
		a = inputs[0]
		b = inputs[1]
		result = self.lookup_node(a).shr(self.lookup_node(b))
		assert result.byte_length == output.getSize()
		self.store_node(output, result)

	def int_left(self, inputs, output):
		assert len(inputs) == 2 and output is not None
		a = inputs[0]
		b = inputs[1]
		result = self.lookup_node(a).shl(self.lookup_node(b))
		assert result.byte_length == output.getSize()
		self.store_node(output, result)

	def int_and(self, inputs, output):
		assert len(inputs) == 2 and output is not None
		a = inputs[0]
		b = inputs[1]
		result = self.lookup_node(a).bitwise_and(self.lookup_node(b))
		assert result.byte_length == output.getSize()
		self.store_node(output, result)

	def int_sub(self, inputs, output):
		assert len(inputs) == 2 and output is not None
		a = inputs[0]
		b = inputs[1]
		result = self.lookup_node(a).sub(self.lookup_node(b))
		assert result.byte_length == output.getSize()
		self.store_node(output, result)

	def int_or(self, inputs, output):
		assert len(inputs) == 2 and output is not None
		a = inputs[0]
		b = inputs[1]
		result = self.lookup_node(a).bitwise_or(self.lookup_node(b))
		assert result.byte_length == output.getSize()
		self.store_node(output, result)

	def int_negate(self, inputs, output):
		assert len(inputs) == 1 and output is not None
		a = inputs[0]
		result = self.lookup_node(a).neg()
		assert result.byte_length == output.getSize()
		self.store_node(output, result)

	def int_xor(self, inputs, output):
		assert len(inputs) == 2 and output is not None
		a = inputs[0]
		b = inputs[1]
		result = self.lookup_node(a).bitwise_xor(self.lookup_node(b))
		assert result.byte_length == output.getSize()
		self.store_node(output, result)

	def int_equal(self, inputs, output):
		assert output is not None
		a = inputs[0]
		b = inputs[1]
		result = self.lookup_node(a).eq(self.lookup_node(b))
		if result.byte_length != output.getSize():
			result = result.resize(output.getSize())
		self.store_node(output, result)

	def int_notequal(self, inputs, output):
		assert output is not None
		a = inputs[0]
		b = inputs[1]
		result = self.lookup_node(a).neq(self.lookup_node(b))
		if result.byte_length != output.getSize():
			result = result.resize(output.getSize())
		self.store_node(output, result)

	def int_less(self, inputs, output):
		assert output is not None
		a = inputs[0]
		b = inputs[1]
		result = self.lookup_node(a).lt(self.lookup_node(b))
		if result.byte_length != output.getSize():
			result = result.resize(output.getSize())
		self.store_node(output, result)

	def int_lessequal(self, inputs, output):
		assert output is not None
		a = inputs[0]
		b = inputs[1]
		result = self.lookup_node(a).le(self.lookup_node(b))
		if result.byte_length != output.getSize():
			result = result.resize(output.getSize())
		self.store_node(output, result)

	def int_sless(self, inputs, output):
		assert output is not None
		a = inputs[0]
		b = inputs[1]
		result = self.lookup_node(a).slt(self.lookup_node(b))
		if result.byte_length != output.getSize():
			result = result.resize(output.getSize())
		self.store_node(output, result)

	def int_slessequal(self, inputs, output):
		assert output is not None
		a = inputs[0]
		b = inputs[1]
		result = self.lookup_node(a).sle(self.lookup_node(b))
		if result.byte_length != output.getSize():
			result = result.resize(output.getSize())
		self.store_node(output, result)

	def ptrsub(self, inputs, output):
		assert len(inputs) == 2
		assert output is not None
		a = inputs[0]
		b = inputs[1]
		if not b.isConstant():
			raise Exception("PTRSUB error")
		result = self.lookup_node(a).add(self.lookup_node(b))
		self.store_node(output, result)

	def store(self, inputs, output):
		assert len(inputs) == 3
		# TODO: record struct store and perform backwards analysis on the stored value to find its type
		temp = self.lookup_node(inputs[1]).ptr_deref()
		if temp.byte_length != inputs[2].getSize():
			temp = temp.resize(inputs[2].getSize())
		self.stores.append(temp)
		# print "STORE:", self.lookup_node(inputs[1]).ptr_deref()

	def load(self, inputs, output):
		assert len(inputs) == 2 and output is not None
		value = self.lookup_node(inputs[1]).ptr_deref()
		if value.byte_length != output.getSize():
			value = value.resize(output.getSize())
		assert value.byte_length == output.getSize()
		self.store_node(output, value)
		# TODO: record struct load and perform forwards analysis on the loaded value to find out its type
		self.loads.append(value)
		# print "LOAD:", value

	def subpiece(self, inputs, output):
		assert len(inputs) == 2 and output is not None
		# TODO: am I understanding this instruction correctly?
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
		print "Multiequal", possibilities, output.getPCAddress()
		self.store_node(output, possibilities[0])

	def int_sext(self, inputs, output):
		assert output is not None and len(inputs) == 1
		self.store_node(output, self.lookup_node(inputs[0]).resize(output.getSize()))

	def int_zext(self, inputs, output):
		# TODO: better modeling later
		assert output is not None and len(inputs) == 1
		self.store_node(output, self.lookup_node(inputs[0]).resize(output.getSize()))

	def int_mult(self, inputs, output):
		assert output is not None and len(inputs) == 2
		a = inputs[0]
		b = inputs[1]
		result = self.lookup_node(a).mult(self.lookup_node(b))
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
			temp = self.lookup_node(b).mult(self.lookup_node(c))
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
		checkFixParameters(called_func, inputs[1:])
		if called_func not in forward_cache:
			pci_new = PCodeInterpreter()
			parameter_varnodes = analyzeFunctionForward(called_func, pci_new)
			forward_cache[called_func] = (pci_new.stores, pci_new.loads, map(pci_new.lookup_node, parameter_varnodes))

		stores, loads, parameter_node_objects = forward_cache[called_func]
		input_node_objects = map(self.lookup_node, inputs[1:])
		for i in stores:
			self.stores.append(i.replace_base_parameters(parameter_node_objects, input_node_objects))
		for i in loads:
			self.loads.append(i.replace_base_parameters(parameter_node_objects, input_node_objects))
		if called_func.getName() == "insert":
			print("DICE")
			print(input_node_objects)
			print(stores)
			print(loads)
			print(self.stores[-len(stores):])
			print(self.loads[-len(loads):])
			# raise Exception("L")
		#print(stores, loads)
		# print("END CALL RECURSIVE FORWARD ANALYSIS")

		if output is not None:
			if called_func not in backward_cache: # This means we want to backwards interpolate the return type
				# print("START CALL RECURSIVE BACKWARDS ANALYSIS")

				#TODO: cache function analysis types
				checkFixReturn(called_func, output)
				pci_new = PCodeInterpreter()
				ret_type, subfunc_parameter_varnodes = analyzeFunctionBackward(called_func, pci_new)
				backward_cache[called_func] = (ret_type, map(pci_new.lookup_node, subfunc_parameter_varnodes))

				# print("END CALL RECURSIVE BACKWARDS ANALYSIS")

			ret_type, subfunc_parameter_node_objs = backward_cache[called_func]
			replaced_rets = []
			for i in ret_type:
				replaced_rets.append(i.replace_base_parameters(subfunc_parameter_node_objs, input_node_objects))

			# TODO: support multiple return type analysis (similar to multiequal), right now we use one
			self.store_node(output, replaced_rets[0])

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
		elif varnode.isConstant():
			# create constant node
			return Node(varnode, None, None, varnode.getSize())
		elif varnode.isAddress():
			return Node(varnode, None, None, varnode.getSize())
		elif varnode not in self.nodes:
			# We have to detect cycles here, by temporarily storing "CYCLE", and if the returned value is "CYCLE", we know there is cycle
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

	# returns a copy of the current tree
	def deep_copy(self):
		pass

def get_highfunction(func):
	if func not in highfunction_cache:
		decompileResults = decompInterface.decompileFunction(func, 30, monitor)
		if decompileResults.decompileCompleted():
			hf = decompileResults.getHighFunction()
			highfunction_cache[func] = hf
			return hf
	else:
		return highfunction_cache[func]

def checkFixParameters(func, parameters):
	hf = get_highfunction(func)
	# Check arguments
	func_proto = hf.getFunctionPrototype()
	if func_proto.getNumParams() < len(parameters):
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

# Make sure func signature matches the call
def checkFixReturn(func, ret_varnode):
	# sig = func.getSignature()
	# sig.setReturnType(Undefined.getUndefinedDataType(0x4))
	# ApplyFunctionSignatureCmd(func.getEntryPoint(), sig, SourceType.USER_DEFINED).applyTo(currentProgram)
	hf = get_highfunction(func)

	func_proto = hf.getFunctionPrototype()
	#  Check return types
	for i in hf.getPcodeOps():
		if i.getOpcode() == PcodeOp.RETURN:
			if len(i.getInputs()) < 2:
				print func, "has no return value, fixing type..."
				sig = func.getSignature()
				sig.setReturnType(Undefined.getUndefinedDataType(ret_varnode.getSize()))
				ApplyFunctionSignatureCmd(func.getEntryPoint(), sig, SourceType.USER_DEFINED).applyTo(currentProgram)
				checkFixReturn(func, ret_varnode)

# This function performs backwards analysis on the function return type with base case of function parameters
# init_param replaces the parameters of the current func to be analyzed in terms the passed parameter expressions
def analyzeFunctionBackward(func, pci, init_param=None):
	print "Backwards analysis", func.getName()

	hf = get_highfunction(func)

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
	hf = get_highfunction(func)

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