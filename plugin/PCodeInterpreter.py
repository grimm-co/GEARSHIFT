#!/usr/bin/env python3
# @category: GEARSHIFT.internal

from __future__ import print_function

from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.pcode import Varnode
from ghidra.program.flatapi import FlatProgramAPI
from Node import Node
from Struct import Struct
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import Undefined
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.program.model.listing import AutoParameterImpl

NODE_LIMIT = 1
log = False

forward_cache = {}
backward_cache = {}
highfunction_cache = {}

# dictionary storing func: list of symbolic parameters the func is called with for each parameter
# this is used to apply retyping in the future

cycle_node = Node("CYCLE", None, None, 0)

class PCodeInterpreter:
	def __init__(self):
		self.nodes = {}
		self.stores = []
		self.loads = []
		self.instruction = None
		self.cycle_exec = {}
		self.loop_variants = set()
		self.arrays = []
		self.subcall_parameter_cache = {}

	def process(self, instruction, depth):
		opcode = instruction.getOpcode()
		output = instruction.getOutput()
		inputs = instruction.getInputs()
		self.depth = depth

		saved_instruction = self.instruction
		self.instruction = instruction

		if opcode == PcodeOp.INT_ADD:
			self.int_add(inputs, output)
		elif opcode == PcodeOp.INT_SDIV:
			self.int_sdiv(inputs, output)
		elif opcode == PcodeOp.INT_DIV:
			self.int_div(inputs, output)
		elif opcode == PcodeOp.INT_SREM:
			self.int_srem(inputs, output)
		elif opcode == PcodeOp.INT_REM:
			self.int_rem(inputs, output)
		elif opcode == PcodeOp.INT_RIGHT:
			self.int_right(inputs, output)
		elif opcode == PcodeOp.INT_SRIGHT:
			self.int_sright(inputs, output)
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
		elif opcode == PcodeOp.INT_2COMP:
			self.int_2comp(inputs, output)
		elif opcode == PcodeOp.PTRSUB:
			self.ptrsub(inputs, output)
		elif opcode == PcodeOp.STORE:
			self.store(inputs, output)
		elif opcode == PcodeOp.LOAD:
			self.load(inputs, output)
		elif opcode == PcodeOp.SUBPIECE:
			self.subpiece(inputs, output)
		elif opcode == PcodeOp.PIECE:
			self.piece(inputs, output)
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
		elif opcode == PcodeOp.CALLIND:
			self.callind(inputs, output)
		elif opcode == PcodeOp.COPY:
			self.copy(inputs, output)
		elif opcode == PcodeOp.INDIRECT:
			self.indirect(inputs, output)
		elif opcode == PcodeOp.RETURN:
			if len(inputs) >= 2:
				print("RETURN")
				print(self.lookup_node(inputs[1]))
		elif opcode == PcodeOp.CBRANCH:
			pass
		else:
			print("Unsupported Opcode:", instruction.getMnemonic(), inputs[0].getPCAddress())

		self.instruction = saved_instruction

	def int_sdiv(self, inputs, output):
		assert len(inputs) == 2 and output is not None
		a = inputs[0]
		b = inputs[1]
		for i in self.lookup_node(a):
			for j in self.lookup_node(b):
				self.store_node(output, i.sdiv(j))

	def int_div(self, inputs, output):
		assert len(inputs) == 2 and output is not None
		a = inputs[0]
		b = inputs[1]
		for i in self.lookup_node(a):
			for j in self.lookup_node(b):
				self.store_node(output, i.div(j))

	def int_srem(self, inputs, output):
		assert len(inputs) == 2 and output is not None
		a = inputs[0]
		b = inputs[1]
		for i in self.lookup_node(a):
			for j in self.lookup_node(b):
				self.store_node(output, i.smod(j))

	def int_rem(self, inputs, output):
		assert len(inputs) == 2 and output is not None
		a = inputs[0]
		b = inputs[1]
		for i in self.lookup_node(a):
			for j in self.lookup_node(b):
				self.store_node(output, i.mod(j))

	def int_add(self, inputs, output):
		assert len(inputs) == 2 and output is not None
		a = inputs[0]
		b = inputs[1]
		if (a.isConstant() and b.isConstant()) or a.isConstant():
			raise Exception("INT_ADD error")
		for i in self.lookup_node(a):
			for j in self.lookup_node(b):
				self.store_node(output, i.add(j))

	def int_right(self, inputs, output):
		assert len(inputs) == 2 and output is not None
		a = inputs[0]
		b = inputs[1]
		for i in self.lookup_node(a):
			for j in self.lookup_node(b):
				self.store_node(output, i.shr(j))

	def int_sright(self, inputs, output):
		assert len(inputs) == 2 and output is not None
		a = inputs[0]
		b = inputs[1]
		for i in self.lookup_node(a):
			for j in self.lookup_node(b):
				self.store_node(output, i.sshr(j))

	def int_left(self, inputs, output):
		assert len(inputs) == 2 and output is not None
		a = inputs[0]
		b = inputs[1]
		for i in self.lookup_node(a):
			for j in self.lookup_node(b):
				self.store_node(output, i.shl(j))

	def int_and(self, inputs, output):
		assert len(inputs) == 2 and output is not None
		a = inputs[0]
		b = inputs[1]
		for i in self.lookup_node(a):
			for j in self.lookup_node(b):
				self.store_node(output, i.bitwise_and(j))

	def int_sub(self, inputs, output):
		assert len(inputs) == 2 and output is not None
		a = inputs[0]
		b = inputs[1]
		for i in self.lookup_node(a):
			for j in self.lookup_node(b):
				self.store_node(output, i.sub(j))

	def int_or(self, inputs, output):
		assert len(inputs) == 2 and output is not None
		a = inputs[0]
		b = inputs[1]
		for i in self.lookup_node(a):
			for j in self.lookup_node(b):
				self.store_node(output, i.bitwise_or(j))

	def int_negate(self, inputs, output):
		assert len(inputs) == 1 and output is not None
		a = inputs[0]
		for i in self.lookup_node(a):
			self.store_node(output, i.neg())

	def int_xor(self, inputs, output):
		assert len(inputs) == 2 and output is not None
		a = inputs[0]
		b = inputs[1]
		for i in self.lookup_node(a):
			for j in self.lookup_node(b):
				self.store_node(output, i.bitwise_xor(j))

	def int_equal(self, inputs, output):
		assert output is not None
		a = inputs[0]
		b = inputs[1]
		for i in self.lookup_node(a):
			for j in self.lookup_node(b):
				res = i.eq(j)
				if res.byte_length != output.getSize():
					res = res.resize(output.getSize())
				self.store_node(output, res)

	def int_notequal(self, inputs, output):
		assert output is not None
		a = inputs[0]
		b = inputs[1]
		for i in self.lookup_node(a):
			for j in self.lookup_node(b):
				res = i.neq(j)
				if res.byte_length != output.getSize():
					res = res.resize(output.getSize())
				self.store_node(output, res)

	def int_less(self, inputs, output):
		assert output is not None
		a = inputs[0]
		b = inputs[1]
		for i in self.lookup_node(a):
			for j in self.lookup_node(b):
				res = i.lt(j)
				if res.byte_length != output.getSize():
					res = res.resize(output.getSize())
				self.store_node(output, res)

	def int_lessequal(self, inputs, output):
		assert output is not None
		a = inputs[0]
		b = inputs[1]
		for i in self.lookup_node(a):
			for j in self.lookup_node(b):
				res = i.le(j)
				if res.byte_length != output.getSize():
					res = res.resize(output.getSize())
				self.store_node(output, res)

	def int_sless(self, inputs, output):
		assert output is not None
		a = inputs[0]
		b = inputs[1]
		for i in self.lookup_node(a):
			for j in self.lookup_node(b):
				res = i.slt(j)
				if res.byte_length != output.getSize():
					res = res.resize(output.getSize())
				self.store_node(output, res)

	def int_slessequal(self, inputs, output):
		assert output is not None
		a = inputs[0]
		b = inputs[1]
		for i in self.lookup_node(a):
			for j in self.lookup_node(b):
				res = i.sle(j)
				if res.byte_length != output.getSize():
					res = res.resize(output.getSize())
				self.store_node(output, res)

	def int_2comp(self, inputs, output):
		assert len(inputs) == 1 and output is not None
		for i in self.lookup_node(inputs[0]):
			self.store_node(output, i.neg())

	def ptrsub(self, inputs, output):
		assert len(inputs) == 2
		assert output is not None
		a = inputs[0]
		b = inputs[1]
		if not b.isConstant():
			raise Exception("PTRSUB error")
		for i in self.lookup_node(a):
			for j in self.lookup_node(b):
				self.store_node(output, i.add(j))

	def store(self, inputs, output):
		assert len(inputs) == 3
		for i in self.lookup_node(inputs[1]):
			for j in self.lookup_node(inputs[2]):
				temp = i.ptr_deref()
				if temp.byte_length != j.byte_length:
					temp = temp.resize(j.byte_length)
				self.stores.append(temp)
				if log:
					print("[*]", "STORE:", inputs[0].getPCAddress(), temp)
					print("VALUE", self.lookup_node(inputs[2]))
					print("")

	def load(self, inputs, output):
		assert len(inputs) == 2 and output is not None
		for i in self.lookup_node(inputs[1]):
			value = i.ptr_deref()
			if value.byte_length != output.getSize():
				value = value.resize(output.getSize())
			self.store_node(output, value)
			self.loads.append(value)

	def subpiece(self, inputs, output):
		assert len(inputs) == 2 and output is not None
		for i in self.lookup_node(inputs[0]):
			for j in self.lookup_node(inputs[1]):
				value = i.shr(j.mult(Node(currentProgram.getAddressFactory().getConstantAddress(8), None, None, i.byte_length)))
				if value.byte_length != output.getSize():
					value = value.resize(output.getSize())
				self.store_node(output, value)

	def piece(self, inputs, output):
		assert len(inputs) == 2 and output is not None
		for i in self.lookup_node(inputs[0]):
			for j in self.lookup_node(inputs[1]):
				value = i.shl(Node(currentProgram.getAddressFactory().getConstantAddress(j.byte_length), None, None, i.byte_length)).add(j)
				if value.byte_length != output.getSize():
					value = value.resize(output.getSize())
				self.store_node(output, value)

	def cast(self, inputs, output):
		assert len(inputs) == 1 and output is not None
		for value in self.lookup_node(inputs[0]):
			assert value.byte_length == output.getSize()
			self.store_node(output, value)

	def multiequal(self, inputs, output):
		assert output is not None and len(inputs) >= 2
		possibilities = []
		count = 0
		for i in inputs:
			result = self.lookup_node(i)
			for j in result:
				possibilities.append(j)
				self.store_node(output, j)
		self.loop_variants.add(output)

	def int_sext(self, inputs, output):
		assert output is not None and len(inputs) == 1
		for i in self.lookup_node(inputs[0]):
			self.store_node(output, i.resize(output.getSize()))

	def int_zext(self, inputs, output):
		assert output is not None and len(inputs) == 1
		for i in self.lookup_node(inputs[0]):
			self.store_node(output, i.resize(output.getSize()))

	def int_mult(self, inputs, output):
		assert output is not None and len(inputs) == 2
		a = inputs[0]
		b = inputs[1]
		for i in self.lookup_node(a):
			for j in self.lookup_node(b):
				result = i.mult(j)
				self.store_node(output, result)

	def ptradd(self, inputs, output):
		assert output is not None and len(inputs) == 3
		assert inputs[2].isConstant() and not inputs[0].isConstant()
		for a in self.lookup_node(inputs[0]):
			for b in self.lookup_node(inputs[1]):
				for c in self.lookup_node(inputs[2]):
					temp = b.mult(c)
					result = a.add(temp)
					assert output.getSize() == result.byte_length
					self.store_node(output, result)

	def callind(self, inputs, output):
		assert len(inputs) >= 1
		print("Warning: indirect call - skipping and returning 0")
		if output is not None:
			self.store_node(output, Node(Varnode(output.getAddress(), output.getSize()), None, None, output.getSize()))

	def call(self, inputs, output):
		assert len(inputs) >= 1
		# First we have to analyze function forward with input arguments
		# If output exists, then we have to analyze backwards to obtain ret value types
		pc_varnode = inputs[0]
		assert pc_varnode.isAddress()
		pc_addr = pc_varnode.getAddress()
		temp = FlatProgramAPI(currentProgram)
		called_func = temp.getFunctionAt(pc_addr)
		print("call:", inputs[0].getPCAddress())

		##### START CALL RECURSIVE FORWARD ANALYSIS

		# Note: the function analysis parameter's varnodes are DIFFERENT that the varnodes from our current state. Thus we replace the varnode -> Node map in the function with the calling parameters
		checkFixParameters(called_func, inputs[1:])
		if called_func not in forward_cache:
			global log
			pci_new = PCodeInterpreter()
			parameter_varnodes = analyzeFunctionForward(called_func, pci_new)
			parameter_nodes = []
			for i in parameter_varnodes:
				parameter_nodes.append(pci_new.lookup_node(i)[0])
			forward_cache[called_func] = (pci_new.stores, pci_new.loads, parameter_nodes, pci_new.arrays, pci_new.subcall_parameter_cache)
			log = False

		stores, loads, parameter_node_objects, arrs, nested_subcall_parameter_cache = forward_cache[called_func]
		input_node_objects = map(self.lookup_node, inputs[1:])
		if called_func not in self.subcall_parameter_cache:
			param_list = []
			for i in range(called_func.getParameterCount()):
				param_list.append([])
			self.subcall_parameter_cache[called_func] = param_list

		node_objects = map(self.lookup_node, inputs[1:])
		for i in range(len(self.subcall_parameter_cache[called_func])):
			self.subcall_parameter_cache[called_func][i] += node_objects[i]

		for i in stores:
			arg_idx = i.find_base_idx(parameter_node_objects)
			if arg_idx is not None:
				for j in node_objects[arg_idx]:
					self.stores.append(i.replace_base_parameters(parameter_node_objects, j))
					if i in arrs:
						self.arrays.append(self.stores[-1])
		for i in loads:
			arg_idx = i.find_base_idx(parameter_node_objects)
			if arg_idx is not None:
				for j in node_objects[arg_idx]:
					self.loads.append(i.replace_base_parameters(parameter_node_objects, j))
					if i in arrs:
						self.arrays.append(self.loads[-1])

		##### END CALL RECURSIVE FORWARD ANALYSIS

		# replace args in parameter cache:
		for func_name in nested_subcall_parameter_cache:
			current_params = nested_subcall_parameter_cache[func_name]
			for param_idx in range(len(current_params)):
				for temp in current_params[param_idx]:
					arg_idx = temp.find_base_idx(parameter_node_objects)
					if arg_idx is not None:
						for j in node_objects[arg_idx]:
							replaced = temp.replace_base_parameters(parameter_node_objects, j)
							if func_name not in self.subcall_parameter_cache:
								param_list = []
								for i in range(func_name.getParameterCount()):
									param_list.append([])
								self.subcall_parameter_cache[func_name] = param_list
							if arg_idx < len(self.subcall_parameter_cache[func_name]):
								self.subcall_parameter_cache[func_name][arg_idx].append(replaced)

		if output is not None:
			if called_func not in backward_cache: # This means we want to backwards interpolate the return type
				##### START CALL RECURSIVE BACKWARDS ANALYSIS

				checkFixReturn(called_func, output)
				pci_new = PCodeInterpreter()
				ret_type, subfunc_parameter_varnodes = analyzeFunctionBackward(called_func, pci_new)
				backward_cache[called_func] = (ret_type, map(pci_new.lookup_node, subfunc_parameter_varnodes))

				##### END CALL RECURSIVE BACKWARDS ANALYSIS

			ret_type, subfunc_parameter_node_objs = backward_cache[called_func]
			replaced_rets = []
			for a in ret_type:
				for i in a:
					arg_idx = i.find_base_idx(subfunc_parameter_node_objs)
					if arg_idx is None:
						node_objects = [1] # Doesn't matter
					else:
						node_objects = self.lookup_node(inputs[1:][arg_idx])
					for j in node_objects:
						replaced_rets.append(i.replace_base_parameters(subfunc_parameter_node_objs, j))

			for i in range(len(replaced_rets)):
				self.store_node(output, replaced_rets[i])

	def copy(self, inputs, output):
		assert len(inputs) == 1 and output is not None
		for result in self.lookup_node(inputs[0]):
			self.store_node(output, result)

	def indirect(self, inputs, output):
		for value in self.lookup_node(inputs[0]):
			assert value.byte_length == output.getSize()
			self.store_node(output, value)

	# maps a Ghidra Varnode object to a binary tree object that represents its expression
	def lookup_node(self, varnode):
		# Detect cycle
		if varnode in self.cycle_exec:
			self.cycle_exec[varnode] += 1
		if varnode in self.cycle_exec and self.cycle_exec[varnode] > 0:
			if varnode not in self.nodes:
				self.store_node(varnode, Node(("CYCLE", varnode), None, None, varnode.getSize()))
			return self.nodes[varnode]
		if varnode.isConstant():
			# create constant node
			return [Node(varnode, None, None, varnode.getSize())]
		elif varnode.isAddress():
			return [Node(varnode, None, None, varnode.getSize())]
		elif varnode not in self.nodes or varnode in self.cycle_exec:
			# We have to detect cycles here, by temporarily storing "CYCLE", and if the returned value is "CYCLE", we know there is cycle
			if varnode not in self.cycle_exec:
				self.cycle_exec[varnode] = 0
			
			self.get_node_definition(varnode)

			if self.cycle_exec[varnode] == 0:
				del self.cycle_exec[varnode]

			return self.lookup_node(varnode)

		# Prune
		if len(self.nodes[varnode]) > NODE_LIMIT:
			self.nodes[varnode] = self.nodes[varnode][:NODE_LIMIT]
		return self.nodes[varnode]

	# recursively backwards traces for node's definition
	def get_node_definition(self, varnode):
		defining_instruction = varnode.getDef()
		if defining_instruction is None:
			print("WARNING: Orphaned varnode? - assuming multiequal analyzation error and skipping")
			self.nodes[varnode] = [Node("ORPHANED", None, None, varnode.getSize())]
			return
		self.process(defining_instruction, -1)

	# stores mapping between Ghidra varnode and binary tree obj
	def store_node(self, varnode, nodeobj):
		if varnode not in self.nodes:
			self.nodes[varnode] = []
		if hash(nodeobj) not in map(hash, self.nodes[varnode]):
			self.nodes[varnode].append(nodeobj)

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
	HighFunctionDBUtil.commitParamsToDatabase(hf, True, SourceType.DEFAULT)
	# reload cache
	del highfunction_cache[func]
	hf = get_highfunction(func)

	# Check arguments
	func_proto = hf.getLocalSymbolMap()
	if func_proto.getNumParams() != len(parameters) and not func.hasVarArgs():
		print(func, "call signature wrong...")
		raise Exception("Function call signature different")

	argument_varnodes = []
	for i in range(func_proto.getNumParams()):
		cur = func_proto.getParam(i).getRepresentative()
		if cur.getSize() != parameters[i].getSize():
			print(cur.getSize(), parameters[i].getSize())
			raise Exception("Func parameter size mismatch")	

# Make sure func signature matches the call
def checkFixReturn(func, ret_varnode):
	hf = get_highfunction(func)

	func_proto = hf.getFunctionPrototype()
	#  Check return types
	for i in hf.getPcodeOps():
		if i.getOpcode() == PcodeOp.RETURN:
			if len(i.getInputs()) < 2:
				print(func, "has no return value, fixing type...", i.getInputs()[0].getPCAddress())
				sig = func.getSignature()
				sig.setReturnType(Undefined.getUndefinedDataType(ret_varnode.getSize()))
				ApplyFunctionSignatureCmd(func.getEntryPoint(), sig, SourceType.USER_DEFINED).applyTo(currentProgram)

# This function performs backwards analysis on the function return type with base case of function parameters
# init_param replaces the parameters of the current func to be analyzed in terms the passed parameter expressions
def analyzeFunctionBackward(func, pci, init_param=None):
	print("Backwards analysis", func.getName())

	hf = get_highfunction(func)
	HighFunctionDBUtil.commitParamsToDatabase(hf, True, SourceType.DEFAULT)

	func_proto = hf.getFunctionPrototype()
	# Grab return varnodes
	return_varnodes = []
	for i in hf.getPcodeOps():
		if i.getOpcode() == PcodeOp.RETURN:
			if len(i.getInputs()) >= 2:
				return_varnodes.append(i.getInputs()[1])

	# Grab argument varnodes as base case
	argument_varnodes = []
	for i in range(func_proto.getNumParams()):
		argument_varnodes.append(func_proto.getParam(i).getRepresentative())

	# Sets argument as base cases
	for arg in range(len(argument_varnodes)):
		if init_param is None:
			pci.store_node(argument_varnodes[arg], Node("ARG"  + str(arg), None, None, argument_varnodes[arg].getSize()))
		else:
			pci.store_node(argument_varnodes[arg], init_param[arg])

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
		if child.getOutput() is not None and child.getOutput() not in visited:
			visited.add(child.getOutput())
			traverseForward(child.getOutput(), depth + 1, pci, visited)

# This function performs forward analysis on function parameters to determine its type (struct, array, or primitive)
def analyzeFunctionForward(func, pci):
	print("Forwards analysis", func.getName())
	hf = get_highfunction(func)
	HighFunctionDBUtil.commitParamsToDatabase(hf, True, SourceType.DEFAULT)
	print(func.getParameters())

	# get the varnode of function parameters
	func_proto = hf.getLocalSymbolMap()
	argument_varnodes = []
	argument_nodes = []
	for i in range(func_proto.getNumParams()):
		argument_varnodes.append(func_proto.getParam(i).getRepresentative())
		argument_nodes.append(Node("ARG"  + str(i), None, None, argument_varnodes[i].getSize()))

	hash_list = set()

	for a in range(2):
		print("Loop variants", map(id, pci.loop_variants))

		variant_vals = []
		new_nodes = {}

		for i in pci.loop_variants:
			new_nodes[i] = pci.nodes[i]
			del pci.nodes[i]
		visited = set()

		pci.nodes = new_nodes

		for arg in range(len(argument_varnodes)):
			pci.store_node(argument_varnodes[arg], argument_nodes[arg])

		# recursively traverse the varnode descendants to get reaching definitions
		for i in argument_varnodes:
			traverseForward(i, 0, pci, visited)

		if a == 0:
			for i in pci.stores + pci.loads:
				hash_list.add(hash(i))
			continue

		temp = pci.stores + pci.loads

		for i in range(len(temp))[::-1]:
			if hash(temp[i]) not in hash_list:
				pci.arrays.append(temp[i])
				print("FOUND ARRAY!")

	return argument_varnodes
