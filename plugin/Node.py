#!/usr/bin/env python3
# @category: GEARSHIFT.internal

from __future__ import print_function

from Struct import Struct
from ghidra.program.model.pcode import Varnode

# Abstract binary operation tree that stores the symbolic expression
class Node:
	def __init__(self, operation, left, right, byte_length):
		self.left = left
		self.right = right
		self.operation = operation
		self.byte_length = byte_length

	def traverse_struct(self, struct):
		if self.is_leaf() and str(self.operation).startswith("ARG"):
			return struct, 0
		elif self.operation == "+":
			assert isinstance(self.left, Node)
			res, off = self.left.traverse_struct(struct)
			return res, off + self.right.operation.getOffset()
		elif self.operation == "*()":
			assert isinstance(self.left, Node)
			res, off = self.left.traverse_struct(struct)
			return res.get2(off), 0
		elif self.operation == "RESIZE":
			return self.left.traverse_struct(struct)
		else:
			print("Not yet supported", self.operation)
			raise ValueError("Not yet supported")

	# (Object reference, reference offset, (Grandparent struct, grandparent offset))
	# Creates the struct specified in arg_struct_list
	# The intuition is that when we encounter a pointer, we also hold a pointer to that pointer (grandparent). Therefore if a pointer is dereferenced and that pointer is not yet marked a struct, then we use grandparent to change it into a struct
	# Otherwise, we just keep track of the current offsets into the current struct and recursive base case is the argument struct.
	def create_struct(self, arg_struct_list, parent_byte_length):
		if self.is_leaf() and str(self.operation).startswith("ARG"):
			arg_idx = int(self.operation[3:])
			return (arg_struct_list[arg_idx], 0, None)
		elif self.operation == "+":
			assert isinstance(self.left, Node)
			sub_struct, offset, grand = self.left.create_struct(arg_struct_list, self.byte_length)
			if isinstance(self.right, Node):
				if not isinstance(self.right.operation, Varnode) or not self.right.operation.isConstant():
					raise ValueError("Complex expression, skipping")
				if self.right.operation.getOffset() & (1 << (self.right.operation.getSize() * 8 - 1)) != 0:
					raise ValueError("Negative constaints not supported yet")
				offset += self.right.operation.getOffset()
			else:
				if not self.right.isConstant():
					print("Non constant indexed detected: Possible array?")
				else:
					raise Exception("Shouldn't happen")
			return (sub_struct, offset, grand)
		elif self.operation == "*()":
			assert isinstance(self.left, Node)
			sub_struct, offset, grand = self.left.create_struct(arg_struct_list, self.byte_length)
			if not isinstance(sub_struct, Struct):
				temp = Struct(offset + parent_byte_length)
				grand[0].insert(grand[1], (temp, ARCH_BITS / 8))
				sub_struct, offset, grand = self.left.create_struct(arg_struct_list, self.byte_length)
				sub_struct = temp
			sub_struct.extend(offset + parent_byte_length)
			if sub_struct.get(offset)[1] == 1:
				sub_struct.insert(offset, (0, parent_byte_length))
			return (sub_struct.get(offset)[0], 0, (sub_struct, offset))
		elif self.operation == "RESIZE":
			return self.left.create_struct(arg_struct_list, self.byte_length)
		else:
			print("Not yet supported", self.operation)
			raise ValueError("Not yet supported")

	def __str__(self):
		if self.is_leaf():
			return str(self.operation)
		elif self.operation == "*()":
			return "*({})".format(str(self.left))
		elif self.operation == "RESIZE":
			return "(uint{}_t)({})".format(self.byte_length * 8, str(self.left))
		elif self.operation == "~":
			return "~({})".format(str(self.left))
		else:
			return str(self.left) + " " + self.operation + " " + str(self.right)

	def __repr__(self):
		return '"' + self.__str__() + '"'

	def __hash__(self):
		ret = hash(str(self))
		return ret

	def relevant(self):
		good = self.operation in ("+", "*()", "RESIZE", "*") or (self.is_leaf() and str(self.operation).startswith("ARG")) or (isinstance(self.operation, Varnode) and self.operation.isConstant()) or self.is_varnode_constant()
		if isinstance(self.left, Node):
			good = good and self.left.relevant()
		if isinstance(self.right, Node):
			good = good and self.right.relevant()
		return good

	def contains(self, nodes):
		if self is None:
			return False
		return self in nodes or (isinstance(self.left, Node) and self.left.contains(nodes)) or (isinstance(self.right, Node) and self.right.contains(nodes))

	def find_base_idx2(self):
		if self.is_leaf() and str(self.operation).startswith("ARG"):
			return int(str(self.operation).split("ARG")[1])
		res = None
		if isinstance(self.left, Node) and res is None:
			res = self.left.find_base_idx2()
		if isinstance(self.right, Node) and res is None:
			res = self.right.find_base_idx2()
		return res

	def find_base_idx(self, old_params):
		if self in old_params:
			idx = old_params.index(self)
			return idx
		res = None
		if isinstance(self.left, Node) and res is None:
			res = self.left.find_base_idx(old_params)
		if isinstance(self.right, Node) and res is None:
			res = self.right.find_base_idx(old_params)
		return res

	#replaces instances of old_params in the binary tree with instance in new_params, and makes a copy of all nodes
	def replace_base_parameters(self, old_params, new_param):
		if self in old_params:
			return new_param
		ret = self.shallow_copy()
		if isinstance(ret.left, Node):
			ret.left = ret.left.replace_base_parameters(old_params, new_param)
		if isinstance(ret.right, Node):
			ret.right = ret.right.replace_base_parameters(old_params, new_param)
		return ret

	def is_varnode_constant(self):
		return isinstance(self.operation, Varnode) and self.operation.isConstant()

	def _simplify(self):
		# TODO: better simplification in the future
		changed = False
		ret = self.shallow_copy()
		if ret.left is not None:
			ret.left, c = ret.left._simplify()
			changed |= c
		if ret.right is not None:
			ret.right, c = ret.right._simplify()
			changed |= c
		if ret.operation == "*" and (self.left.is_varnode_constant()) and (self.right.is_varnode_constant()) and ret.left.operation.getSize() == ret.right.operation.getSize():
			temp = ret.left.operation
			temp2 = ret.right.operation
			ret = Node(Varnode(temp.getAddress().getNewAddress(temp.getOffset() * temp2.getOffset()), temp.getSize()), None, None, temp.getSize())
			return ret, True
		elif ret.operation == "+" and (self.left.is_varnode_constant()) and (self.right.is_varnode_constant()) and ret.left.operation.getSize() == ret.right.operation.getSize():
			temp = ret.left.operation
			temp2 = ret.right.operation
			ret = Node(Varnode(temp.getAddress().getNewAddress(temp.getOffset() + temp2.getOffset()), temp.getSize()), None, None, temp.getSize())
			return ret, True
		elif ret.operation == "RESIZE" and self.left.is_varnode_constant():
			return Node(Varnode(ret.left.operation.getAddress(), ret.byte_length), ret.left.left, ret.left.right, ret.byte_length), True
		return ret, changed

	def simplify(self):
		s, c = self._simplify()
		while c:
			s, c = s._simplify()
		return s

	def shallow_copy(self):
		ret = Node(self.operation, self.left, self.right, self.byte_length)
		return ret

	def deep_copy(self):
		left = self.left
		right = self.right
		if isinstance(left, Node):
			return left.deep_copy()
		if isinstance(right, Node):
			return rigth.deep_copy()
		return Node(self.operation, left, right, self.byte_length)

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

	def eq(self, other):
		return Node("==", self, other, self.byte_length)

	def neq(self, other):
		return Node("neq", self, other, self.byte_length)

	def lt(self, other):
		return Node("<", self, other, self.byte_length)

	def le(self, other):
		return Node("<=", self, other, self.byte_length)

	def slt(self, other):
		return Node("s<", self, other, self.byte_length)

	def sle(self, other):
		return Node("s<=", self, other, self.byte_length)

	def neg(self):
		return Node("~", self, None, self.byte_length)

	def sdiv(self, other):
		return Node("s/", self, other, self.byte_length)

	def smod(self, other):
		return Node("s%", self, other, self.byte_length)

	def mod(self, other):
		return Node("%", self, other, self.byte_length)

	def sshr(self, other):
		return Node("s>>", self, other, self.byte_length)
