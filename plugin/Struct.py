#!/usr/bin/env python3
# @category: GEARSHIFT.internal

from __future__ import print_function

from ghidra.program.model.data import StructureDataType, CategoryPath, DataTypeConflictHandler, PointerDataType, BuiltInDataTypeManager, ArrayDataType

class Struct(object):
	def __init__(self, size):
		self.size = size # Total size of the struct
		self.members = [(0, 1)] * size # Represents member (value, member_size)
		self.marked = [False] * size # Marked represents offsets in the struct that are accessed
		self.is_array = False
		global struct_counter
		self.name = "S{}".format(struct_counter)
		struct_counter += 1
		self.dtype = None
		self.pretty = None

	def get_dtype(self):
		if self.dtype is not None:
			return self.dtype
		dm = currentProgram.getDataTypeManager()
		bdm = BuiltInDataTypeManager.getDataTypeManager()
		new_struct = StructureDataType(CategoryPath("/struct"), self.name, self.size)
		size_lookup = {}
		size_lookup[1] = bdm.getDataType("/char")
		size_lookup[2] = bdm.getDataType("/short")
		size_lookup[4] = bdm.getDataType("/int")
		size_lookup[8] = bdm.getDataType("/longlong")
		off = 0
		for i in range(len(self.members)):
			t, size = self.members[i][0], self.members[i][1]
			comment = ""
			if len(self.members[i]) > 2 and self.members[i][2] == False:
				comment = "NOT ACCESSED"
			if isinstance(t, Struct):
				if not t.is_array:
					sub_struct_dtype = t.get_dtype()
					new_struct.replaceAtOffset(off, sub_struct_dtype, ARCH_BITS / 8, "entry_{}".format(i), comment)
				else:
					arr_dtype = bdm.getPointer(size_lookup[1], ARCH_BITS / 8)
					new_struct.replaceAtOffset(off, arr_dtype, ARCH_BITS / 8, "entry_{}".format(i), comment)
			else:
				if size not in size_lookup:
					arr_dtype = ArrayDataType(size_lookup[1], size, 1)
					new_struct.replaceAtOffset(off, arr_dtype, size, "entry_{}".format(i), comment)
				else:
					new_struct.replaceAtOffset(off, size_lookup[size], size, "entry_{}".format(i), comment)
			off += size
		print("DONE CREATING STRUCT", self.name)
		dm.addDataType(new_struct, DataTypeConflictHandler.REPLACE_HANDLER)
		self.dtype = dm.getPointer(new_struct, ARCH_BITS / 8)
		return self.dtype

	def __str__(self):
		return str(self.members)

	def __repr__(self):
		return self.__str__()

	def make_array(self):
		print("Making array")
		print(self.members)
		self.is_array = True
		stride = self.members[0][1]
		self.stride = stride

	# Consolidates struct members of size 1 into a char array
	def consolidate(self):
		new_members = []
		consolidate_length = 0
		cur_offset = 0
		for i in self.members:
			if self.marked[cur_offset] is True:
				if consolidate_length != 0:
					new_members.append((0, consolidate_length, False))
					consolidate_length = 0
				new_members.append(i)
			else:
				consolidate_length += 1
			cur_offset += i[1]
		if consolidate_length != 0:
			new_members.append((0, consolidate_length))
			consolidate_length = 0
		self.members = new_members

	def mark(self, start, end):
		for i in range(start, end):
			self.marked[i] = True

	# Indicates that there is a struct member (value, member_size) at given offset
	def insert(self, offset, member):
		c = 0
		idx = 0
		# find member
		while c < offset:
			c += self.members[idx][1]
			idx += 1
		if c != offset:
			print("Misaligned buf")
			self.break_member(idx - 1)
			self.insert(offset, member)
			return

		# combine
		c = 0
		temp = idx
		while c < member[1]:
			c += self.members[idx][1]
			idx += 1
		if c != member[1]:
			# Misaligned struct and data size accesses - might be an array?
			print("Misaligned buf")
			self.break_member(idx - 1)
			self.insert(offset, member)
			return
		c = 0
		idx = temp
		while c < member[1]:
			c += self.members[idx][1]
			del self.members[idx]
		self.members.insert(idx, member)
		self.mark(offset, offset + member[1])

	def merge_until(self, idx, until):
		total_length = 0
		while idx < len(self.members) and self.members[idx][0] != until:
			total_length += self.members[idx][1]
			del self.members[idx]
		self.members.insert(idx, (0, total_length))

	# Breaks apart the member at index self.members[idx]
	def break_member(self, idx):
		assert not isinstance(self.members[idx][0], Struct)
		size = self.members[idx][1]
		del self.members[idx]
		for i in range(size):
			self.members.insert(idx, (0, 1))

	# Fetches member at given offset, and breaks apart member if there is member alignment conflict
	def get(self, offset):
		c = 0
		idx = 0
		while c < offset:
			c += self.members[idx][1]
			idx += 1
		if c != offset:
			# Same issue as insert
			print(self.members[idx - 1][1])
			print(c)
			print("Get issue", self.members[idx - 1])
			self.break_member(idx - 1)
			ret = self.get(offset)
			return ret
		self.mark(offset, offset + self.members[idx][1])
		return self.members[idx]

	# Only fetches member at given offset
	def get2(self, offset):
		c = 0
		idx = 0
		while c < offset:
			c += self.members[idx][1]
			idx += 1
		if c != offset:
			return -1
		return self.members[idx][0]

	# Extends the size of the struct
	def extend(self, length):
		while self.size < length:
			self.size += 1
			self.members.append((0, 1))
			self.marked.append(False)

	def get_field(self, length, entry_num):
		if length <= 8 and length & 1 == 0:
			return "uint{}_t entry_{};".format(length * 8, entry_num)
		elif length == 1:
			return "char entry_{};".format(entry_num)
		else:
			return "char entry_{}[{}];".format(entry_num, length)

	def pretty_print(self):
		if self.pretty is not None:
			return self.pretty
		self.consolidate()

		# first, we detect if it's size 0, or only has one member
		if self.size == 0:
			return ""
		elif len(self.members) == 1:
			return ""

		res = "struct {} {{\n".format(self.name)

		c = -1
		length = 0
		entry_counter = -1
		while length < self.size:
			c += 1
			entry_counter += 1
			if isinstance(self.members[c][0], Struct):
				length += ARCH_BITS / 8
				if not self.members[c][0].is_array:
					res += "struct {}* entry_{};\n".format(self.members[c][0].name, entry_counter)
					res = self.members[c][0].pretty_print() + "\n" + res
				else:
					res += "uint{}_t* entry_{};\n".format(self.members[c][0].stride * 8, entry_counter)
			else:
				res += self.get_field(self.members[c][1], entry_counter) + "\n"
				if len(self.members[c]) > 2:
					res = res[:-1] + " //NOT ACCESSED\n"
				length += self.members[c][1]
		self.pretty = res + "};"
		return self.pretty

class Generator(object):
	def __init__(self):
		self.allocation_counter = 0

	def _new_allocation(self):
		alloc = "allocation{}".format(self.allocation_counter)
		self.allocation_counter += 1
		return alloc

	def _do_read(self, struct, current_reference):
		ret = ""
		clean = ""

		if not struct.is_array:
			curoff = 0
			total_length = 0
			for i in range(len(struct.members)):
				total_length += struct.members[i][1]

			current_allocation = self._new_allocation()
			ret += "void* {} = malloc({});\n".format(current_allocation, total_length)
			ret += "{} = (struct {}*){};\n".format(current_reference, struct.name, current_allocation)
			for i in range(len(struct.members)):
				value = struct.members[i][0]
				length = struct.members[i][1]
				if type(value) is int and value & 0xff == 0x0:
					ret += "fread((void*)&{}->entry_{}, 1, {}, h);\n".format(current_reference, i, length)
				elif type(value) is int and value & 0xff == 0x1:
					entry_allocation = self._new_allocation()
					ret += "void* {} = malloc({});\n".format(entry_allocation, (value >> 8) + 1)
					ret += "{}->entry_{} = (char*){};\n".format(current_reference, i, entry_allocation);
					ret += "{}->entry_{}[{}] = 0;\n".format(current_reference, i, (value >> 8));
					ret += "fread({}->entry_{}, 1, {}, h);\n" .format(current_reference, i, value >> 8)
					clean += "free({});\n".format(entry_allocation)
				else:
					r, c = self._do_read(value, current_reference + "->entry_{}".format(i))
					ret += r
					clean += c
				curoff += length
			clean += "free({});\n".format(current_allocation)
		else:
			current_allocation = self._new_allocation()
			ret += "void* {} = malloc({});\n".format(current_allocation, 8 * struct.stride)
			ret += "{} = (char*){};\n".format(current_reference, current_allocation)
			ret += "fread((char*){}, 1, {}, h);\n".format(current_reference, 8 * struct.stride);
			clean += "free({});\n".format(current_allocation)
		return ret, clean

	def generate_struct_reader(self, args):
		code = ""
		cleanup = ""
		arg_names = []
		for i in range(len(args)):
			arg_names.append("arg_{}".format(i))
			if args[i].size == 0:
				# this is an int
				code += args[i].get_field(ARCH_BITS / 8, 0).replace("entry_0", "arg_{}".format(i)) + "\n"
				code += "fread(&arg_{}, 1, 8, h);\n".format(i)
			elif len(args[i].members) == 1:
				# this is a primitive pointer
				code += args[i].get_field(ARCH_BITS / 8, 0).replace("entry_0", "temp_arg_{}".format(i)) + "\n"
				code += args[i].get_field(ARCH_BITS / 8, 0).replace("entry_0", "*arg_{}".format(i))[:-1] + " = &temp_arg_{};\n".format(i)
				code += "fread(arg_{}, 1, 8, h);\n".format(i)
			else:
				cur = args[i]
				if isinstance(cur, Struct) and not cur.is_array:
					# struct
					code += "struct {}* arg_{};\n".format(cur.name, i)
					res, clean = self._do_read(cur, "arg_{}".format(i))
					code += res
					cleanup += clean
				else:
					# array
					array_length = 8
					code += "char* {} = (char*)malloc({});\n".format(arg_names[-1], array_length + 1)
					code += "{}[{}] = 0;\n".format(arg_names[-1], array_length)
					code += "fread({}, 1, {}, h);\n".format(arg_names[-1], array_length)
					cleanup += "free({});\n".format(arg_names[-1])
		return code, cleanup, ", ".join(arg_names)

def generate_struct_reader(args):
	generator = Generator()
	return generator.generate_struct_reader(args)
