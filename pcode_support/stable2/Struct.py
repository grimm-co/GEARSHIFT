class Struct:
	def __init__(self, size):
		self.size = size # Total size of the struct
		self.members = [(0, 1)] * size # Represents member (value, member_size)
		self.marked = [False] * size # Marked represents offsets in the struct that are accessed
		self.is_array = False

	def __str__(self):
		return str(self.members)

	def __repr__(self):
		return self.__str__()

	def make_array(self):
		self.is_array = True
		stride = self.members[0][1]
		for i in range(len(self.members)):
			if self.members[i][1] != stride:
				raise Exception("Array stride different")
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
			# self.merge_until(idx - 1, member)
			raise Exception("Merging")
			return

		# combine
		c = 0
		temp = idx
		while c < member[1]:
			c += self.members[idx][1]
			idx += 1
		if c != member[1]:
			# Misaligned struct and data size accesses - might be an array?
			# TODO: better solution later to mark data as array? For now we break the conflicting type and reinsert
			print("Misaligned buf")
			self.break_member(idx - 1)
			self.insert(offset, member)
			# self.merge_until(idx - 1, member)
			raise Exception("Merging")
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
		while self.members[idx][0] != until:
			total_length += self.members[idx][1]
			del self.members[idx]
		self.members.insert(idx, (0, total_length))

	# Breaks apart the member at index self.members[idx]
	def break_member(self, idx):
		# TODO: figure out why this assertion fails sometimes
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
			# TODO: instead of breaking, we should truncate conflicting member instead
			self.break_member(idx - 1)
			ret = self.get(offset)
			self.merge_until(idx - 1, ret)
			raise Exception("Merging")
			return ret
		self.mark(offset, offset + self.members[idx][1])
		return self.members[idx]

	# Extends the size of the struct
	def extend(self, length):
		while self.size < length:
			self.size += 1
			self.members.append((0, 1))
			self.marked.append(False)

	def get_field(self, length, entry_num):
		if length <= 8 and length & 1 == 0:
			return "\tuint{}_t entry_{}".format(length * 8, entry_num)
		elif length == 1:
			return "\tchar entry_{}".format(entry_num)
		else:
			return "\tchar entry_{}[{}]".format(entry_num, length)

	def pretty_print(self):
		self.consolidate()
		global struct_counter
		res = "struct S{} {{\n".format(struct_counter)
		self.name = "S{}".format(struct_counter)
		struct_counter += 1

		c = -1
		length = 0
		entry_counter = -1
		while length < self.size:
			c += 1
			entry_counter += 1
			if isinstance(self.members[c][0], Struct):
				length += ARCH_BITS / 8
				if not self.members[c][0].is_array:
					res += "\tS{}* entry_{}\n".format(struct_counter, entry_counter)
					res = self.members[c][0].pretty_print() + "\n" + res
					continue
				else:
					res += "\tuint{}_t* entry_{}\n".format(self.members[c][0].stride * 8, entry_counter)
					continue
			res += self.get_field(self.members[c][1], entry_counter) + "\n"
			if len(self.members[c]) > 2:
				res = res[:-1] + " NOT ACCESSED\n"
			length += self.members[c][1]
		return res + "}"

def do_read(struct, current_reference):
	ret = ""
	clean = ""

	if not struct.is_array:
		curoff = 0
		total_length = 0
		for i in range(len(struct.members)):
			total_length += struct.members[i][1]
		ret += "{} = ({}*)malloc({});\n".format(current_reference, struct.name, total_length)
		for i in range(len(struct.members)):
			value = struct.members[i][0]
			length = struct.members[i][1]
			if type(value) is int and value & 0xff == 0x0:
				ret += "fread((char*)&{}->entry_{}, 1, {}, h);\n".format(current_reference, i, length)
			elif type(value) is int and value & 0xff == 0x1:
				# TODO: better array length
				ret += "{}->entry_{} = (char*)malloc({});\n".format(current_reference, i, (value >> 8) + 1);
				ret += "{}->entry_{}[{}] = 0;\n".format(current_reference, i, (value >> 8));
				ret += "fread({}->entry_{}, 1, {}, h);\n" .format(current_reference, i, value >> 8)
				clean += "\tfree({}->entry_{});".format(current_reference, i)
			else:
				r, c = do_read(value, current_reference + "->entry_{}".format(i))
				ret += r
				clean += c
			curoff += length
		clean += "free({});\n".format(current_reference)
	else:
		ret += "{} = (char*)malloc({});\n".format(current_reference, 8 * struct.stride)
		ret += "fread((char*){}, 1, {}, h);\n".format(current_reference, 8 * struct.stride);
		clean += "\tfree({});\n".format(current_reference)
	return ret, clean

def generate_struct_reader(args):
	code = ""
	cleanup = ""
	arg_names = []
	for i in range(len(args)):
		if False:
			# this is an int
			code += "uint64_t {};\n".format(x8664_args[i]);
			code += "fread(&{}, 1, 8, h);\n".format(x8664_args[i])
		else:
			cur = args[i]
			if isinstance(cur, Struct) and not cur.is_array:
				# struct
				arg_names.append("ARG{}".format(i))
				code += cur.name + "* ARG{};\n".format(i)
				res, clean = do_read(cur, "ARG{}".format(i))
				code += res
				cleanup += clean
			else:
				# array
				raise Exception("ARR")
				code += "char* {} = (char*)malloc({});\n".format(x8664_args[i], (cur >> 8) + 1)
				code += "{}[{}] = 0;\n".format(x8664_args[i], cur >> 8)
				code += "fread({}, 1, {}, h);\n".format(x8664_args[i], cur >> 8)
				cleanup += "\tfree({});\n".format(x8664_args[i])
	return code, cleanup, ", ".join(arg_names)
