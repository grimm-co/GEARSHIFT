import hashlib
from config import *

#x8664_args = ["VRDI", "VRSI", "VRDX", "VRCX"]

struct_hashes = {}
arguments = {}
printed = set()
c = open(output_source, "w")
struct_string = ""
args_list = []

n = 0

# gets the struct modifier based on member type and size
def get_modifier(member):
	if type(member[0]) is int:
		if member[0] & 0xff== 0x0: # int
			if member[1] == 4:
				return "uint32_t"
			elif member[1] == 8:
				return "uint64_t"
		elif member[0] & 0xff == 0x1: # buf
			return "char*"
	elif type(member[0]) is Struct:
		return str(member[0]) + "*"

# A struct is defined by a name, id in the order of creation, and offsets of members
# The class's members list store values and/or pointer to structs with the size of each member
# insert_member consolidates current member list if necessary to insert a new member
# get_struct_at_off fetches the struct pointer member at some offset
class Struct:
	def __init__(self, name, offsets, id):
		print("Create", name, offsets)
		self.name = name
		self.members = []
		self.id = id
		for i in range(len(offsets) - 1):
			member_length = offsets[i + 1] - offsets[i]
			self.members.append((0x0, member_length))
		self.members.append((0x0, 8))

	def insert_member(self, member_size, offset, value):
		print("Inserting", member_size, offset, "into", self.name, self.members)
		c = 0
		length = 0
		while length < offset:
			length += self.members[c][1]
			c += 1
		if length != offset:
			raise Exception("Offset mismatch")
		replace = 0
		while replace < member_size:
			replace += self.members[c][1]
			del self.members[c]
		self.members.insert(c, (value, member_size))

	def __str__(self):
		return self.name + str(self.id)

	def get_struct_at_off(self, offset):
		print("fetch struct at off", self.name, offset, self.members)
		c = 0
		length = 0
		while length < offset:
			length += self.members[c][1]
			c += 1
		ret = self.members[c][0]
		if type(ret) is int:
			raise Exception("Dereference is primitive")
		return ret

	def pp(self):
		res = ""
		res += "typedef struct {\n"
		for i in range(len(self.members)):
			cur = self.members[i]
			res += "\t" + get_modifier(cur) + " entry_" + str(i) + ";\n"
		res += "} " + str(self) + ";\n"
		return res
	
	def get_hash(self):
		h = 0
		for i in range(len(self.members)):
			if self.members[i][0] == 0:
				h = 31 * h + self.members[i][1]
			else:
				h = 31 * h + (int(hashlib.md5(str(self.members[i][0]).encode()).hexdigest(), 16) & 0xff)
		return h

# finds the depth of a struct description key
def get_depth(key, depth):
	idx = key.find("(")
	if idx == -1:
		return depth + 1
	name = key[:idx + 1]
	child = key[idx + 1:]
	return depth + get_depth(child, depth) + 1

def get_member_length(name):
	if name.startswith("V"):
		return 8
	elif name.startswith("W"):
		return 4

# parses a key for top level name, child descriptor key, and child offset
def parse_key(key):
	start = key.find("(")
	end = len(key) + 1
	if start == -1:
		off = 0
		if "+" in key:
			start = key.find("+")
			off = int(key[start + 1:])
		else:
			start = len(key) + 1
		return key[:start], off, ""
	else:
		end = len(key) - key[::-1].find(")")
	name = key[:start]
	offset = 0
	child = key[start + 1:end - 1]
	off = key[end:]
	if len(off) != 0:
		offset = int(off)	
	print(key, name, offset, child)
	return name, offset, child

# finds the struct a descriptor key is referring to by propagation from the lowest level up and dereferencing the struct at some offset at each level until it reaches the top
def find_struct(key):
	name, offset, child = parse_key(key)
	if len(child) == 0:
		return arguments[name], offset
	else:
		child_struct, child_struct_offset = find_struct(child)
		return child_struct.get_struct_at_off(child_struct_offset), offset

# sets the value referred to by key
def set_value(key, val, top_level=False):
	name, offset, child = parse_key(key)
	if len(child) == 0:
		if name not in arguments:
			# this is an array
			arguments[name] = val
		return arguments[name], offset
	else:
		child_struct, child_struct_offset = set_value(child, val)
		if not top_level:
			return child_struct.get_struct_at_off(child_struct_offset), offset
		else:
			child_struct.insert_member(0x8, child_struct_offset, val)

# builds a struct for the current descriptor key
def build_struct(tup):
	key = tup[1]
	offsets = tup[2]

	name, offset, child = parse_key(key)

	global n
	struct = Struct(name, offsets, n)
	if struct.get_hash() in struct_hashes:
		struct = struct_hashes[struct.get_hash()]
	n += 1
	arguments[name] = struct
	struct_hashes[struct.get_hash()] = struct

	if len(child) > 0:
		child_struct, offset = find_struct(child)
		print(child, offset)
		child_struct.insert_member(get_member_length(name), offset, struct)
	return struct

# structs is a list of tuples of the form (key, Offsets)
# this returns a list of structs
def converter(structs, num_args):
	depth_sorted = []
	result = []
	# assign recursive struct depth to each key
	for i in range(len(structs)):
		key = structs[i][0]
		offsets = structs[i][1]
		depth = get_depth(key, 0)
		depth_sorted.append((depth, key, offsets))
	depth_sorted.sort()
	for i in range(len(depth_sorted)):
		# parse and create structs
		struct = build_struct(depth_sorted[i])
		result.append(struct)
	return result

def do_read(struct, current_reference):
	ret = ""
	clean = ""
	curoff = 0
	total_length = 0
	for i in range(len(struct.members)):
		total_length += struct.members[i][1]
	ret += "{} = ({}*)malloc({});\n".format(current_reference, str(struct), total_length)
	for i in range(len(struct.members)):
		value, length = struct.members[i]
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
	if struct.get_hash() not in printed:
		global struct_string
		struct_string += struct.pp()
		printed.add(struct.get_hash())
	return ret, clean

def generate_struct_reader(nargs):
	code = ""
	cleanup = ""
	for i in range(nargs):
		args_list.append(x8664_args[i])
		if x8664_args[i] not in arguments:
			# this is an int
			code += "uint64_t {};\n".format(x8664_args[i]);
			code += "fread(&{}, 1, 8, h);\n".format(x8664_args[i])
		else:
			cur = arguments[x8664_args[i]]
			if type(cur) is Struct:
				# struct
				code += str(cur) + "* " + x8664_args[i] + ";\n"
				res, clean = do_read(cur, x8664_args[i])
				code += res
				cleanup += clean
			else:
				# array
				code += "char* {} = (char*)malloc({});\n".format(x8664_args[i], (cur >> 8) + 1)
				code += "{}[{}] = 0;\n".format(x8664_args[i], cur >> 8)
				code += "fread({}, 1, {}, h);\n".format(x8664_args[i], cur >> 8)
				cleanup += "\tfree({});\n".format(x8664_args[i])
	return code, cleanup

out = open("output", "r").read().strip().split("\n")
structs = []
arrs = []
log = False
num_args = 0
arch = ""
base = 0x0
for i in out:
	if log:
		if "Array: " in i:
			first = i.split("Base: ")[1].split(", ")[0]
			second = int(i.split("bytes: ")[1])
			arrs.append((first, second))
		elif "Struct: " in i:
			first = i.split("Struct: ")[1].split(" | ")[0]
			second = eval(i.split(" | ")[1])
			structs.append((first, second))
		elif "Params: " in i:
			num_args = int(i.split("Params: ")[1].strip())
		elif "Program: " in i:
			arch = i.split("Program: ")[1]
		elif "Base Addr: " in i:
			base = int(i.split(": ")[1])
		else:
			log = False

	if "Address: " in i and int(i.split("Address: ")[1]) == function_offset:
		log = True

c = open(output_source, "w")

print("ARCH", arch)

# key, list of offsets
#structs = [("V(V(VRDI+8)+24)", [0, 4, 8, 12]), ("V(V(VRDI+8)+16)", [0, 4, 8, 12]), ("V(VRDI+8)", [0, 8, 16, 24]), ("VRDI", [0, 4, 8])]
# key, size of array (might be inaccurate)
#arrs = [("V(V(VRDI+8))", 6)]
# create structs
res = converter(structs, num_args)
# set arrays
for i in arrs:
	set_value(i[0], 0x1 | (i[1] << 8), True)
code, cleanup = generate_struct_reader(num_args)
final = template.format(structs=struct_string, process_path=process_path.replace("\\", "\\\\"), code=code.replace("\n", "\n\t"), func_offset=hex(function_offset), args=", ".join(args_list), cleanup=cleanup)
c.write(final)
c.close()
