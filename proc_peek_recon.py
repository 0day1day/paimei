#
# IDA Python Proc Peek Recon
# Locate all potentially interesting points and dump to file.
#
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: proc_peek_recon.py 236 2010-03-05 18:16:17Z pedram.amini $
#
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program; if not, write to the Free
# Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

'''
@author:       Pedram Amini
@license:      GNU General Public License 2.0 or later
@contact:      pedram.amini@gmail.com
@organization: www.openrce.org
'''

from idaapi   import *
from idautils import *
from idc      import *

########################################################################################################################
### Support Functions
###

#
# Type define the argument data type; 
# S -> string
# I -> num
#
def get_arg(ea, arg_num, type):
	arg_index = 1

	while True:
		ea = PrevNotTail(ea)
		if GetMnem(ea) == "push":
			if arg_index == arg_num:
			
				# string parameter
				if type == 'S':
					dref = Dfirst(ea)
					if dref == BADADDR:
						return dref
					return read_string(dref)
			
				# number parameter
				elif type == 'I': 
					return read_size(ea)

			arg_index += 1
	
def instruction_match (ea, mnem=None, op1=None, op2=None, op3=None):
    if mnem and mnem != GetMnem(ea):
		return False
		
    if op1 and op1 != GetOpnd(ea, 0): return False
    if op2 and op2 != GetOpnd(ea, 1): return False
    if op3 and op3 != GetOpnd(ea, 2): return False

    return True

def disasm_match (ea, needle):
    disasm_line = GetDisasm(ea)

    # collapse whitespace
    while disasm_line.find("  ") != -1:
        disasm_line = disasm_line.replace("  ", " ")

    if disasm_line.find(needle) == -1:
        return False

    return True

def read_size(ea):
	s = GetOpnd(ea, 0)
	if s.endswith("h"):
		return int(s.rstrip('h'), 16)
	else:
		return BADADDR


def read_string (ea):
	s = ""
	string_type = GetStringType(ea)
	if string_type == ASCSTR_C:
		while True:
			byte = Byte(ea)

			if byte == 0: #or byte < 32 or byte > 126:
				break
				
			if byte == 0x0d: s += "<CR>"
			elif byte == 0x0a: s += "<LF>"
			else: s += chr(byte)
			
			ea += 1
		return s
	elif string_type == ASCSTR_UNICODE:
		#TODO
		while True:
			word = Word(ea)
			if byte == 0:
				break
			else: s += word
			ea += 2
		return "unicode string: " + s
			
	elif string_type == ASCSTR_PASCAL:
		byte = Byte(ea)
		for i in range (1, byte):
			s += Byte(ea)
		return "pascal string: " + s
	
	

def token_count (format_string):
    return format_string.count("%") - format_string.count("%%")

########################################################################################################################
### Meat and Potatoes
###

peek_filename = AskFile(1, "*.recon", "Proc Peek Recon Filename?")
peek_file     = open(peek_filename, "w+")

#ida_log   = lambda x: None
ida_log    = lambda x: sys.stdout.write("RECON> " + x + "\n")
write_line = lambda x: peek_file.write("%s\n" % x)

window = state = found_ea = processed = 0

ida_log("searching for inline memcpy()'s and sign extended moves (movsx).")

for ea in Heads(MinEA(), MaxEA()):
	processed += 1
  
	# rep movsd : rep movsd [edi], [esi] : eax = memcpy(edi, esi, ecx)
	# rep stosd : rep stosd [edi], eax : eax = memset(edi, eax, ecx)
	# rep scasd : rep scasd [edi] : eax = strchr(edi, eax)
	
	# we don't care about instructions within known library routines.
	# if GetFunctionFlags(ea) and GetFunctionFlags(ea) & FUNC_LIB:
	if GetFunctionFlags(ea) & FUNC_LIB:
		continue

	if disasm_match(ea, "movsx"):
		ida_log("%08x: found sign extended move" % ea)
		set_cmt(ea, "sign extended move", False)
		write_line("%08x:sign extended move" % ea)
	elif state == 0 and instruction_match(ea, "shr", "ecx", "2"):
		state = 1
		window = 0
	elif state == 1 and disasm_match(ea, "rep movsd"):
		state = 2
		window = 0
		found_ea = ea
	elif state == 2 and instruction_match(ea, "and", "ecx", "3"):
		state  = 3
		window = 0
	elif state == 3 and disasm_match(ea, "rep movsb"):
		ida_log("%08x: found memcpy" % found_ea)
		set_cmt(ea, "inline memcpy()", False)
		write_line("%08x: inline memcpy" % found_ea)
		found_ea = state = window = 0

	if window > 15:
		state = window = 0
	
	if state != 0:
		window += 1

ida_log("done. looked at %d heads." % processed)
ida_log("looking for potentially interesting API calls now.")

# format of functions dictionary is function name: format string arg number
# fill this from google search: +run-time.library +security.note site:msdn.microsoft.com
# [cm] my own google dork: "Security Warning" intitle:function site:msdn.microsoft.com
# 					  "Security note" crt site:msdn.microsoft.com
functions = \
{
# insecure by default	
	"gets"       	    : {}, 
	"getws"        	    : {}, 

# exec functions	
	"execl"        		: {"cmd_name": 1}, 
	"wexecl"      		: {"cmd_name": 1}, 
	"execv"	      		: {"cmd_name": 1}, 
	"wexecv"       		: {"cmd_name": 1}, 
	"WinExec"     		: {"cmd_name": 1}, 
	"ShellExecute"   	: {},
	"ShellExecuteEx"   	: {},
	"CreateProcess"		: {"cmd_name": 2},
	"CreateProcessAsUser": {"cmd_name": 2},
	"CreateProcessWithLogon" : {"cmd_name": 2},

# memory copy functions
    "memcpy"       		: {"size": 3},
	"wmemcpy"       	: {"size": 3},
	"VirtualAllocEx"	: {"size": 3},
	"VirtualAlloc"      : {"size": 2},
	"VirtualAllocExNuma": {"size": 2},
	"LocalAlloc"		: {"size": 2},
	"HeapAlloc"			: {"size": 3},
	"CopyMemory"		: {"size": 3},
	
# string functions	
    "lstrcat"      		: {},
	"lstrcat"     		: {}, 
    "lstrcpy"      		: {},
	"lstrlen"	   		: {},
	"lstrlen"	   		: {},
    "mbscat"       		: {},
    "mbscpy"       		: {},
	"mbsncpy"     		: {"size": 3},
	"mbsnbcpy"     		: {"size": 3},
    "mbsncat"      		: {},
	"mbsstr_l"     		: {},
	"RtlInitString"		: {}, 
	"SHAnsiToAnsi" 		: {"size": 3}, 
	"SHAnsiToUnicode" 	: {"size": 3}, 
	"SHUnicodeToUnicode": {"size": 3}, 
	"SHUnicodeToAnsi"	: {"size": 3}, 
    "strcpy"       		: {},
	"strncpy"       	: {"size": 3},
    "strcat"     		: {},
    "StrCatBuf"   		: {}, 
	"StrCatChain" 		: {}, 
	"StrCpyN"			: {},
	"StrCpyN"			: {},
	"strcpy"			: {},
    "strncat"     		: {"size": 3}, 
	"strstr"     		: {}, 
	"wcscat"      		: {},
	"wcsstr"     		: {}, 
    "wcsncat"    		: {},
    "wcscpy"     		: {},
	"wcsncpy"     		: {"size": 3},
	"CompareStringWrapW": {},
	"MultiByteToWideChar": {},
	"WideCharToMultiByte": {}, 

# format strings
	"printf"       		: {"fs_arg": 1},
	"wprintf"       	: {"fs_arg": 1}, 
    "snprintf"     		: {"fs_arg": 3},
    "snwprintf"   		: {"fs_arg": 3},
	"scanf"      		: {"fs_arg": 1},
    "sprintf"    		: {"fs_arg": 2},
    "sscanf"     		: {"fs_arg": 2},
    "swprintf"  	    : {"fs_arg": 2},
    "swscanf"   		: {"fs_arg": 2},
    "vfprintf"   		: {"fs_arg": 2},
    "vfwprintf"  		: {"fs_arg": 2},
    "vprintf"    		: {"fs_arg": 1},
    "vwprintf"   		: {"fs_arg": 1},
    "vsprintf"   	    : {"fs_arg": 2},
    "vsnprintf"   		: {"fs_arg": 3},
    "vsnwprintf"  		: {"fs_arg": 3},
    "vswprintf"   		: {"fs_arg": 2},
    "wsprintf"   		: {"fs_arg": 2},
    "wsprintf"   	 	: {"fs_arg": 2},
    "wvsprintf"   		: {"fs_arg": 2},
    "wvsprintf"   		: {"fs_arg": 2},
	"wvnsprintf"   		: {"fs_arg": 3},
	"wnsprintf"	  		: {"fs_arg": 3}, 
}

prefixes = ["", "_", "__imp_", "__imp__"]
suffixes = ["", "A", "W"] 

# For every function we are interested in.
for func in functions:
	
	# enumerate all possibile suffixes.
	for prefix in prefixes:
	
		# enumerate all possible prefixes.
		for suffix in suffixes:
			full_name = prefix + func + suffix
			#ida_log("library %s" % full_name)
			location  = LocByName(full_name)

			if location == BADADDR:
				continue

			ida_log("enumerating xrefs to %s" % full_name)

			for xref in list(CodeRefsTo(location, True)) + list(DataRefsTo(location)):
				if GetMnem(xref) in ("call", "jmp"):
					# Ensure the xref does not exist within a known library routine.
					# if GetFunctionFlags(ea) and GetFunctionFlags(xref) & FUNC_LIB:
					
					#if GetFunctionFlags(xref) & FUNC_LIB:
					#	continue
					
					###
					### peek a call with format string arguments
					###
					if functions[func].has_key("fs_arg"):
						fs_arg = functions[func]["fs_arg"]

						format_string = get_arg(xref, fs_arg, 'S')

						# format string must be resolved at runtime.
						if format_string == BADADDR:
							ida_log("%08x format string must be resolved at runtime" % xref)
							write_line("%08x: %s" % (xref, full_name))

						# XXX - we have to escape '%' chars here otherwise 'print', which wraps around 'Message()' will
						#       incorrectly dereference from the stack and potentially crash the script.
						else:
							format_string = str(format_string).replace("%", "%%")

							# format string found.
							if format_string.find("%s") != -1:
								format_string = format_string.replace("\n", "")
								ida_log("%08x favorable format string found '%s'" % (xref, format_string))
								write_line("%08x:%d:%s %s" % (xref, token_count(format_string), full_name, format_string))
					#
					# TODO: get cmd_name string
					#
					elif functions[func].has_key("cmd_name"):
						cmd_name = functions[func]["cmd_name"]
						
						cmd = get_arg(xref, cmd_name, 'S')
						
						if cmd == BADADDR:
							ida_log("%08x command must be resolved at runtime" % xref)
							write_line("%08x: %s" % (xref, full_name))
						else:
							ida_log("%08x found call to '%s' with static command: %d" % (xref, full_name, cmd))
							write_line("%08x: %s command: %s" % (xref, full_name, cmd))
						
					#
					# get static size value
					#
					elif functions[func].has_key("size"):
						size_arg = functions[func]["size"]
						
						size = get_arg(xref, size_arg, 'I')		

						if size == BADADDR:
							ida_log("%08x size must be resolved at runtime" % xref)
							write_line("%08x: %s" % (xref, full_name))
						else:
							ida_log("%08x found call to '%s' with static size: %d" % (xref, full_name, size))
							write_line("%08x: %s size: %d" % (xref, full_name, size))

					###	
					### peek a non format string call
					###
					else:
						ida_log("%08x found call to '%s'" % (xref, full_name))
						write_line("%08x: %s" % (xref, full_name))

peek_file.close()
ida_log("done.")