#
# IDA Python Proc Peek Recon
# Locate all potentially interesting points and dump to file.
#
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: proc_peek_recon_db.py 231 2008-07-21 22:43:36Z pedram.amini $
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

import MySQLdb

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


def ida_log (message):
	print "RECON> " + message


def add_recon (mysql, module_id, offset, stack_depth, reason, status):
	# escape single quotes and backslashes in fields that might have them.
	reason = reason.replace("\\", "\\\\").replace("'", "\\'")

	sql  = " INSERT INTO pp_recon"
	sql += " SET module_id   = '%d'," % module_id
	sql += "     offset      = '%d'," % offset
	sql += "     stack_depth = '%d'," % stack_depth
	sql += "     reason      = '%s'," % reason
	sql += "     status      = '%s',"  % status
	sql += "     notes       = ''"

	cursor = mysql.cursor()

	try:
		cursor.execute(sql)
	except MySQLdb.Error, e:
		ida_log("MySQL error %d: %s" % (e.args[0], e.args[1]))
		ida_log(sql)
		return False

	cursor.close()
	return True

########################################################################################################################
### Meat and Potatoes
###

def meat_and_potatoes (mysql):
	# init some local vars.
	window = state = found_ea = processed = 0

	# calculate the current modules base address.
	# XXX - cheap hack, the subtraction is for the PE header size.
	base_address = MinEA() - 0x1000

	# create a database entry for the current module.
	cursor = mysql.cursor()

	try:
		cursor.execute("INSERT INTO pp_modules SET name = '%s', base = '%d', notes = ''" % (GetInputFile(), base_address))
	except MySQLdb.Error, e:
		ida_log("MySQL error %d: %s" % (e.args[0], e.args[1]))
		ida_log(sql)
		cursor.close()
		return

	# save the module ID we just created.
	module_id = cursor.lastrowid

	cursor.close()

	ida_log("searching for inline memcpy()'s and sign extended moves (movsx).")
	for ea in Heads(MinEA(), MaxEA()):
		processed += 1

		# we don't care about instructions within known library routines.
		if GetFunctionFlags(ea) & FUNC_LIB:
			continue

		if disasm_match(ea, "movsx"):
			ida_log("%08x: found sign extended move" % ea)

			if not add_recon(mysql, module_id, ea - base_address, 3, "sign extended mov", "new"):
				return

		if state == 0 and instruction_match(ea, "shr", "ecx", "2"):
			# this is a good place to watch the inline strcpy since it gets executed only once and we can see the
			# original size value prior to division by 4.
			state    = 1
			window   = 0
			found_ea = ea

		elif state == 1 and disasm_match(ea, "rep movsd"):
			state    = 2
			window   = 0

		elif state == 2 and instruction_match(ea, "and", "ecx", "3"):
			state  = 3
			window = 0

		elif state == 3 and disasm_match(ea, "rep movsb"):
			ida_log("%08x: found memcpy" % found_ea)
			set_cmt(found_ea, "inline memcpy()", False)

			if not add_recon(mysql, module_id, found_ea - base_address, 5, "inline memcpy", "new"):
				return

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

	# for every function we are interested in.
	for func in functions:
	
		# enumerate all possibile suffixes.
		for suffix in suffixes:
		
			# enumerate all possible prefixes.
			for prefix in prefixes:
				full_name = prefix + func + suffix
				location  = LocByName(full_name)

				if location == BADADDR:
					continue

				ida_log("enumerating xrefs to %s" % full_name)

				for xref in list(CodeRefsTo(location, True)) + list(DataRefsTo(location)):
					if GetMnem(xref) in ("call", "jmp"):
						# ensure the xref does not exist within a known library routine.
						flags = GetFunctionFlags(xref)
						if flags:
							if flags & FUNC_LIB:
								continue

						###
						### peek a call with format string arguments
						###
						if functions[func].has_key("fs_arg"):
							fs_arg = functions[func]["fs_arg"]

							format_string = get_arg(xref, fs_arg, 'S')

							# format string must be resolved at runtime.
							if format_string == BADADDR:
								ida_log("%08x format string must be resolved at runtime" % xref)

								if not add_recon(mysql, module_id, xref - base_address, 0, full_name, "new"):
									return

							# XXX - we have to escape '%' chars here otherwise 'print', which wraps around 'Message()' will
							#       incorrectly dereference from the stack and potentially crash the script.
							else:
								format_string = str(format_string).replace("%", "%%")

								# format string found.
								if format_string.find("%s") != -1:
									format_string = format_string.replace("\n", "")
									ida_log("%08x favorable format string found '%s'" % (xref, format_string))

									if not add_recon(mysql, module_id, xref - base_address, token_count(format_string)+fs_arg, "%s - fs: %s" % (full_name, format_string), "new"):
										return
						#
						# TODO: get cmd_name string
						#
						elif functions[func].has_key("cmd_name"):
							cmd_name = functions[func]["cmd_name"]
							
							cmd = get_arg(xref, cmd_name, 'S')
							
							if cmd == BADADDR:
								ida_log("%08x command must be resolved at runtime" % xref)
								if not add_recon(mysql, module_id, xref - base_address, cmd_name, full_name, "new"):
									return
							else:
								ida_log("%08x found call to '%s' with static command: %d" % (xref, full_name, cmd))
								if not add_recon(mysql, module_id, xref - base_address, cmd_name, "%s - cmd: %s" % (full_name, cmd_name), "new"):
									return
						#
						# get static size value
						#
						elif functions[func].has_key("size"):
							size_arg = functions[func]["size"]
							
							size = get_arg(xref, size_arg, 'I')		

							if size == BADADDR:
								ida_log("%08x size must be resolved at runtime" % xref)
								if not add_recon(mysql, module_id, xref - base_address, size_arg, full_name, "new"):
									return
							else:
								ida_log("%08x found call to '%s' with static size: %d" % (xref, full_name, size))
								if not add_recon(mysql, module_id, xref - base_address, size_arg, "%s - size: %d" % (full_name, size), "new"):
									return
						
						###
						### peek a non format string call
						###

						else:
							ida_log("%08x found call to '%s'" % (xref, func))

							if not add_recon(mysql, module_id, xref - base_address, 0, full_name, "new"):
								return

	ida_log("done.")


########################################################################################################################
### MySQL Connectivity
###

def mysql_connect ():
	mysql_host = None
	mysql_user = None
	mysql_pass = None

	if not mysql_host:
		mysql_host = AskStr("localhost", "MySQL IP address or hostname:")

		if not mysql_host:
			return -1

	if not mysql_user:
		mysql_user = AskStr("root", "MySQL username:")

		if not mysql_user:
			return -1

	if not mysql_pass:
		mysql_pass = AskStr("", "MySQL password:")

		if not mysql_pass:
			return -1

    # connect to mysql
	try:
		mysql = MySQLdb.connect(host=mysql_host, user=mysql_user, passwd=mysql_pass, db="paimei")
	except MySQLdb.OperationalError, err:
		ida_log("failed connecting to MySQL server: %s" % err[1])
		mysql = None

	return mysql


########################################################################################################################
### main()
###

def main ():
	mysql = mysql_connect()

	if mysql == -1:
		ida_log("cancelled by user.")
	elif mysql == None:
		# error message already printed.
		return
	else:
		meat_and_potatoes(mysql)
	
	mysql.close()

main()