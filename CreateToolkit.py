#!/bin/python
import sys
import sqlite3 as sqlite
import subprocess
import optparse
import re

class database:
	con = 0
	def __init__(self,vanilla_os):
		database.con = sqlite.connect('test.db')
		self.vanilla_os = vanilla_os
	def create(self):
		database.con = sqlite.connect('test.db')
		cur = database.con.cursor()
		q_str = "create table "+self.vanilla_os+" (id integer primary key,data blob, arch, ver,syscall)"
		print q_str
		cur.execute(q_str)
		cur.execute(
		"create table "+self.vanilla_os+"_tools ("
			"id integer primary key,"
			"data blob, arch, ver,toolname,tooltype)")
		cur.execute(
		"create table "+self.vanilla_os+"_header ("
			"id integer primary key,"
			"syscall, arch, ver,number)")
		cur.close()

	def close(self):
		database.con.close()
		print "Way to go team!!!"

#I may be able to gut this
def GrabLinuxToolObjects(toolname,tooltype,filename,arch,ver,db):
	cur = db.con.cursor()
	with open(filename,"rb") as input_file:
		ablob = input_file.read()
		cur.execute(
		    "insert into "+db.vanilla_os+"_tools values (null,?,?,?,?,? )",
		    (sqlite.Binary(ablob),arch,ver,toolname,tooltype))
		db.con.commit()
		
	cur.close()	

#grab all syscall containing object files and put in db
#os_ver,os_title,arch,arch_ver
def GrabLinuxSyscallObjects(objfile,filename,arch,ver,db):
	cur = db.con.cursor()
	with open(filename,"rb") as input_file:
		ablob = input_file.read()

		cur.execute(
		    "insert into "+db.vanilla_os+" values (null,?,?,?,? )",
		    (sqlite.Binary(ablob),arch,ver,objfile))
		db.con.commit()

	cur.close()

#get the syscalls from the header and compare to object files
def GetHeader(header_location,db,arch,ver):
	print "GetHeader"
	print header_location
	syscall_header=[]
	proc = subprocess.Popen(['cat',header_location],stdout=subprocess.PIPE)
	for line in iter(proc.stdout.readline,''):
		line=line.strip().split()
		#print line
		if len(line) > 2:
			if line[0] == '#define':
				
				cur = db.con.cursor()
				cur.execute(
				    "insert into "+db.vanilla_os+"_header values (null,?,?,?,? )",
				    (line[1],arch,ver,line[2]))
				db.con.commit()
				cur.close()
#def GrabLinuxToolObjects(toolname,tooltype,filename,arch,ver,db):
def GrabSysrootHeaders(sysroot,db):
	subprocess.call(['tar',"-z","-c","-v","-f","sysroot.tar.gz",sysroot])
	GrabLinuxToolObjects('sysroot',"sysroot", "sysroot.tar.gz", "", "", db)

def GrabLibcParseObjects(prefix,libc):
	location_str = ""
	if prefix == None:
		prefix =""
		location_str="ar"
	else:
		location_str = libc+"/"+prefix+"ar"
	print "GrabLibcParseObjects"
	
	libc_full = libc+"/libc.a"
	#extract libc contents
	print location_str
	print libc_full
	subprocess.call([location_str,"-x",libc_full])
	proc = subprocess.Popen(['ls'],stdout=subprocess.PIPE)
	for line in iter(proc.stdout.readline,''):
		line=line.strip().split()
		if len(line) > 0:
			if line[0].endswith('.o'):
				#print potential_syscall
				arch_os=ReadElf(line[0])
				#print arch_os
				GrabLinuxSyscallObjects(line[0][:-2],line[0],arch_os[0],arch_os[1],db)
#read the semantics of the elf file for storage
def ReadElf(elffile):
	arch=""
	os=""
	proc = subprocess.Popen(['readelf','-h',elffile],stdout=subprocess.PIPE)
	for line in iter(proc.stdout.readline,''):
		line=line.strip()
		#get os version
		if line.find("UNIX - System V",0,len(line)):
			os="Linux"
		elif line.find("UNIX - FreeBSD",0,len(line)):
			os="FreeBSD"

		#get architecture
		if "Machine:" in line:
			if "Intel 80386" in line:
				arch="x86"
			elif "X86-64" in line:
				arch='x64'
			elif "ARM" in line:
				arch="arm"
	return [arch,os]

#Get rid of all of the old obj files and such
def SanitizeArea():
	proc = subprocess.Popen(['ls'],stdout=subprocess.PIPE)
	for line in iter(proc.stdout.readline,''):
		line=line.strip().split()
		if len(line) > 0:
			if line[0].endswith('.o') or line[0].endswith('.a')	or line[0].endswith('.bin') or line[0].endswith('ld') or line[0].endswith('gcc') or line[0].endswith('ar'):
				subprocess.call(['rm','-r','-f',line[0]])
if __name__ == '__main__':
	version 	=""
	arch 		=""
	osystem 	=""
	header		=""
	toolchain 	=""
	libc 		=""
	parser 		= optparse.OptionParser()
	parser.add_option('-d', '--origin-directory', 
		dest='origin',
		type='string',
		help='\t\tdirectory to extract and place everything, working dir')
	parser.add_option('-s', '--syscalls', 
		dest='header',
		type='string',
		help='\t\tc syscall header to upload')
	# parser.add_option('-a', '--arch', 
	# 	dest='arch',
	# 	help='\t\tdesired cpu architecture')
	parser.add_option('-o', '--os', 
		dest='osystem',
		type='string',
		help='\t\tdesired operating system')
	# parser.add_option('-v', '--version', 
	# 	dest='version',
	# 	help='\t\tdesired os version')
	parser.add_option('-t', '--toolchain-prefix', 
		dest='toolchain',
		type='string',
		help='\t\tprefix of toolchain for ld, gcc, and objdump')
	parser.add_option('-l', '--libc', 
		dest='libc',
		type='string',
		help='\t\tlibc location')
	parser.add_option('-r', '--sysroot', 
		dest='sysroot',
		type='string',
		help='\t\main header files location')
	(opts, args)= parser.parse_args()
	if not opts.sysroot:
		parser.error('Sysroot not given, i.e. /usr/include')
	if not opts.osystem:
		parser.error('OS title not given, i.e. Ubunutu, or FreeBSD')
	if not opts.header:
		parser.error('Syscall header, usually unistd_?.h location not specified')
	if not opts.origin:
		parser.error('Wroking dir location not specified')
	if not opts.libc:
		parser.error('Libc.a location not specified')
	try:
		subprocess.call(['rm','-rf','test.db'])
	except Exception, e:
		print "Database exists...deleting..."
	else:
		pass
	finally:
		pass
	SanitizeArea()
	print str(opts.osystem).lower()
	print str(opts.header)
	print str(opts.toolchain)
	print str(opts.libc)
	env = ReadElf(opts.libc+"/libc.a")
	db = database(str(opts.osystem).lower())
	db.create()
	GrabSysrootHeaders(opts.sysroot,db)
	GetHeader(opts.header,db,env[0],env[1])
	GrabLibcParseObjects(opts.toolchain,opts.libc)
	tools = ['ar','ld','cc','objdump','readelf']
	for tool in tools:
		var_dir =""
		if opts.toolchain == None:
			var_dir="/usr/bin/"+tool
		else:
			var_dir=toolchain+tool
		toolnames = var_dir.split('/')
		toolname = toolnames[len(toolnames)-1]
		GrabLinuxToolObjects(toolname,tool,var_dir,env[0],env[1],db)
	SanitizeArea()