#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('bank_patched', checksec=False)
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
        set max-visualize-chunk-size 0x500
        brva 0x32AD   
        brva 0x02E78 
        brva 0x3683
        c
        ''')
        sleep(1)


if args.REMOTE:
    p = remote('')
else:
    p = process([exe.path])
GDB()

def open_acc(name, choice, desposit_num):
    slna(b'Enter choice: ', 1)
    sla(b'Holder name: ', name)        
    slna(b'Product (0=Current, 1=Savings, 2=Term): ', choice)
    slna(b'Opening deposit (VND): ', desposit_num)

def acc_statement(idx):
    slna(b'Enter choice: ', 2)
    slna(b'Account no (numeric part): ', idx)

sla(b'Teller ID: ', b'3636')
open_acc(b'a'*0x4f, 0, 0x10000)
open_acc(b'b'*0x4f, 0, 0x10000)




p.interactive()
