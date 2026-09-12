from pwn import *
import os

context.log_level = "info"


def foo(io, line):
    print("before", io.pid, flush=True)
    os.write(io.stdin.fileno(), line + b"\n")
    print("after send", io.poll(), flush=True)


io = process(["./bin/broker"], env={"CTF_STDIO": "1"}, stdin=PIPE, stdout=PIPE, stderr=PIPE)
print(repr(io.recvline(timeout=3)))
foo(io, b"REGISTER alice")
print("outside", repr(io.recvline(timeout=3)), flush=True)
