#!/usr/bin/env python3
import os
import time

from pwn import *

context.log_level = "info"


def start():
    return process(
        ["./bin/broker"],
        env={"CTF_STDIO": "1"},
        stdin=PIPE,
        stdout=PIPE,
        stderr=PIPE,
    )


def cmd(io, line):
    log.info("send %s", line[:48])
    io.sendline(line)
    io.stdin.flush()
    response = b""
    while True:
        response = io.recvline(timeout=5) or b""
        if not response.startswith(b"["):
            break
        log.debug("runtime: %s", response.rstrip())
    log.info("recv %r", response)
    return response or b""


def main():
    io = start()
    greeting = b""
    while not greeting or greeting.startswith(b"["):
        greeting = io.recvline(timeout=5) or b""
    log.info(greeting.decode(errors="replace").rstrip())
    if os.getenv("BATCH_PROBE"):
        lines = [
            b"REGISTER alice",
            b"CREATE x " + (b"41" * 33),
            b"WRITE x " + (b"42" * 33),
        ]
        io.send(b"\n".join(lines) + b"\n")
        io.stdin.flush()
        for _ in lines:
            log.info("recv %r", io.recvline(timeout=5))
        log.info("paused; broker pid=%d", io.pid)
        time.sleep(60)
        return
    print(cmd(io, b"REGISTER alice").decode(errors="replace"), end="", flush=True)
    print(cmd(io, b"CREATE x 00").decode(errors="replace"), end="", flush=True)
    payload = b"41" * int(os.getenv("WRITE_LEN", "1000"))
    print(cmd(io, b"WRITE x " + payload).decode(errors="replace"), end="", flush=True)
    if os.getenv("PAUSE_BEFORE_READ"):
        log.info("paused before READ; broker pid=%d", io.pid)
        time.sleep(45)
    print(cmd(io, b"READ x").decode(errors="replace"), end="", flush=True)
    io.interactive()


if __name__ == "__main__":
    main()
