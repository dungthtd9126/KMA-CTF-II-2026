#!/usr/bin/env python3
"""Solve the two-stage KMA Rubik challenge."""

import time

import requests


BASE_URL = "http://42.112.213.93:18081"


def post(path, body):
    # This sends an HTTP POST request. And wait 15 seconds for server's response
    response = requests.post(BASE_URL + path, json=body, timeout=15)
    # check HTTP status code. If the server got error, raises an exception
    response.raise_for_status()
    # Converts the server's JSON response into Python objects.
    return response.json()


def reverse_scramble(scramble):
    result = []
    for move in reversed(scramble.split()):
        if move.endswith("'"):
            move = move[:-1]       # R' -> R
        elif not move.endswith("2"):
            move += "'"             # R -> R'
        # R2 stays R2. The reversed order is already handled above.
        result.append(move)
    print("-"*0x10)
    print(f"After reverse the order:\n {result}")
    print("-"*0x10)

    return result


def solve_stage(stage, pass_token=None):
    if pass_token is None:
        start_body = {}
    else:
        start_body = {"stagePassToken": pass_token}
    run = post(f"/api/stages/{stage}/start", start_body)

    # The server queues the run before accepting moves.
    wait = run["startsAt"] - run["serverNow"]
    if wait < 0:
        wait = 0
    wait = wait / 1000 + 0.25
    time.sleep(wait)
    print(run)
    result = post(
        f"/api/stages/{stage}/finish",
        {
            "runId": run["runId"],
            "moves": reverse_scramble(run["scramble"]),
        },
    )
    print("-"*0x20)
    print(f"Final result: {result}")
    print("-"*0x20)

    if not result.get("ok"):
        raise RuntimeError(result)
    return result


stage1 = solve_stage(1)
print("Stage 1 solved")
stage2 = solve_stage(2, stage1["stagePassToken"])
print(stage2["flag"])
