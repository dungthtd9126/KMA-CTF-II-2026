#!/usr/bin/env python3
"""Solve the two-stage KMA Rubik challenge by reversing each server scramble."""

import argparse
import time

import requests


def inverse_scramble(scramble):
    moves = []
    for move in reversed(scramble.split()):
        if move.endswith("'"):
            moves.append(move[:-1])
        elif move.endswith("2"):
            moves.append(move)
        else:
            moves.append(move + "'")
    return moves


def post_json(session, url, payload):
    response = session.post(url, json=payload, timeout=15)
    data = response.json()
    if not response.ok:
        raise RuntimeError(f"{response.status_code}: {data}")
    return data


def start_stage(session, base_url, stage, token=None):
    payload = {} if stage == 1 else {"stagePassToken": token}
    data = post_json(session, f"{base_url}/api/stages/{stage}/start", payload)
    # The server intentionally queues runs for three seconds before accepting moves.
    delay = max(0, (data["startsAt"] - data["serverNow"]) / 1000) + 0.25
    time.sleep(delay)
    return data


def finish_stage(session, base_url, run):
    moves = inverse_scramble(run["scramble"])
    return post_json(
        session,
        f"{base_url}/api/stages/{run['stage']}/finish",
        {"runId": run["runId"], "moves": moves},
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("base_url", nargs="?", default="http://42.112.213.93:18081")
    args = parser.parse_args()
    base_url = args.base_url.rstrip("/")

    with requests.Session() as session:
        stage1 = start_stage(session, base_url, 1)
        result1 = finish_stage(session, base_url, stage1)
        print(f"stage 1: {result1}")

        stage2 = start_stage(session, base_url, 2, result1["stagePassToken"])
        result2 = finish_stage(session, base_url, stage2)
        print(f"stage 2: {result2}")
        print(result2["flag"])


if __name__ == "__main__":
    main()
