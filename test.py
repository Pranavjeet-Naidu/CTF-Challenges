#!/usr/bin/env python3
import asyncio
import aiohttp
import time
import csv
import sys
from datetime import datetime

# ----------------------------
# Configuration
# ----------------------------
URL = sys.argv[1] if len(sys.argv) > 1 else None
OUTPUT_CSV = sys.argv[2] if len(sys.argv) > 2 else "results.csv"

if URL is None:
    print(f"Usage: {sys.argv[0]} <url> [output_csv]")
    sys.exit(1)

# Virtual user simulation parameters
NUM_USERS = [500, 1000]       # Number of simulated users
REQUESTS_PER_USER = 50            # Number of requests each user will perform
CONCURRENCY_PER_USER = 5          # Max simultaneous requests per user
PAUSE_BETWEEN_REQUESTS = 0.02     # Seconds between requests per user

# ----------------------------
# Helpers
# ----------------------------
def timestamp_now():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

async def fetch(session, url):
    start = time.monotonic()
    try:
        async with session.get(url) as resp:
            await resp.text()
            elapsed = time.monotonic() - start
            status = resp.status
            return elapsed, status
    except Exception:
        elapsed = time.monotonic() - start
        return elapsed, -1

async def user_simulation(user_id, session, results, concurrency):
    sem = asyncio.Semaphore(concurrency)
    for i in range(REQUESTS_PER_USER):
        async with sem:
            elapsed, status = await fetch(session, URL)
            results.append((elapsed, status))
            if i % 10 == 0:
                print(f"[User {user_id}] Completed {i+1}/{REQUESTS_PER_USER} requests")

async def run_test(num_users, concurrency_per_user):
    print(f"\n=== Running test: {num_users} users, concurrency {concurrency_per_user} per user ===")
    results = []
    async with aiohttp.ClientSession() as session:
        tasks = [asyncio.create_task(user_simulation(uid, session, results, concurrency_per_user))
                 for uid in range(1, num_users + 1)]
        start_time = time.monotonic()
        await asyncio.gather(*tasks)
        end_time = time.monotonic()

    total_requests_done = len(results)
    errors = sum(1 for r in results if r[1] != 200)
    avg_latency = sum(r[0] for r in results)/total_requests_done if total_requests_done > 0 else 0
    rps = total_requests_done / (end_time - start_time) if (end_time - start_time) > 0 else 0

    print(f"Test completed: {total_requests_done} requests, RPS={rps:.2f}, Avg latency={avg_latency:.3f}s, Errors={errors}")
    return total_requests_done, rps, avg_latency, errors

# ----------------------------
# CSV logging
# ----------------------------
try:
    with open(OUTPUT_CSV, "x", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp","num_users","concurrency_per_user","total_requests",
                         "requests_per_sec","avg_latency_s","errors","tool_used"])
except FileExistsError:
    pass  # append to existing file

# ----------------------------
# Main
# ----------------------------
async def main():
    for num_users in NUM_USERS:
        total, rps, avg_lat, errors = await run_test(num_users, CONCURRENCY_PER_USER)
        ts = timestamp_now()
        with open(OUTPUT_CSV, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([ts, num_users, CONCURRENCY_PER_USER, total, round(rps,3),
                             round(avg_lat,6), errors, "aiohttp"])
        await asyncio.sleep(1)  # pause between tests

    print(f"\nAll tests completed. Results saved to {OUTPUT_CSV}")

if __name__ == "__main__":
    asyncio.run(main())
