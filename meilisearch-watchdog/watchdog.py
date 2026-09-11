#!/usr/bin/env python3
"""
watchdog.py

Monitors the shared Meilisearch container. When Dockhand reports it has
been updated to the latest image AND its logs show the classic
"database version incompatible" crash-loop, this:

  1. Stops meilisearch
  2. Backs up meili_data/data.ms to meili_data/data.ms-bckup
     (deleting any PREVIOUS backup first - never keeps more than one)
  3. Deletes the live data.ms
  4. Starts meilisearch again (boots with a fresh, empty index)
  5. Triggers a full reindex in Karakeep via its admin API
  6. Triggers a full reindex in Linkwarden by resetting indexVersion in
     its Postgres DB (Linkwarden has no reindex API - this is the
     documented community workaround: linkwarden/linkwarden#1662)

Required env vars:
  DOCKHAND_URL              e.g. https://dockhand.ashish-syn-nas.synology.me
  DOCKHAND_TOKEN            Dockhand API bearer token (Settings > API Tokens)
  MEILISEARCH_CONTAINER     Container name to watch, e.g. "meilisearch"
  MEILI_DATA_PATH           Path INSIDE this container to meili_data
                            (mount the same host directory Meilisearch uses)
  KARAKEEP_URL              e.g. https://karakeep.ashish-syn-nas.synology.me
  KARAKEEP_ADMIN_API_KEY    An admin-role Karakeep API key
  LINKWARDEN_DB_HOST        e.g. "postgres" (the service name)
  LINKWARDEN_DB_NAME        e.g. "linkwarden"
  LINKWARDEN_DB_USER        e.g. "linkwardenuser"
  LINKWARDEN_DB_PASSWORD    linkwarden's postgres password

Optional env vars:
  LINKWARDEN_DB_PORT        default 5432
  CHECK_INTERVAL_SECS       default 300 (5 minutes)
  REMEDIATION_COOLDOWN_SECS default 1800 (don't re-trigger remediation more
                            than once per 30 min, in case recovery takes a
                            moment and logs still show the old error briefly)

CONFIRMED (2026-09-11) against a real Dockhand instance:
  - GET .../api/containers/check-updates?env=<id> requires the env query param
  - Response shape: {"environmentId": N, "pendingUpdates": [{"containerName": ..., ...}]}
  - A container is "on latest" if it's simply absent from pendingUpdates
See container_is_on_latest() below for the exact parsing.
"""

import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

import docker
import psycopg2
import requests

DOCKHAND_URL = os.environ["DOCKHAND_URL"].rstrip("/")
DOCKHAND_TOKEN = os.environ["DOCKHAND_TOKEN"]
DOCKHAND_ENVIRONMENT_ID = os.environ.get("DOCKHAND_ENVIRONMENT_ID", "1")   # Dockhand's multi-host "environment" - 1 is the default for a single-host setup
MEILISEARCH_CONTAINER = os.environ.get("MEILISEARCH_CONTAINER", "meilisearch")
MEILI_DATA_PATH = os.environ["MEILI_DATA_PATH"]

KARAKEEP_URL = os.environ["KARAKEEP_URL"].rstrip("/")
KARAKEEP_ADMIN_API_KEY = os.environ["KARAKEEP_ADMIN_API_KEY"]

LINKWARDEN_DB_HOST = os.environ["LINKWARDEN_DB_HOST"]
LINKWARDEN_DB_PORT = int(os.environ.get("LINKWARDEN_DB_PORT", "5432"))
LINKWARDEN_DB_NAME = os.environ["LINKWARDEN_DB_NAME"]
LINKWARDEN_DB_USER = os.environ["LINKWARDEN_DB_USER"]
LINKWARDEN_DB_PASSWORD = os.environ["LINKWARDEN_DB_PASSWORD"]

CHECK_INTERVAL_SECS = int(os.environ.get("CHECK_INTERVAL_SECS", "300"))
REMEDIATION_COOLDOWN_SECS = int(os.environ.get("REMEDIATION_COOLDOWN_SECS", "1800"))

# The exact text Meilisearch prints when the on-disk data.ms format predates
# the running engine version and it refuses to start. Confirmed verbatim
# across multiple Meilisearch GitHub issues (e.g. meilisearch/meilisearch#5534).
VERSION_MISMATCH_RE = re.compile(
    r"Your database version \(([\d.]+)\) is incompatible with your current engine version \(([\d.]+)\)"
)

docker_client = docker.from_env()
last_remediation_ts = 0.0


def log(msg):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[{ts}] {msg}", flush=True)


def container_is_on_latest(container_name):
    """
    Ask Dockhand whether this container currently has a pending update.

    Confirmed response shape (2026-09-11, live test against a real Dockhand
    instance):
        {
          "environmentId": 1,
          "pendingUpdates": [
            {
              "containerId": "...",
              "containerName": "Syncthing",
              "currentImage": "ghcr.io/linuxserver/syncthing:latest",
              "checkedAt": "2026-09-11T05:16:18.447Z"
            }
          ]
        }

    pendingUpdates only lists containers that HAVE an update available - a
    container not appearing in this list is already on the latest pulled
    image. There's no separate boolean field to check.
    """
    resp = requests.get(
        f"{DOCKHAND_URL}/api/containers/check-updates",
        params={"env": DOCKHAND_ENVIRONMENT_ID},
        headers={"Authorization": f"Bearer {DOCKHAND_TOKEN}"},
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()

    pending = data.get("pendingUpdates", [])
    for item in pending:
        if item.get("containerName") == container_name:
            return False  # has a pending update - NOT on latest yet

    return True  # absent from pendingUpdates - already on latest


def get_recent_logs(container_name, tail=300):
    container = docker_client.containers.get(container_name)
    raw = container.logs(tail=tail)
    return raw.decode("utf-8", errors="replace")


def is_crash_looping(container_name):
    container = docker_client.containers.get(container_name)
    container.reload()
    state = container.attrs.get("State", {})
    restart_count = container.attrs.get("RestartCount", 0)
    # "Restarting" true, or a healthy-looking restart count, both indicate a loop
    return bool(state.get("Restarting")) or restart_count >= 2


def rotate_and_clear_meili_data():
    data_ms = os.path.join(MEILI_DATA_PATH, "data.ms")
    backup = os.path.join(MEILI_DATA_PATH, "data.ms-bckup")

    if not os.path.isdir(data_ms):
        log(f"WARNING: {data_ms} doesn't exist - nothing to back up, skipping rotation")
        return

    if os.path.exists(backup):
        log(f"Removing previous backup at {backup} (never keep more than 1)")
        subprocess.run(["rm", "-rf", backup], check=True)

    log(f"Backing up {data_ms} -> {backup}")
    os.rename(data_ms, backup)  # same filesystem (same bind mount) - this is instant, not a copy

    # os.rename already means data.ms no longer exists, but be explicit/defensive
    if os.path.exists(data_ms):
        subprocess.run(["rm", "-rf", data_ms], check=True)
    log("data.ms cleared - Meilisearch will create a fresh empty index on next start")


def restart_meilisearch():
    container = docker_client.containers.get(MEILISEARCH_CONTAINER)
    log(f"Stopping {MEILISEARCH_CONTAINER}")
    container.stop(timeout=30)

    rotate_and_clear_meili_data()

    log(f"Starting {MEILISEARCH_CONTAINER}")
    container.start()

    # Wait for it to actually come up healthy before triggering reindexes
    for _ in range(30):
        time.sleep(2)
        container.reload()
        status = container.attrs["State"]["Status"]
        if status == "running":
            log(f"{MEILISEARCH_CONTAINER} is running again")
            return True
    log(f"WARNING: {MEILISEARCH_CONTAINER} did not report 'running' within 60s")
    return False


def trigger_karakeep_reindex():
    log("Triggering Karakeep reindex via admin API")
    resp = requests.post(
        f"{KARAKEEP_URL}/api/v1/admin/jobs/trigger/reindex",
        headers={"Authorization": f"Bearer {KARAKEEP_ADMIN_API_KEY}"},
        json={},
        timeout=15,
    )
    resp.raise_for_status()
    log(f"Karakeep reindex response: {resp.json()}")


def trigger_linkwarden_reindex():
    log("Triggering Linkwarden reindex via DB (resetting indexVersion) - see linkwarden/linkwarden#1662")
    conn = psycopg2.connect(
        host=LINKWARDEN_DB_HOST,
        port=LINKWARDEN_DB_PORT,
        dbname=LINKWARDEN_DB_NAME,
        user=LINKWARDEN_DB_USER,
        password=LINKWARDEN_DB_PASSWORD,
    )
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute('UPDATE "Link" SET "indexVersion" = NULL;')
                log(f"Reset indexVersion on {cur.rowcount} Linkwarden links")
    finally:
        conn.close()


def remediate():
    global last_remediation_ts
    now = time.time()
    if now - last_remediation_ts < REMEDIATION_COOLDOWN_SECS:
        log("Remediation was run recently - within cooldown window, skipping")
        return

    log("=== REMEDIATION STARTING ===")
    try:
        if restart_meilisearch():
            # Give Meilisearch a moment to fully accept connections before
            # the two apps start hammering it with reindex requests
            time.sleep(10)
            trigger_karakeep_reindex()
            trigger_linkwarden_reindex()
            log("=== REMEDIATION COMPLETE ===")
        else:
            log("=== REMEDIATION ABORTED - meilisearch never came back up ===")
    except Exception as exc:
        log(f"=== REMEDIATION FAILED: {exc} ===")
    finally:
        last_remediation_ts = now


def check_once():
    try:
        on_latest = container_is_on_latest(MEILISEARCH_CONTAINER)
    except Exception as exc:
        log(f"Dockhand check-updates call failed: {exc}")
        return

    if on_latest is not True:
        log(f"'{MEILISEARCH_CONTAINER}' not confirmed on latest per Dockhand (on_latest={on_latest}) - skipping log check")
        return

    try:
        logs = get_recent_logs(MEILISEARCH_CONTAINER)
    except Exception as exc:
        log(f"Failed to read {MEILISEARCH_CONTAINER} logs: {exc}")
        return

    match = VERSION_MISMATCH_RE.search(logs)
    if not match:
        return  # on latest, logs look fine - nothing to do

    db_version, engine_version = match.groups()
    log(f"Version mismatch detected in logs: db={db_version} engine={engine_version}")

    try:
        crash_looping = is_crash_looping(MEILISEARCH_CONTAINER)
    except Exception as exc:
        log(f"Could not check container state: {exc}")
        crash_looping = True  # err toward remediating if we can't confirm otherwise

    if crash_looping:
        remediate()
    else:
        log("Version mismatch text found but container isn't currently crash-looping - waiting")


def main():
    log(
        f"meilisearch-watchdog starting - watching '{MEILISEARCH_CONTAINER}', "
        f"checking every {CHECK_INTERVAL_SECS}s"
    )
    while True:
        check_once()
        time.sleep(CHECK_INTERVAL_SECS)


if __name__ == "__main__":
    main()