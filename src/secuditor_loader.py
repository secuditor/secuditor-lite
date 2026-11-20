# Secuditor Database Loader – Copyright (c) 2026 Menahem Levinski

import csv
import hashlib
import io
import os
import re
import sqlite3
import time

import requests

UPVER = "4.0"

OUI_RESOURCE_URL = "https://updates.secuditor.com/oui-version.json"
def _resolve_oui_db_path():
    """Return the OuiCache.db path under AppData\\Local\\Secuditor Lite\\Cache."""
    local_app_data = os.getenv("LOCALAPPDATA") or os.path.join(
        os.path.expanduser("~"), "AppData", "Local"
    )
    cache_dir = os.path.join(local_app_data, "Secuditor Lite", "Cache")
    try:
        os.makedirs(cache_dir, exist_ok=True)
    except OSError:
        pass
    return os.path.join(cache_dir, "OuiCache.db")


OUI_DB_PATH = _resolve_oui_db_path()

def _connect():
    os.makedirs(os.path.dirname(OUI_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(OUI_DB_PATH, timeout=10)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS oui_vendor (
            mac_prefix TEXT PRIMARY KEY,
            vendor_name TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS oui_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn

def _read_resource (timeout=4):
    headers = {
        "User-Agent": f"Secuditor-Lite/{UPVER}",
    }

    response = requests.get(
        OUI_RESOURCE_URL,
        headers=headers,
        timeout=timeout,
    )

    response.raise_for_status()
    resource = response.json()

    version = resource.get("oui_version")
    expected_hash = resource.get("sha256", "").lower()
    url = resource.get("url")

    if not isinstance(version, str) or not version.strip():
        raise ValueError("Invalid OUI version in resource")

    if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
        raise ValueError("Invalid OUI SHA-256 in resource")

    if url != "https://updates.secuditor.com/oui.csv":
        raise ValueError("Unexpected OUI download URL")

    print(f"[+] OUI resource retrieved successfully (version {version}).")

    return version, expected_hash, url

def _parse_csv(content):
    text = content.decode("utf-8-sig")
    reader = csv.reader(io.StringIO(text, newline=""))

    # Expected CSV format: first column = MAC prefix,
    # second column = vendor name.
    next(reader, None)

    records = {}
    prefix_pattern = re.compile(
        r"^(?:[0-9A-F]{2}[:-]){2,7}[0-9A-F]{2}$"
    )

    for row in reader:
        if len(row) < 2:
            continue

        prefix = row[0].strip().upper().replace(":", "-")
        vendor = row[1].strip()

        if not prefix or not vendor:
            continue

        # Support OUI prefixes such as 00-00-0C.
        if not prefix_pattern.fullmatch(prefix):
            continue

        records[prefix] = vendor

    # Do not replace a valid cache with an empty or malformed file.
    if not records:
        raise ValueError("CSV contains no valid OUI records")

    return records

def load_oui_cache():
    """Load the current local vendor mapping. Never requires internet."""
    try:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT mac_prefix, vendor_name FROM oui_vendor"
            ).fetchall()
        return dict(rows)
    except (sqlite3.Error, OSError):
        return {}

def get_oui_version():
    """Return the cached version, or None if not initialized."""
    try:
        with _connect() as conn:
            row = conn.execute(
                "SELECT value FROM oui_metadata WHERE key = 'version'"
            ).fetchone()
        return row[0] if row else None
    except (sqlite3.Error, OSError):
        return None

def update_oui_cache(timeout=8):
    """
    Update the local OUI database if the remote version differs.
    Returns True if an update was installed, False otherwise.
    """
    try:
        version, expected_hash, url = _read_resource(timeout)

        cached_version = get_oui_version()

        if cached_version == version:
            print("[=] OUI database is already up to date.")
            return False

        print(
            f"[*] OUI database update available "
            f"(cached: {cached_version or 'none'}, server: {version})."
        )

        response = requests.get(
            url,
            headers={"User-Agent": f"Secuditor-Lite/{UPVER}"},
            timeout=timeout,
        )
        response.raise_for_status()
        content = response.content

        actual_hash = hashlib.sha256(content).hexdigest()
        if actual_hash != expected_hash:
            raise ValueError("OUI CSV SHA-256 verification failed")

        records = _parse_csv(content)

        with _connect() as conn:
            # Both changes commit together. On failure, SQLite rolls back.
            conn.execute("DELETE FROM oui_vendor")
            conn.executemany(
                """
                INSERT INTO oui_vendor (mac_prefix, vendor_name)
                VALUES (?, ?)
                """,
                records.items(),
            )
            conn.execute("""
                INSERT INTO oui_metadata (key, value)
                VALUES ('version', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """, (version,))
            conn.execute("""
                INSERT INTO oui_metadata (key, value)
                VALUES ('sha256', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """, (actual_hash,))
            conn.execute("""
                INSERT INTO oui_metadata (key, value)
                VALUES ('updated_at', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """, (str(int(time.time())),))

        return True

    except (requests.RequestException, ValueError, UnicodeError,
            csv.Error, sqlite3.Error, OSError) as exc:
        print(f"[!] OUI update failed; retaining local cache: {exc}")
        return False
