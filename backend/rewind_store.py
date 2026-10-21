"""
JSON-file storage for rewind records and holds.

On Lambda, /tmp is wiped on cold start. For real deployments,
replace _load/_save with DynamoDB or S3.
"""

import json
import os
from datetime import datetime, timedelta, timezone

STORE_PATH = os.environ.get("REWIND_STORE", "/tmp/cloudguard_rewind.json")


def now():
    return datetime.now(timezone.utc)


class RewindStore:

    def __init__(self, path=STORE_PATH):
        self.path = path
        self.data = self._load()

    def _load(self):
        try:
            with open(self.path) as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            data = {}
        data.setdefault("records", {})
        data.setdefault("holds", {})
        return data

    def _save(self):
        with open(self.path, "w") as f:
            json.dump(self.data, f, indent=2)

    # ---- records ----

    def add_record(self, record):
        self.data["records"][record["id"]] = record
        self._save()

    def get_record(self, rewind_id):
        return self.data["records"].get(rewind_id)

    def list_records(self):
        recs = list(self.data["records"].values())
        return sorted(recs, key=lambda r: r["time"], reverse=True)

    def update_record(self, rewind_id, **fields):
        self.data["records"][rewind_id].update(fields)
        self._save()

    # ---- holds ----

    def add_hold(self, key, hours, reason):
        self.data["holds"][key] = {
            "expires_at": (now() + timedelta(hours=hours)).isoformat(),
            "reason": reason,
        }
        self._save()

    def active_hold(self, key):
        hold = self.data["holds"].get(key)
        if not hold:
            return None
        if datetime.fromisoformat(hold["expires_at"]) <= now():
            del self.data["holds"][key]
            self._save()
            return None
        return hold
