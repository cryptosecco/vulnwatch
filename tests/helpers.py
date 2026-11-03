import json
import os
from datetime import datetime, timezone

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
NOW = datetime(2026, 11, 3, 12, 0, 0, tzinfo=timezone.utc)


def fixture_path(rel):
    return os.path.join(FIX, rel)


def load_fixture(rel):
    with open(fixture_path(rel)) as f:
        return json.load(f)


def json_bytes(obj):
    return json.dumps(obj).encode("utf-8")
