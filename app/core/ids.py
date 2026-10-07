"""Single source of truth for event_id validation/normalization."""
import re

_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


def normalize_event_id(value) -> str:
    """Return the lowercase canonical UUID string, or raise ValueError."""
    if not isinstance(value, str) or not _UUID_RE.fullmatch(value):
        raise ValueError(
            "event_id must be a UUID in canonical hyphenated form "
            "(xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)"
        )
    if value.lower() == "00000000-0000-0000-0000-000000000000":
        raise ValueError("event_id must not be the nil UUID")
    return value.lower()