import re

class ValidationError(Exception):
    pass

def is_int(v):
    try:
        int(v)
        return True
    except:
        return False

def validate_condition(cond):
    if not isinstance(cond, dict):
        raise ValidationError("Condition must be a dictionary")
    
    required = {"id", "description", "protocol", "match"}
    missing = required - set(cond.keys())
    if missing:
        raise ValidationError(f"Missing required keys: {missing}")

    match = cond["match"]
    
    for p in ["sport", "dport"]:
        if p in match:
            if not is_int(match[p]) or not (0 <= int(match[p]) <= 65535):
                raise ValidationError(f"Invalid {p}: {match[p]}")

    if "payload_magic" in match:
        pm = match["payload_magic"]
        if isinstance(pm, str) and pm.startswith("0x"):
            if not re.fullmatch(r"0x[0-9a-fA-F]+", pm):
                raise ValidationError("Malformed hex string in payload_magic")

    return True