"""
Occult Tracer - Rule Matcher
==============================
Scores incoming normalized packets against known threat signatures.
Returns (matched: bool, score: int, reasons: str) per packet.
"""

import binascii
from common_utilities import load_config

CONFIG = load_config()
WEIGHTS = CONFIG.get("SCORING_WEIGHTS", {})
THRESHOLD = CONFIG.get("MATCH_SCORE_THRESHOLD", 60)


def hexstr_to_bytes(s):
    """Converts '0xDEADBEEF' hex strings or plain strings to bytes."""
    if isinstance(s, str) and s.startswith("0x"):
        return binascii.unhexlify(s[2:])
    return str(s).encode()


def parse_int_safe(val):
    """Safely converts a value (int, decimal string, or hex string) to int."""
    try:
        if isinstance(val, int): return val
        if isinstance(val, str):
            if val.startswith("0x"): return int(val, 16)
            if val.isdigit(): return int(val)
        return int(val)
    except Exception:
        return None


def match_tcp_options(match, norm_pkt):
    """
    Checks if a required TCP option value is present in the captured packet.
    Handles bytes, string, and integer decoding to ensure robust comparison.
    """
    if "tcp_option_value" not in match:
        return False
    expected = match["tcp_option_value"]
    options = norm_pkt.get("tcp_options_raw", [])

    for opt in options:
        if len(opt) > 1:
            val = opt[1]
            # 1. Direct string comparison
            if str(val) == str(expected):
                return True
            # 2. Bytes → big-endian integer comparison (e.g. cd00r port 1366)
            if isinstance(val, bytes):
                try:
                    if str(int.from_bytes(val, 'big')) == str(expected):
                        return True
                except Exception:
                    pass
                # 3. Bytes → UTF-8 string comparison
                try:
                    if val.decode('utf-8') == str(expected):
                        return True
                except Exception:
                    pass
                # 4. Bytes → hex string comparison
                if "0x" + val.hex() == str(expected):
                    return True
    return False


def match_rule(norm_pkt, rule):
    """
    Scores a normalized packet against a single threat signature rule.

    Scoring Logic:
      - Each matching field adds its configured weight.
      - A +50 burst bonus is applied only when >= 2 distinct fields match,
        preventing false positives from a single common field (e.g. dport=443).

    Returns:
        (matched: bool, score: int, reasons: str)
    """
    match = rule.get("match", {})
    score = 0
    reasons = []
    matched_field_count = 0  # Track how many distinct fields matched

    # Protocol pre-check: skip immediately if protocol doesn't match
    if norm_pkt.get("protocol") not in rule.get("protocols", []):
        return False, 0, ""

    # --- Header Field Matching ---
    for fld in ["sport", "dport", "seq", "ack", "window_size"]:
        if fld in match:
            expected = parse_int_safe(match[fld])
            actual = norm_pkt.get(fld)
            if expected is not None and actual == expected:
                score += WEIGHTS.get(fld, 5)
                reasons.append(f"{fld}={expected}")
                matched_field_count += 1

    # --- Source Port Range Matching (e.g. Syslogk high-port ephemeral pattern) ---
    if "sport_range" in match and norm_pkt.get("sport") is not None:
        sr = match["sport_range"]
        if isinstance(sr, list) and len(sr) == 2:
            if sr[0] <= norm_pkt.get("sport") <= sr[1]:
                score += WEIGHTS.get("sport", 10)
                reasons.append(f"sport_range={sr}")
                matched_field_count += 1

    # --- Payload Magic Bytes (REQUIRED field — miss = hard reject) ---
    if "payload_magic" in match:
        magic = hexstr_to_bytes(match["payload_magic"])
        variants = norm_pkt.get("payload_variants", [norm_pkt.get("payload", b"")])
        found = False
        for i, variant in enumerate(variants):
            if magic in variant:
                found = True
                method = "raw" if i == 0 else "decoded"
                reasons.append(f"magic_found({method})")
                break
        if found:
            score += WEIGHTS.get("payload_magic", 30)
            matched_field_count += 1
        else:
            # Magic bytes are required; if absent the rule cannot match
            return False, 0, "magic_miss"

    # --- Password Field Matching ---
    if "password" in match:
        pwd = hexstr_to_bytes(match["password"])
        variants = norm_pkt.get("payload_variants", [norm_pkt.get("payload", b"")])
        for i, variant in enumerate(variants):
            if pwd in variant:
                method = "raw" if i == 0 else "decoded"
                reasons.append(f"password_found({method})")
                score += WEIGHTS.get("password", 30)
                matched_field_count += 1
                break

    # --- Payload Prefix Matching ---
    if "payload_starts_with" in match:
        prefix = hexstr_to_bytes(match["payload_starts_with"])
        variants = norm_pkt.get("payload_variants", [norm_pkt.get("payload", b"")])
        for i, variant in enumerate(variants):
            if variant.startswith(prefix):
                method = "raw" if i == 0 else "decoded"
                reasons.append(f"payload_starts_with_found({method})")
                score += WEIGHTS.get("payload_starts_with", 25)
                matched_field_count += 1
                break

    # --- IP Fragmentation Offset Detection ---
    if "ip_offset" in match and norm_pkt.get("ip_offset") is not None:
        if norm_pkt.get("ip_offset") == match["ip_offset"]:
            score += WEIGHTS.get("ip_offset", 20)
            reasons.append("ip_offset_detected")
            matched_field_count += 1

    # --- TCP Option Value Matching ---
    if match_tcp_options(match, norm_pkt):
        score += WEIGHTS.get("tcp_option_value", 20)
        reasons.append("tcp_opt_match")
        matched_field_count += 1

    # --- Critical Burst Bonus ---
    # Only apply the +50 burst if at least 2 distinct fields matched.
    # This prevents a single common field (e.g. dport=443) from causing a false positive.
    if matched_field_count >= 2:
        score += 50

    matched = score >= THRESHOLD
    return matched, score, ", ".join(reasons)