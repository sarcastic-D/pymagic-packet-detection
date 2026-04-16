# import binascii
# from common_utilities import load_config

# CONFIG = load_config()
# WEIGHTS = CONFIG.get("SCORING_WEIGHTS", {})
# THRESHOLD = CONFIG.get("MATCH_SCORE_THRESHOLD", 60)

# def hexstr_to_bytes(s):
#     if isinstance(s, str) and s.startswith("0x"):
#         return binascii.unhexlify(s[2:])
#     return str(s).encode()

# def parse_int_safe(val):
#     try:
#         if isinstance(val, int): return val
#         if isinstance(val, str):
#             if val.startswith("0x"): return int(val, 16)
#             if val.isdigit(): return int(val)
#         return int(val)
#     except:
#         return None

# def match_tcp_options(match, norm_pkt):
#     """
#     FIXED: Handles both String and Integer byte decoding.
#     """
#     if "tcp_option_value" not in match: return False
#     expected = match["tcp_option_value"]
#     options = norm_pkt.get("tcp_options_raw", [])
    
#     for opt in options:
#         # opt is tuple (Name, Value)
#         if len(opt) > 1:
#             val = opt[1]
            
#             # 1. Compare Strings (Direct)
#             if str(val) == str(expected): return True
            
#             # 2. Handle Bytes decoding
#             if isinstance(val, bytes):
#                 # Try decoding as Integer (Fixes cd00r 1366 issue)
#                 # We try various byte lengths (2 or 4 bytes are common for options)
#                 try:
#                     int_val = int.from_bytes(val, 'big')
#                     if str(int_val) == str(expected): return True
#                 except: pass
                
#                 # Try decoding as String
#                 try:
#                     if val.decode('utf-8') == str(expected): return True
#                 except: pass
                
#                 # Try Hex
#                 if "0x" + val.hex() == str(expected): return True

#     return False

# def match_rule(norm_pkt, rule):
#     match = rule.get("match", {})
#     score = 0
#     reasons = []
    
#     critical_match = False

#     if norm_pkt.get("protocol") not in rule.get("protocols", []):
#         return False, 0, ""

#     # Header Fields
#     for fld in ["sport", "dport", "seq", "ack", "window_size"]:
#         if fld in match:
#             expected = parse_int_safe(match[fld])
#             actual = norm_pkt.get(fld)
            
#             if expected is not None and actual == expected:
#                 score += WEIGHTS.get(fld, 5)
#                 reasons.append(f"{fld}={expected}")
                
#                 # CRITICAL UPDATE: 
#                 # 1. Boost specific headers (Window, Seq, Ack)
#                 # 2. Boost Source Ports if they are non-standard (Ephemeral/High) to catch Syslogk
#                 if fld in ["window_size", "seq", "ack"]:
#                     critical_match = True
#                 if fld == "sport" and expected > 1024:
#                     critical_match = True

#     # Payload Magic
#     if "payload_magic" in match:
#         magic = hexstr_to_bytes(match["payload_magic"])
#         if magic in norm_pkt.get("payload", b""):
#             score += WEIGHTS.get("payload_magic", 30)
#             reasons.append("magic_found")
#             critical_match = True 
#         else:
#             return False, 0, "magic_miss"

#     # TCP Option
#     if match_tcp_options(match, norm_pkt):
#         score += WEIGHTS.get("tcp_option_value", 20)
#         reasons.append("tcp_opt_match")
#         critical_match = True 
    
#     # Apply Boost
#     if critical_match:
#         score += 50 

#     matched = score >= THRESHOLD
#     return matched, score, ", ".join(reasons)


import binascii
from common_utilities import load_config

CONFIG = load_config()
WEIGHTS = CONFIG.get("SCORING_WEIGHTS", {})
THRESHOLD = CONFIG.get("MATCH_SCORE_THRESHOLD", 60)

def hexstr_to_bytes(s):
    if isinstance(s, str) and s.startswith("0x"):
        return binascii.unhexlify(s[2:])
    return str(s).encode()

def parse_int_safe(val):
    try:
        if isinstance(val, int): return val
        if isinstance(val, str):
            if val.startswith("0x"): return int(val, 16)
            if val.isdigit(): return int(val)
        return int(val)
    except:
        return None

def match_tcp_options(match, norm_pkt):
    if "tcp_option_value" not in match: return False
    expected = match["tcp_option_value"]
    options = norm_pkt.get("tcp_options_raw", [])
    
    for opt in options:
        if len(opt) > 1:
            val = opt[1]
            if str(val) == str(expected): return True
            if isinstance(val, bytes):
                try:
                    int_val = int.from_bytes(val, 'big')
                    if str(int_val) == str(expected): return True
                except: pass
                try:
                    if val.decode('utf-8') == str(expected): return True
                except: pass
                if "0x" + val.hex() == str(expected): return True
    return False

def match_rule(norm_pkt, rule):
    match = rule.get("match", {})
    score = 0
    reasons = []
    
    critical_match = False

    if norm_pkt.get("protocol") not in rule.get("protocols", []):
        return False, 0, ""

    for fld in ["sport", "dport", "seq", "ack", "window_size"]:
        if fld in match:
            expected = parse_int_safe(match[fld])
            actual = norm_pkt.get(fld)
            
            if expected is not None and actual == expected:
                score += WEIGHTS.get(fld, 5)
                reasons.append(f"{fld}={expected}")
                if fld in ["window_size", "seq", "ack"]:
                    critical_match = True
                if fld == "sport" and expected > 1024:
                    critical_match = True

    if "sport_range" in match and norm_pkt.get("sport") is not None:
        sr = match["sport_range"]
        if isinstance(sr, list) and len(sr) == 2:
            if sr[0] <= norm_pkt.get("sport") <= sr[1]:
                score += WEIGHTS.get("sport", 10)
                reasons.append(f"sport_range={sr}")
                critical_match = True

    if "payload_magic" in match:
        magic = hexstr_to_bytes(match["payload_magic"])
        variants = norm_pkt.get("payload_variants", [norm_pkt.get("payload", b"")])
        
        found = False
        for i, variant in enumerate(variants):
            if magic in variant:
                found = True
                method = "raw" if i==0 else "decoded"
                reasons.append(f"magic_found({method})")
                break
        
        if found:
            score += WEIGHTS.get("payload_magic", 30)
            critical_match = True 
        else:
            # If magic is required but not found, miss.
            return False, 0, "magic_miss"

    if "password" in match:
        pwd = hexstr_to_bytes(match["password"])
        variants = norm_pkt.get("payload_variants", [norm_pkt.get("payload", b"")])
        
        found = False
        for i, variant in enumerate(variants):
            if pwd in variant:
                found = True
                method = "raw" if i==0 else "decoded"
                reasons.append(f"password_found({method})")
                break
        
        if found:
            score += WEIGHTS.get("password", 30)
            critical_match = True

    if "payload_starts_with" in match:
        prefix = hexstr_to_bytes(match["payload_starts_with"])
        variants = norm_pkt.get("payload_variants", [norm_pkt.get("payload", b"")])
        
        found = False
        for i, variant in enumerate(variants):
            if variant.startswith(prefix):
                found = True
                method = "raw" if i==0 else "decoded"
                reasons.append(f"payload_starts_with_found({method})")
                break
        
        if found:
            score += WEIGHTS.get("payload_starts_with", 25)
            critical_match = True

    if "ip_offset" in match and norm_pkt.get("ip_offset") is not None:
        if norm_pkt.get("ip_offset") == match["ip_offset"]:
            score += WEIGHTS.get("ip_offset", 20)
            reasons.append(f"ip_offset_detected")
            critical_match = True

    if match_tcp_options(match, norm_pkt):
        score += WEIGHTS.get("tcp_option_value", 20)
        reasons.append("tcp_opt_match")
        critical_match = True 
    
    # --- [NEW] Shannon Entropy Detection ---
    # If the payload has high entropy (> threshold), it indicates 
    # encrypted/obfuscated content designed to evade signature-based detection.
    entropy_threshold = CONFIG.get("ENTROPY_THRESHOLD", 7.5)
    entropy_val = norm_pkt.get("entropy", 0.0)
    if entropy_val > entropy_threshold:
        entropy_boost = WEIGHTS.get("entropy", 35)
        score += entropy_boost
        reasons.append(f"high_entropy({entropy_val})")
        critical_match = True

    if critical_match:
        score += 50 

    matched = score >= THRESHOLD
    return matched, score, ", ".join(reasons)