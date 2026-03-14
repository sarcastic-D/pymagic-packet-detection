# import os
# import json
# import hashlib
# from datetime import datetime
# from copy import deepcopy
# from common_v2 import load_config

# CONFIG = load_config()
# WEIGHTS = CONFIG.get("SCORING_WEIGHTS", {})

# def ensure_dir(d):
#     os.makedirs(d, exist_ok=True)

# def make_rule_id(match_data):
#     # Deterministic SHA256 Hash
#     canonical = json.dumps(match_data, sort_keys=True)
#     hash_id = hashlib.sha256(canonical.encode()).hexdigest()[:12]
#     return f"rule_{hash_id}"

# def compute_score(match):
#     score = 0
#     for field in match:
#         if field in WEIGHTS:
#             score += WEIGHTS[field]
#         elif "offset" in field:
#              score += WEIGHTS.get("ip_offset", 10)
#     return min(score, 100)

# def normalize_rule(rootkit_name, cond):
#     r = {}
#     r["meta"] = {
#         "generated_at": datetime.utcnow().isoformat(),
#         "source_rootkit": rootkit_name,
#         "source_id": cond.get("id"),
#         "description": cond.get("description", "")
#     }
#     proto = cond.get("protocol")
#     r["protocols"] = [p.upper() for p in (proto if isinstance(proto, list) else [str(proto)])]
#     r["match"] = deepcopy(cond.get("match", {}))
    
#     if "sample_meta" in cond:
#         r["evidence"] = {"sample_meta": cond["sample_meta"]}
#     else:
#         r["evidence"] = {"original_condition": cond}

#     r["rule_id"] = make_rule_id(r["match"])
#     r["score"] = compute_score(r["match"])
#     return r

# def suricata_rule_from_normalized(r):
#     proto = r["protocols"][0].lower()
#     if proto == "ANY": proto = "tcp"
#     match = r["match"]
#     dport = match.get("dport", "any")
#     sport = match.get("sport", "any")
#     sid = int(int(r["rule_id"].split("_")[1], 16) % 10000000) + 1000000
    
#     options = [f'msg:"{r["meta"].get("description", "Sentinel Forge Rule")}"']
    
#     if "payload_magic" in match:
#         v = match["payload_magic"]
#         if isinstance(v, str) and v.startswith("0x"):
#             options.append(f'content:"|{v[2:].upper()}|"')
#         else:
#             options.append(f'content:"{v}"')
            
#     if "seq" in match: options.append(f'seq:{match["seq"]}')
#     if "window_size" in match: options.append(f'window:{match["window_size"]}')
    
#     options.append(f"sid:{sid}")
#     options.append("rev:1")
#     return f'alert {proto} {sport} -> any {dport} ({"; ".join(options)};)\n'

# def write_rules(rules, outdir):
#     ensure_dir(outdir)
#     combined = []
#     for r in rules: combined.append(r)
#     combined_path = os.path.join(outdir, "combined_rules_v2.json")
#     with open(combined_path, "w") as fh:
#         json.dump(combined, fh, indent=2)
#     return combined_path, len(combined)

# def write_suricata(rules_list, outdir):
#     ensure_dir(outdir)
#     outpath = os.path.join(outdir, "suricata_v2.rules")
#     with open(outpath, "w") as fh:
#         for r in rules_list: fh.write(suricata_rule_from_normalized(r))
#     return outpath

import os
import json
import hashlib
from datetime import datetime
from copy import deepcopy
from common_utilities import load_config

CONFIG = load_config()
WEIGHTS = CONFIG.get("SCORING_WEIGHTS", {})

def ensure_dir(d):
    os.makedirs(d, exist_ok=True)

def make_rule_id(match_data):
    # Deterministic SHA256 Hash
    canonical = json.dumps(match_data, sort_keys=True)
    hash_id = hashlib.sha256(canonical.encode()).hexdigest()[:12]
    return f"rule_{hash_id}"

def compute_score(match):
    score = 0
    for field in match:
        if field in WEIGHTS:
            score += WEIGHTS[field]
        elif "offset" in field:
             score += WEIGHTS.get("ip_offset", 10)
    return min(score, 100)

def normalize_rule(rootkit_name, cond):
    r = {}
    r["meta"] = {
        "generated_at": datetime.utcnow().isoformat(),
        "source_rootkit": rootkit_name,
        "source_id": cond.get("id"),
        "description": cond.get("description", "")
    }
    proto = cond.get("protocol")
    r["protocols"] = [p.upper() for p in (proto if isinstance(proto, list) else [str(proto)])]
    r["match"] = deepcopy(cond.get("match", {}))
    
    if "sample_meta" in cond:
        r["evidence"] = {"sample_meta": cond["sample_meta"]}
    else:
        r["evidence"] = {"original_condition": cond}

    r["rule_id"] = make_rule_id(r["match"])
    r["score"] = compute_score(r["match"])
    return r

def suricata_rule_from_normalized(r):
    """
    Translates a normalized rule into valid Suricata/Snort rule syntax.
    Supports: payload_magic, password, payload_starts_with, seq, window_size,
    and Shannon Entropy-based meta comments.
    """
    proto = r["protocols"][0].lower()
    if proto == "any": proto = "tcp"
    match = r["match"]
    dport = match.get("dport", "any")
    sport = match.get("sport", "any")
    sid = int(int(r["rule_id"].split("_")[1], 16) % 10000000) + 1000000
    
    options = [f'msg:"{r["meta"].get("description", "Sentinel Forge Rule")}"']
    
    # Content matching options
    if "payload_magic" in match:
        v = match["payload_magic"]
        if isinstance(v, str) and v.startswith("0x"):
            options.append(f'content:"|{v[2:].upper()}|"')
        else:
            options.append(f'content:"{v}"')
    
    if "password" in match:
        v = match["password"]
        if isinstance(v, str) and v.startswith("0x"):
            options.append(f'content:"|{v[2:].upper()}|"')
        else:
            options.append(f'content:"{v}"')

    if "payload_starts_with" in match:
        v = match["payload_starts_with"]
        if isinstance(v, str) and v.startswith("0x"):
            options.append(f'content:"|{v[2:].upper()}|"; offset:0; depth:4')
        else:
            options.append(f'content:"{v}"; offset:0; depth:{len(v)}')
            
    # Header matching options
    if "seq" in match: options.append(f'seq:{match["seq"]}')
    if "window_size" in match: options.append(f'window:{match["window_size"]}')
    
    # Entropy-based metadata (informational, Suricata doesn't natively support entropy matching)
    if match.get("high_entropy"):
        options.append('metadata:sentinel_forge_entropy_anomaly')
    
    options.append(f"sid:{sid}")
    options.append("rev:1")
    return f'alert {proto} {sport} -> any {dport} ({"; ".join(options)};)\n'

def write_rules(rules, outdir):
    ensure_dir(outdir)
    combined = []
    for r in rules: combined.append(r)
    combined_path = os.path.join(outdir, "combined_rules_v2.json")
    with open(combined_path, "w") as fh:
        json.dump(combined, fh, indent=2)
    return combined_path, len(combined)

def write_suricata(rules_list, outdir):
    ensure_dir(outdir)
    outpath = os.path.join(outdir, "suricata_v2.rules")
    with open(outpath, "w") as fh:
        for r in rules_list: fh.write(suricata_rule_from_normalized(r))
    return outpath