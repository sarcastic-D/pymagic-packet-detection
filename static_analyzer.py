import argparse
import json
import os
from common_utilities import load_config
from structure_validator import validate_condition, ValidationError
from metadata_expansion import expand_condition
from rule_generator import normalize_rule, write_rules, write_suricata
from semantic_validator import SemanticValidator

def main():
    config = load_config()
    
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="infile", default=config.get("INPUT_FILE", "conditions.json"))
    ap.add_argument("--outdir", dest="outdir", default=config.get("OUTPUT_DIR", "output_v2"))
    ap.add_argument("--suricata", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(args.infile):
        print(f"[ERROR] Input file not found: {args.infile}")
        return

    with open(args.infile, "r") as fh:
        db = json.load(fh)

    normalized_rules = []
    errors = []

    print(f"[*] Sentinel Forge v2: Reading {args.infile}...")

    for rk_name, data in db.items():
        if not isinstance(data, dict) or "conditions" not in data:
            continue

        for cond in data["conditions"]:
            expanded_list = expand_condition(rk_name, cond)

            for ex in expanded_list:
                try:
                    validate_condition(ex)
                    SemanticValidator(ex)
                    nr = normalize_rule(rk_name, ex)
                    normalized_rules.append(nr)

                except ValidationError as e:
                    errors.append({"rootkit": rk_name, "error": str(e)})

    combined_path, count = write_rules(normalized_rules, args.outdir)
    print(f"[+] Compiled {count} rules into {combined_path}")

    if args.suricata:
        s_path = write_suricata(normalized_rules, args.outdir)
        print(f"[+] Wrote Suricata rules -> {s_path}")

    if errors:
        print(f"[!] Found {len(errors)} validation errors.")
        with open(os.path.join(args.outdir, "errors.json"), "w") as fh:
            json.dump(errors, fh, indent=2)

if __name__ == "__main__":
    main()