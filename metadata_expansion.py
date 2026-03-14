from copy import deepcopy

def expand_condition(rootkit_name, cond):
    expanded = []
    if "samples" in cond and isinstance(cond["samples"], list):
        for i, s in enumerate(cond["samples"]):
            new = deepcopy(cond)
            new["id"] = f"{cond.get('id')}_{i}"
            
            if "port" in s: new["match"]["sport"] = s["port"]
            if "magic" in s: new["match"]["payload_magic"] = s["magic"]
            if "password" in s: new["match"]["password"] = s["password"]
            
            new["sample_meta"] = s
            del new["samples"]
            expanded.append(new)
    else:
        expanded.append(cond)
    return expanded