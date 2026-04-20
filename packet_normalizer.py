from scapy.all import IP, TCP, UDP, Raw
import base64
import binascii
import math


def calculate_shannon_entropy(data: bytes) -> float:
    """
    Calculates the Shannon Entropy of a byte sequence.

    Returns a value between 0.0 (perfectly predictable) and 8.0
    (perfectly random / encrypted). High entropy (> 6.5) on a payload
    of >= 32 bytes strongly indicates encryption or compression.
    """
    if not data:
        return 0.0
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    total = len(data)
    entropy = 0.0
    for count in byte_counts:
        if count == 0:
            continue
        probability = count / total
        entropy -= probability * math.log2(probability)
    return round(entropy, 4)


def get_xor_decoded_variants(raw_load: bytes) -> list:
    """
    Lazy XOR decoder — call this ONLY when a rule requires payload_magic matching.
    Attempts all 256 single-byte XOR keys and returns the first variant
    with >= 30% printable characters (a strong indicator that the key is correct).

    Real-world rootkits (BPFDoor, Syslogk) use single-byte XOR to hide
    magic bytes from signature scanners.
    """
    variants = []
    for key in range(1, 256):
        xor_decoded = bytes([b ^ key for b in raw_load])
        printable_ratio = sum(
            1 for b in xor_decoded if 32 <= b <= 126
        ) / max(len(xor_decoded), 1)
        if printable_ratio > 0.3:
            variants.append(xor_decoded)
            break  # One good XOR key is enough
    return variants


def normalize_packet(pkt):
    """
    Extracts high-level fields, DECODES payloads for deep inspection,
    and calculates Shannon Entropy for encrypted payload detection.
    """
    if IP not in pkt: return None
    
    norm = {
        "protocol": "TCP" if TCP in pkt else "UDP" if UDP in pkt else "IP",
        "ip_src": pkt[IP].src,
        "ip_dst": pkt[IP].dst
    }
    
    if TCP in pkt:
        norm["sport"] = pkt[TCP].sport
        norm["dport"] = pkt[TCP].dport
        norm["seq"] = pkt[TCP].seq
        norm["ack"] = pkt[TCP].ack
        norm["window_size"] = pkt[TCP].window
        norm["tcp_options_raw"] = pkt[TCP].options 
        
    elif UDP in pkt:
        norm["sport"] = pkt[UDP].sport
        norm["dport"] = pkt[UDP].dport
    
    # --- Payload Normalization & Decoding ---
    norm["payload_variants"] = []
    
    if Raw in pkt:
        raw_load = bytes(pkt[Raw].load)
    else:
        # Fallback for Scapy padding issues with custom payloads
        raw_load = bytes(pkt.payload.payload.payload) if pkt.payload and pkt.payload.payload and hasattr(pkt.payload.payload, 'payload') else b""
        
    if len(raw_load) > 0:
        norm["payload"] = raw_load
        norm["payload_variants"] = [raw_load]
        
        # Attempt Base64 decoding
        try:
            b64_decoded = base64.b64decode(raw_load.strip())
            if b64_decoded:
                norm["payload_variants"].append(b64_decoded)
        except Exception:
            pass

        # Attempt Hex decoding (e.g. payload is the ASCII string "414243")
        try:
            hex_decoded = binascii.unhexlify(raw_load.strip())
            norm["payload_variants"].append(hex_decoded)
        except Exception:
            pass

        # NOTE: XOR brute-force is intentionally NOT done here.
        # It is a slow O(n*256) operation. The rule_matcher calls
        # get_xor_decoded_variants() lazily only when a rule needs it.
        
        # --- [NEW] Shannon Entropy Calculation ---
        # Calculate entropy on the raw payload bytes
        # Only calculate on payloads large enough to be statistically meaningful
        if len(raw_load) >= 32:
            norm["entropy"] = calculate_shannon_entropy(raw_load)
        else:
            norm["entropy"] = 0.0
            
    else:
        norm["payload"] = b""
        norm["entropy"] = 0.0

    # --- [NEW] Magic Pattern Detection ---
    # Checks if the raw payload starts with a non-TLS, non-HTTP byte pattern.
    # Real TLS ClientHello starts with 0x16 0x03. Real HTTP starts with 'GET'/'POST'.
    # Anything else on port 443 is likely a custom C2 protocol with magic bytes.
    raw_payload = norm.get("payload", b"")
    has_magic = False
    if len(raw_payload) >= 4:
        first_byte = raw_payload[0]
        # TLS starts with 0x16 (22), HTTP starts with printable ASCII (G=71, P=80, H=72, D=68, O=79)
        is_tls  = (first_byte == 0x16)
        is_http = (first_byte in [71, 80, 72, 68, 79, 67])  # GET POST HEAD DELETE OPTIONS CONNECT
        has_magic = not is_tls and not is_http
    norm["has_magic_pattern"] = 1 if has_magic else 0

    # --- [NEW] Unsolicited Inbound Connection Detection ---
    # This discriminates malware C2 beacons from legitimate HTTPS responses
    # WITHOUT relying on IP ranges (which fail in virtual lab environments
    # where attacker Kali is also RFC1918 10.x.x.x).
    #
    # The key insight is PORT DIRECTION:
    #   Malware beacon:   Kali(sport=12345 HIGH) --> Ubuntu(dport=443 WELL-KNOWN) → flag=1
    #   HTTPS response:   Google(sport=443 WELL-KNOWN) --> Ubuntu(dport=54321 HIGH) → flag=0
    #
    # If dport is well-known (443/80/22) AND sport is high/ephemeral (>1024):
    #   → someone is INITIATING an unsolicited connection TO our server port
    #   → this is the exact pattern of malware C2, backdoor beacons, and rootkit triggers
    #   → legitimate HTTPS responses have the OPPOSITE pattern (sport=443, dport=high)
    sport_n  = norm.get("sport", 0)
    dport_n  = norm.get("dport", 0)
    WELL_KNOWN_PORTS = {80, 443, 22, 8443, 8080, 21, 23, 25, 53}
    norm["is_inbound_to_server"] = 1 if (dport_n in WELL_KNOWN_PORTS and sport_n > 1024) else 0

    return norm