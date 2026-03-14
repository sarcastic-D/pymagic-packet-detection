from scapy.all import IP, TCP, UDP, Raw
import base64
import binascii
import math


def calculate_shannon_entropy(data: bytes) -> float:
    """
    Calculates the Shannon Entropy of a byte sequence.
    
    Returns a value between 0.0 (perfectly uniform/predictable) 
    and 8.0 (perfectly random/encrypted).
    
    High entropy (> 7.5) strongly indicates encrypted, compressed,
    or obfuscated payloads designed to evade signature-based detection.
    """
    if not data or len(data) == 0:
        return 0.0
    
    # Count the frequency of each byte value (0x00 - 0xFF)
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    
    total = len(data)
    entropy = 0.0
    
    for count in byte_counts:
        if count == 0:
            continue
        # Probability of this byte value
        probability = count / total
        # Shannon's formula: H = -sum(p * log2(p))
        entropy -= probability * math.log2(probability)
    
    return round(entropy, 4)


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
        # 1. Always add the raw payload
        norm["payload"] = raw_load 
        norm["payload_variants"].append(raw_load)
        
        # 2. Attempt Base64 Decode
        try:
            b64_decoded = base64.b64decode(raw_load.strip())
            if b64_decoded:
                norm["payload_variants"].append(b64_decoded)
        except Exception:
            pass 
            
        # 3. Attempt Hex Decode (e.g., payload is "414243")
        try:
            hex_decoded = binascii.unhexlify(raw_load.strip())
            norm["payload_variants"].append(hex_decoded)
        except Exception:
            pass 
        
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
        
    return norm