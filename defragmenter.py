from scapy.all import IP, defrag
import time

# Maximum seconds to keep an incomplete fragment stream in memory.
# If a stream is not completed within this window it is evicted.
_FRAGMENT_TTL_SECONDS = 30


class FragmentReassembler:
    """
    Anti-Evasion Module: Handles IP Fragmentation.
    Buffers incoming fragments and reassembles them into full packets
    before passing them to the inspection engine.
    """
    def __init__(self):
        # Buffer: Key=(src, dst, id) → {"pkts": [], "first_seen": float}
        self.buffer = {}

    def process(self, pkt):
        """
        Ingests a packet.
        Returns:
          - The packet itself (if not fragmented).
          - A reassembled packet (if fragmentation finished).
          - None (if packet is a fragment and we are waiting for more).
        """
        if IP not in pkt:
            return pkt

        ip = pkt[IP]
        
        # Check for fragmentation flags (MF=1) or offset > 0
        is_fragment = (ip.flags.MF == 1) or (ip.frag > 0)

        if not is_fragment:
            return pkt

        key = (ip.src, ip.dst, ip.id)

        # TTL eviction: clean up stale fragment streams before adding new ones.
        now = time.time()
        stale_keys = [
            k for k, v in self.buffer.items()
            if now - v["first_seen"] > _FRAGMENT_TTL_SECONDS
        ]
        for k in stale_keys:
            del self.buffer[k]

        if key not in self.buffer:
            self.buffer[key] = {"pkts": [], "first_seen": now}

        self.buffer[key]["pkts"].append(pkt)
        
        # VISUAL PROOF FOR DEMO
        print(f"    [⚡ DEFRAG] Buffering fragment (offset={ip.frag}) from {ip.src}...")

        # Optimization: Only attempt defrag if we see the 'Last Fragment' (MF=0)
        # or if buffer is getting large.
        if ip.flags.MF == 0:
            try:
                reassembled_list = defrag(self.buffer[key]["pkts"])
                lists_to_check = reassembled_list if isinstance(reassembled_list, tuple) else [reassembled_list]
                for plist in lists_to_check:
                    for p in plist:
                        if IP in p and p[IP].frag == 0 and p[IP].flags.MF == 0:
                            del self.buffer[key]
                            print(f"    [🛡️ DEFRAG] Successfully reassembled {len(p)} bytes from fragments! Passing to DPI...")
                            p._was_fragmented = True
                            return p
            except Exception as e:
                print(f"[!] Defrag Error: {e}")
                
        return None