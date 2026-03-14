from scapy.all import IP, defrag

class FragmentReassembler:
    """
    Anti-Evasion Module: Handles IP Fragmentation.
    Buffers incoming fragments and reassembles them into full packets
    before passing them to the inspection engine.
    """
    def __init__(self):
        # Buffer to store fragments: Key=(src, dst, id), Value=List of packets
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

        # Identification Key for this IP flow
        key = (ip.src, ip.dst, ip.id)

        if key not in self.buffer:
            self.buffer[key] = []

        self.buffer[key].append(pkt)

        # Optimization: Only attempt defrag if we see the 'Last Fragment' (MF=0)
        # or if buffer is getting large.
        if ip.flags.MF == 0:
            try:
                # Scapy's defrag returns ([reassembled], [remaining])
                # We assume a clean stream for this PoC
                reassembled_list = defrag(self.buffer[key])
                
                # Check if it returned a tuple of lists or a single list
                lists_to_check = reassembled_list if isinstance(reassembled_list, tuple) else [reassembled_list]
                for plist in lists_to_check:
                    for p in plist:
                        # Find the first valid, fully reassembled IP packet
                        if IP in p and p[IP].frag == 0 and p[IP].flags.MF == 0:
                            # Clean up buffer
                            del self.buffer[key]
                            # Return the full, reassembled packet for inspection
                            return p
            except Exception as e:
                print(f"[!] Defrag Error: {e}")
                
        return None