import requests
import time
from collections import OrderedDict
from common_utilities import load_config

CONFIG = load_config()
OTX_API_KEY = CONFIG.get("OTX_API_KEY", "")

# We keep a small local cache so we don't query the API 100 times for the same IP
_cache = OrderedDict()
_CACHE_MAX = 500

def check_ip_reputation(ip_address):
    """
    Queries AlienVault OTX to see if the world thinks this IP is malicious.
    """
    if ip_address in _cache:
        return _cache[ip_address]
        
    if not OTX_API_KEY or OTX_API_KEY == "YOUR_FREE_API_KEY_HERE":
        # Fallback if no key is configured
        return {"pulse_count": 0, "error": "No API Key"}

    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"

    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            result = {
                "pulse_count": pulse_count,
                "country": data.get("country_name", "Unknown"),
                "error": None
            }
        else:
            result = {"pulse_count": 0, "error": f"HTTP {response.status_code}"}
            
        # Add to LRU cache
        _cache[ip_address] = result
        if len(_cache) > _CACHE_MAX:
            _cache.popitem(last=False)
            
        return result
        
    except Exception as e:
        return {"pulse_count": 0, "error": str(e)}

def revalidate_blocked_ip(ip_address):
    """
    Runs after an IP is blocked to act as a sanity-check against False Positives.
    """
    intel = check_ip_reputation(ip_address)
    
    # Internal Network IPs (192.168, 10.0, etc.) will naturally return 0 pulses.
    # But for external IPs, a 0 score could indicate a False Positive.
    
    if intel.get("pulse_count", 0) > 0:
        print(f"\n[THREAT INTEL CONFIRMATION] {ip_address} is globally flagged! "
              f"({intel['pulse_count']} threat reports. Country: {intel.get('country')})")
    elif not intel.get("error"):
        print(f"\n[THREAT INTEL WARNING] {ip_address} was blocked, but has 0 global threat reports. "
              f"Potential False Positive. Flagging for SOC Analyst review.")
    else:
        # We had an error, ignore silently or log
        pass
