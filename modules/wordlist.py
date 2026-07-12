#!/usr/bin/env python3
"""
Wordlist Generator v6 (2026)

Smart, Morocco/ISP-aware password candidate generator for authorized testing.
Focus: real-world patterns (ESSID, names, cities, phones, years 1960-2030,
keyboard walks, ISP defaults, Fiberhome/Inwi-style transforms).

Target size: up to 1_000_000 unique WPA-valid strings (len 8..12).
"""

from __future__ import annotations

import re
import itertools
from pathlib import Path
from typing import Iterable, List, Optional, Set

# ── Core dictionaries (updated for 2026) ─────────────────

MOROCCAN_NAMES = [
    "Mohamed", "Mohammed", "Ahmed", "Youssef", "Omar", "Hassan", "Karim", "Mehdi",
    "Hicham", "Nabil", "Rachid", "Said", "Adil", "Kamal", "Amine", "Soufiane",
    "Ismail", "Anas", "Hamza", "Khalid", "Jamal", "Abdellah", "Mustapha", "Tariq",
    "Zakaria", "Brahim", "Younes", "Ilyas", "Reda", "Othmane", "Ayoub", "Imad",
    "Fatima", "Amina", "Khadija", "Aicha", "Nadia", "Samira", "Sara", "Imane",
    "Leila", "Yasmine", "Meryem", "Sanae", "Zineb", "Salma", "Nour", "Hajar",
    "Ibtissam", "Kawtar", "Ghita", "Oumaima", "Chaimae", "Rim", "Lina", "Ines",
]

MOROCCAN_CITIES = [
    "Casablanca", "Casa", "Rabat", "Marrakech", "Marrakesh", "Fes", "Fez",
    "Tanger", "Tangier", "Agadir", "Meknes", "Oujda", "Kenitra", "Tetouan",
    "Safi", "Sale", "Essaouira", "Laayoune", "Dakhla", "Mohammedia", "Temara",
    "Nador", "ElJadida", "BeniMellal", "Khouribga", "Settat", "Berrechid",
    "Inezgane", "Taza", "Khemisset", "Larache", "Guelmim", "Errachidia",
]

MOROCCAN_WORDS = [
    "Maroc", "Morocco", "Maghreb", "Bladi", "Hbibti", "Habibti", "Habibi",
    "Raja", "Wydad", "FUS", "FAR", "MAS", "Atlas", "Sahara", "Ramadan",
    "Aid", "Eid", "InchaAllah", "Salam", "Baraka", "Magana", "Darija",
    "Amazigh", "Tamazight", "Chleuh", "Rifi", "Souss", "Nord", "Sud",
]

ISP_BRANDS = [
    "inwi", "Inwi", "INWI", "IAM", "iam", "MarocTelecom", "Orange", "orange",
    "Livebox", "livebox", "Fibre", "Fiber", "ADSL", "ONT", "GPON", "FTTH",
    "ZTE", "Huawei", "TPLink", "Tenda", "Fiberhome", "fh", "Wifi", "WiFi",
    "Perso", "Maison", "Home", "Box", "Modem", "Router",
]

KEYBOARD_WALKS = [
    "qwertyui", "qwerty123", "azertyui", "azerty123", "asdfghjk", "zxcvbnm1",
    "1qaz2wsx", "qazwsxed", "qwerty12", "password", "passw0rd", "P@ssw0rd",
    "admin123", "admin1234", "letmein1", "welcome1", "changeme", "iloveyou",
    "sunshine", "princess", "football", "baseball", "dragon12", "master12",
    "monkey12", "shadow12", "abc12345", "abcd1234", "abcdefg1", "trustno1",
]

COMMON_PASSWORDS = [
    "12345678", "123456789", "1234567890", "00000000", "11111111", "22222222",
    "33333333", "44444444", "55555555", "66666666", "77777777", "88888888",
    "99999999", "12121212", "11223344", "10101010", "password", "passw0rd",
    "Password1", "Password123", "admin123", "admin1234", "root1234", "toor1234",
    "qwerty123", "azerty123", "azertyuiop", "qwertyuiop",
    # 2024-2026 Morocco / ISP flavored
    "Maroc2024", "Maroc2025", "Maroc2026", "Maroc2027",
    "Casa2024", "Casa2025", "Casa2026", "Rabat2024", "Rabat2025", "Rabat2026",
    "Raja2024", "Raja2025", "Raja2026", "Wydad2024", "Wydad2025", "Wydad2026",
    "Orange123", "orange123", "inwi1234", "INWI1234", "livebox123", "fibre1234",
    "Fibre2024", "Fibre2025", "Fibre2026", "Wifi2024", "Wifi2025", "Wifi2026",
    "iam12345", "IAM12345", "telecom1", "Menara12", "Bladi2024", "Bladi2025",
    "Bladi2026", "Hassan2m", "Mohamed6", "MHMD1234", "fatima12", "hassan12",
    "youssef1", "ahmed123", "karim123", "mehdi123", "hamza123", "sara1234",
    "wifi1234", "WIFI1234", "home1234", "maison12", "internet", "Internet1",
    "router12", "gateway1", "default1", "1234qwer", "qwer1234", "1q2w3e4r",
]

SUFFIXES = [
    "123", "1234", "12345", "123456", "1234567", "12345678",
    "0000", "1111", "000", "00", "01", "007", "99", "98", "69", "77",
    "2020", "2021", "2022", "2023", "2024", "2025", "2026", "2027", "2028",
]
SPECIAL = ["", "@", "!", "#", "_", ".", "-", "*"]
YEARS = [str(y) for y in range(1960, 2031)]
RECENT_YEARS = [str(y) for y in range(1990, 2031)]
HOT_YEARS = [str(y) for y in range(2015, 2031)]  # wifi era

LEET_MAP = str.maketrans({
    "a": "4", "e": "3", "i": "1", "o": "0", "s": "5",
    "A": "4", "E": "3", "I": "1", "O": "0", "S": "5",
})

WORDLIST_DIR = Path(__file__).resolve().parent.parent / "data" / "wordlists"


WPA_PASS_MIN_LEN = 8
WPA_PASS_MAX_LEN = 12


def _valid(pwd: str) -> bool:
    """WPA candidates for this project: length 8..12 only."""
    if not pwd:
        return False
    n = len(pwd)
    return WPA_PASS_MIN_LEN <= n <= WPA_PASS_MAX_LEN


class WordlistGenerator:
    """Priority-ordered unique password candidate generator."""

    def __init__(self):
        self.wordlist = {}  # password -> priority (lower = better)

    def clear(self):
        self.wordlist = {}

    def _add(self, word, priority=50):
        if not _valid(str(word)):
            return False
        w = str(word).strip()
        if w not in self.wordlist or priority < self.wordlist[w]:
            self.wordlist[w] = int(priority)
            return True
        return False

    def _extract_words(self, text):
        return [w for w in re.split(r"[\s\-_\.#@+&/]+", str(text or "")) if len(w) >= 2]

    def _extract_numbers(self, text):
        return re.findall(r"\d+", str(text or ""))

    def _case_variants(self, word):
        w = str(word)
        out = {w, w.lower(), w.upper(), w.capitalize()}
        if len(w) > 1:
            out.add(w[:1].upper() + w[1:].lower())
        return [x for x in out if x]

    def _generate_patterns(self, base_word, priority_base=40, years=None):
        years = years or HOT_YEARS
        base_word = str(base_word or "").strip()
        if len(base_word) < 2:
            return
        for form in self._case_variants(base_word):
            if _valid(form):
                self._add(form, priority_base)
            low = form.lower()
            for y in years:
                self._add(low + y, priority_base + 1)
                self._add(form + y, priority_base + 1)
                self._add(y + low, priority_base + 2)
                for sym in ("@", "!", "_", "#", ""):
                    self._add(low + sym + y, priority_base + 2)
                    self._add(form + sym + y, priority_base + 2)
            for s in SUFFIXES:
                self._add(low + s, priority_base + 2)
                self._add(form + s, priority_base + 2)
                self._add(low + "@" + s, priority_base + 3)
            # leet
            leeted = low.translate(LEET_MAP)
            if leeted != low:
                for s in SUFFIXES[:10]:
                    self._add(leeted + s, priority_base + 4)
                for y in years[:12]:
                    self._add(leeted + y, priority_base + 4)
            # doubled
            if len(low) * 2 <= 12:
                self._add(low + low, priority_base + 5)

    def _add_dates(self, priority=70):
        days = [1, 2, 5, 7, 10, 12, 15, 17, 20, 21, 22, 25, 28, 30]
        months = list(range(1, 13))
        for y in RECENT_YEARS:
            for m in months:
                for d in days:
                    self._add("{d:02d}{m:02d}{y}".format(d=d, m=m, y=y), priority)
                    self._add("{y}{m:02d}{d:02d}".format(d=d, m=m, y=y), priority)
                    self._add("{d:02d}{m:02d}{ys}".format(d=d, m=m, ys=y[-2:]), priority + 1)

    def _add_phones_ma(self, target, priority=80):
        """Moroccan mobile patterns 06/07 + systematic tails (not pure random)."""
        # 06/07 + 8 digits systematically
        prefixes = ["06", "07", "05"]
        # denser coverage for common ranges
        step = 1
        # For large targets fill many; for small keep lighter
        max_each = max(1000, min(200000, target // 3))
        count = 0
        for pref in prefixes:
            # structured: pref + AB + CD + EFGH patterns
            for a in range(0, 100):
                for b in range(0, 100, 1 if target >= 500000 else 3):
                    for c in range(0, 100, 1 if target >= 800000 else 7):
                        # 2+2+2+2 = 8 digits after? pref is 2, need 8 more for 10 total often used as pass
                        # Use pref + 6 digits (8 total) and pref + 8 digits (10 total)
                        body6 = "{a:02d}{b:02d}{c:02d}".format(a=a, b=b, c=c)
                        self._add(pref + body6, priority)
                        count += 1
                        if count >= max_each:
                            return
            # full 8-digit tails with stride
            stride = max(1, 100000000 // max(1, max_each))
            for n in range(0, 100000000, stride):
                self._add(pref + "{n:08d}".format(n=n), priority)
                count += 1
                if count >= max_each:
                    return

    def _add_keyboard_and_common(self):
        for p in COMMON_PASSWORDS:
            self._add(p, 5)
        for p in KEYBOARD_WALKS:
            self._add(p, 8)
            for y in HOT_YEARS:
                self._add(p + y, 9)
            for s in SUFFIXES[:8]:
                self._add(p + s, 9)

    def _add_isp_bundle(self, essid="", bssid="", model=""):
        try:
            from modules.isp_passwords import candidates_for_target
            for c in candidates_for_target(
                essid=essid, bssid=bssid, model=model, limit=200
            ):
                conf = int(c.get("confidence") or 20)
                # map confidence to priority (higher conf -> lower priority number)
                pr = max(1, 40 - conf // 3)
                self._add(c.get("password"), pr)
        except Exception:
            pass
        for brand in ISP_BRANDS:
            self._generate_patterns(brand, 25, years=HOT_YEARS)

    def _add_numeric_fills(self, target):
        # repeated digits / simple sequences
        for d in range(10):
            for length in range(8, 13):
                self._add(str(d) * length, 85)
        for seq in ("01234567", "12345678", "23456789", "87654321", "98765432",
                    "13572468", "11223344", "11112222", "12121212", "13131313"):
            self._add(seq, 84)
        # systematic 8-digit
        if len(self.wordlist) < target:
            stride = max(1, 100000000 // max(1, target - len(self.wordlist) + 1))
            for n in range(0, 100000000, stride):
                self._add("{n:08d}".format(n=n), 88)
                if len(self.wordlist) >= target:
                    break
        # 9-10 digit phone-like without prefix
        if len(self.wordlist) < target:
            for n in range(0, 1000000000, 9973):
                self._add("{n:09d}".format(n=n % 1000000000), 89)
                if len(self.wordlist) >= target:
                    break

    def generate_for_network(
        self,
        essid="",
        bssid="",
        brand="",
        model="",
        max_words=100000,
    ):
        self.clear()
        target = max(1, int(max_words))
        essid = str(essid or "")
        words = self._extract_words(essid)
        nums = self._extract_numbers(essid)
        clean = re.sub(r"[\s\-_\.]", "", essid)

        # Priority layers
        self._add_keyboard_and_common()
        self._add_isp_bundle(essid=essid, bssid=bssid, model=model)

        if clean:
            self._generate_patterns(clean, 0)
        for w in words:
            if len(w) >= 3:
                self._generate_patterns(w, 10)
        for n in nums:
            if len(n) >= 4:
                self._add(n.zfill(8) if len(n) < 8 else n, 12)
                for y in HOT_YEARS:
                    self._add(n + y, 13)

        brands = [brand] if brand else list(ISP_BRANDS)
        for bn in brands:
            if not bn:
                continue
            self._generate_patterns(str(bn), 20)
            if clean:
                self._generate_patterns(str(bn) + clean, 15)
                self._generate_patterns(clean + str(bn), 15)

        for name in MOROCCAN_NAMES:
            self._generate_patterns(name, 30)
        for city in MOROCCAN_CITIES:
            self._generate_patterns(city, 35)
        for mw in MOROCCAN_WORDS:
            self._generate_patterns(mw, 40)

        # name + city combos (high value)
        for name in MOROCCAN_NAMES[:25]:
            for city in MOROCCAN_CITIES[:12]:
                self._add(name.lower() + city.lower(), 45)
                self._add(name.capitalize() + city.capitalize(), 45)
                for y in HOT_YEARS[:8]:
                    self._add(name.lower() + y, 46)
                    self._add(city.lower() + y, 46)

        self._add_dates(priority=70)

        # phones + numeric fill to reach target
        if len(self.wordlist) < target:
            self._add_phones_ma(target, priority=80)
        if len(self.wordlist) < target:
            self._add_numeric_fills(target)

        # final guarantee (structured, not pure random): year+serial
        serial = 0
        while len(self.wordlist) < target:
            for y in HOT_YEARS:
                self._add("{y}{serial:06d}".format(y=y, serial=serial), 95)
                serial += 1
                if len(self.wordlist) >= target:
                    break
            if serial > 5000000:
                break

        result = sorted(
            self.wordlist.keys(),
            key=lambda w: (self.wordlist[w], w),
        )[:target]
        return result

    def generate_from_essid(self, essid, max_words=500):
        return self.generate_for_network(essid=essid, max_words=max_words)

    def generate_mega(self, max_words=1000000, essid="", bssid="", brand="", model=""):
        """Generate a large general + targeted list (default 1M)."""
        return self.generate_for_network(
            essid=essid or "Wifi_Maroc_Home",
            bssid=bssid,
            brand=brand,
            model=model,
            max_words=max_words,
        )

    def save_to_file(self, filepath, max_words=1000000):
        words = sorted(
            self.wordlist.keys(),
            key=lambda w: (self.wordlist[w], w),
        )[: int(max_words)]
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            for w in words:
                handle.write(w + "\n")
        return len(words)

    def save_list(self, words: Iterable[str], filepath) -> int:
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        n = 0
        with open(path, "w", encoding="utf-8") as handle:
            for w in words:
                if _valid(w):
                    handle.write(str(w) + "\n")
                    n += 1
        return n
