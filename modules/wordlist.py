#!/usr/bin/env python3
"""
Smart Wordlist Generator
- Generates targeted wordlists based on:
  - Network name (ESSID)
  - Router manufacturer
  - Location patterns
  - Common password patterns
"""

import re
from datetime import datetime


# Common password patterns by region
PATTERNS = {
    "phone": [
        "05{}", "06{}", "07{}", "08{}", "09{}",
        "+212{}", "+213{}", "+216{}", "+966{}", "+971{}",
    ],
    "date": [
        "{:04d}{:02d}{:02d}", "{:02d}{:02d}{:04d}",
        "{:02d}{:02d}{:02d}", "{:02d}/{:02d}/{:04d}",
    ],
    "name": [
        "{}123", "{}1234", "{}12345", "{}@123", "{}@1234",
        "{}2020", "{}2021", "{}2022", "{}2023", "{}2024", "{}2025", "{}2026",
        "{}_123", "{}_2024", "{}00", "{}01",
    ],
    "address": [
        "{}{}", "door{}", "house{}", "flat{}",
    ],
}

# Common base words
COMMON_WORDS = [
    "password", "12345678", "123456789", "1234567890",
    "qwerty", "abc123", "monkey", "master", "dragon",
    "iloveyou", "trustno1", "sunshine", "princess",
    "football", "shadow", "superman", "michael",
    "letmein", "welcome", "admin", "passw0rd",
]

# Arabic/Moroccan common words
ARABIC_WORDS = [
    "allah", "mohamed", "ahmed", "youssef", "khalid",
    "omar", "ali", "hassan", "fatima", "amina",
    "sara", "nadia", "hamza", "anas", "ismail",
    "rachid", "mourad", "nabil", "soufiane", "abdelilah",
    "maghrib", "maroc", "casablanca", "rabat", "fes",
    "marrakech", "tanger", "agadir", "meknes", "oujda",
    "inwi", "maroc_telecom", "orange", "iam", "wana",
]

# Router default password patterns
ROUTER_DEFAULTS = {
    "TP-Link": ["{}admin", "{}1234", "tplink{}", "tp-link{}"],
    "D-Link": ["dlink{}", "d-link{}", "{}admin"],
    "ZTE": ["zte{}", "zte521{}", "{}admin"],
    "Huawei": ["huawei{}", "{}admin", "awei567{}"],
    "Netgear": ["netgear{}", "{}password"],
    "ASUS": ["asus{}", "{}admin"],
    "Orange": ["orange{}", "{}orange", "livebox{}", "{}livebox"],
    "inwi": ["inwi{}", "{}inwi", "fibre{}"],
    "Maroc Telecom": ["iam{}", "{}iam", "adsl{}"],
}


class WordlistGenerator:
    """Generate targeted wordlists"""

    def __init__(self):
        self.wordlist = set()

    def generate_for_network(self, essid, bssid="", brand="", max_words=50000):
        """Generate wordlist targeted at specific network"""
        self.wordlist = set()

        # Extract useful info from ESSID
        words_from_essid = self._extract_words(essid)
        numbers_from_essid = self._extract_numbers(essid)

        # Add base words
        for word in words_from_essid:
            self._add_word_variations(word)

        # Add number patterns
        for num in numbers_from_essid:
            self._add_number_patterns(num)

        # Add brand-specific
        if brand and brand in ROUTER_DEFAULTS:
            for pattern in ROUTER_DEFAULTS[brand]:
                for word in words_from_essid:
                    self._try_add(pattern.format(word))

        # Add ESSID-based passwords
        essid_clean = essid.replace(" ", "").replace("-", "").replace("_", "")
        self._add_word_variations(essid_clean)

        # Add common words
        for word in COMMON_WORDS:
            self._try_add(word)

        # Add Arabic/Moroccan words
        for word in ARABIC_WORDS:
            self._add_word_variations(word)

        # Add date patterns
        for year in range(2000, 2028):
            for month in range(1, 13):
                for day in range(1, 32):
                    self._try_add(f"{day:02d}{month:02d}{year}")
                    self._try_add(f"{year}{month:02d}{day:02d}")
                    if len(self.wordlist) > max_words:
                        break

        # Add phone-like patterns
        for prefix in ["06", "07", "05"]:
            for i in range(10000000):
                self._try_add(f"{prefix}{i:07d}")
                if len(self.wordlist) > max_words:
                    break

        # Filter: 8-63 chars (WPA requirement)
        filtered = [w for w in self.wordlist if 8 <= len(w) <= 63]

        return sorted(filtered)[:max_words]

    def generate_from_essid(self, essid):
        """Quick wordlist from ESSID only"""
        self.wordlist = set()
        words = self._extract_words(essid)

        for word in words:
            self._add_word_variations(word)

        essid_clean = essid.replace(" ", "").replace("-", "").replace("_", "")
        self._add_word_variations(essid_clean)

        return [w for w in self.wordlist if 8 <= len(w) <= 63]

    def _extract_words(self, text):
        """Extract words from text"""
        # Split on common separators
        words = re.split(r'[\s_\-\.]+', text)
        # Filter short words
        return [w.lower() for w in words if len(w) >= 2]

    def _extract_numbers(self, text):
        """Extract numbers from text"""
        return re.findall(r'\d+', text)

    def _add_word_variations(self, word):
        """Add all variations of a word"""
        w = word.lower()
        self._try_add(w)
        self._try_add(w.capitalize())
        self._try_add(w.upper())
        self._try_add(w + "123")
        self._try_add(w + "1234")
        self._try_add(w + "12345")
        self._try_add(w + "123456")
        self._try_add(w + "@123")
        self._try_add(w + "@1234")
        self._try_add(w + "2024")
        self._try_add(w + "2025")
        self._try_add(w + "2026")
        self._try_add(w + "!")
        self._try_add(w + "@")
        self._try_add(w + "#")
        self._try_add("123" + w)
        self._try_add("1234" + w)
        self._try_add(w + w)
        self._try_add(w.capitalize() + "123")
        self._try_add(w.capitalize() + "2024")
        self._try_add(w.capitalize() + "2025")
        self._try_add(w.capitalize() + "2026")
        self._try_add(w + "00")
        self._try_add(w + "01")
        self._try_add(w + "1")
        self._try_add(w + "007")

    def _add_number_patterns(self, num):
        """Add number-based patterns"""
        self._try_add(num)
        self._try_add(num * 2)
        self._try_add(num + "123")
        self._try_add(num + "1234")
        self._try_add(num + "0000")
        for year in range(2020, 2027):
            self._try_add(num + str(year))

    def _try_add(self, word):
        """Add word if valid"""
        if word and 8 <= len(word) <= 63:
            self.wordlist.add(word)

    def save_to_file(self, filepath, max_words=50000):
        """Save wordlist to file"""
        words = sorted(self.wordlist)[:max_words]
        with open(filepath, "w") as f:
            for w in words:
                f.write(w + "\n")
        return len(words)
