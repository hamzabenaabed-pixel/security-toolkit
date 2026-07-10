#!/usr/bin/env python3
"""
Script to generate a list of 100,000 potential passwords for Morocco.
Includes numbers (8-12 digits), common Moroccan names, cities, and combinations.
"""

import random
import string

# Common Moroccan names
moroccan_names = [
    "Mohamed", "Fatima", "Youssef", "Khadija", "Ahmed", "Karim", "Omar", "Amina", 
    "Sara", "Iman", "Hassan", "Aicha", "Noura", "Laila", "Mehdi", "Soufiane", 
    "Driss", "Malik", "Samira", "Leila", "Hicham", "Mustapha", "Yasmine", "Zineb",
    "Nabil", "Said", "Rachid", "Kamal", "Abdellah", "Nadia", "Hanane", "Asma",
    "Jalal", "Tariq", "Wafae", "Ibtissam", "Sanae", "Meryem", "Hajjar", "Brahim",
    "Adil", "Fouad", "Nabil", "Othman", "Zakaria", "Siham", "Rania", "Dounia"
]

# Common Moroccan cities
moroccan_cities = [
    "Casablanca", "Rabat", "Marrakech", "Fes", "Tanger", "Agadir", "Meknes", 
    "Oujda", "Kenitra", "Tetouan", "Safi", "Sale", "Essaouira", "Chefchaouen", 
    "Merzouga", "ErgChebbi", "AitBenHaddou", "Volubilis", "AlHoceima", "Nador", 
    "Taza", "Berkane", "Taourirt", "Driouch", "Jerada", "Figuig", "Boujdour", 
    "TanTan", "Guelmim", "Assa", "Zagora", "Laayoune", "Dakhla", "SidiIfni",
    "BenGuerir", "Khouribga", "Settat", "Khemisset", "Skhirat", "Temara", "TitMellil",
    "Benslimane", "Berrechid"
]

# Common Moroccan words and terms
moroccan_terms = [
    "Maroc", "Morocco", "MA", "Maghreb", "AlMaghrib", "KingMohammedVI", 
    "Allah", "Islam", "Quran", "Ramadan", "Eid", "Mosque", "Football", 
    "RajaCasablanca", "WydadCasablanca", "FUSRabat", "KawkabMarrakech", 
    "HassanII", "MohammedV", "AlQarawiyyin", "Atlas", "Sahara", "Mediterranean",
    "Arabic", "Berber", "Amazigh", "Tamazight", "Couscous", "Tajine", "MintTea",
    "Pastilla", "Harira", "Bastilla", "Tagine", "Moroccan", "DarElMakhzen", 
    "BabElMansour", "Chefchaouen", "Merzouga", "WesternSahara", "MarocTelecom",
    "Inwi", "IAM", "OrangeMaroc"
]

# Common password patterns
common_patterns = [
    "123456", "12345678", "123456789", "1234567890", "111111", "000000",
    "123123", "123321", "654321", "112233", "121212", "12341234", "43214321",
    "12345670", "12345679", "98765432", "87654321", "11112222", "22221111"
]

# Years
years = [str(year) for year in range(1990, 2031)]

# Moroccan phone prefixes
phone_prefixes = ["212", "2120", "2121", "2122", "2123", "2124", "2125", "2126", "2127", "2128", "2129"]


def generate_numeric_passwords(count=30000):
    """Generate numeric passwords with lengths between 8 and 12 digits."""
    passwords = []
    while len(passwords) < count:
        length = random.randint(8, 12)
        password = ''.join(random.choices(string.digits, k=length))
        passwords.append(password)
    return passwords


def generate_name_based_passwords(count=20000):
    """Generate passwords based on Moroccan names."""
    passwords = []
    while len(passwords) < count:
        name = random.choice(moroccan_names)
        suffix = random.choice([
            str(random.randint(100, 999)),
            str(random.randint(1000, 9999)),
            random.choice(years),
            "", "123", "2024", "2025"
        ])
        password = f"{name}{suffix}".lower()
        passwords.append(password)
    return passwords


def generate_city_based_passwords(count=15000):
    """Generate passwords based on Moroccan cities."""
    passwords = []
    while len(passwords) < count:
        city = random.choice(moroccan_cities)
        suffix = random.choice([
            str(random.randint(100, 999)),
            str(random.randint(1000, 9999)),
            random.choice(years),
            "", "123", "2024", "2025"
        ])
        password = f"{city}{suffix}".lower()
        passwords.append(password)
    return passwords


def generate_term_based_passwords(count=10000):
    """Generate passwords based on Moroccan terms."""
    passwords = []
    while len(passwords) < count:
        term = random.choice(moroccan_terms)
        suffix = random.choice([
            str(random.randint(100, 999)),
            str(random.randint(1000, 9999)),
            random.choice(years),
            "", "123", "2024", "2025"
        ])
        password = f"{term}{suffix}".lower()
        passwords.append(password)
    return passwords


def generate_phone_based_passwords(count=5000):
    """Generate passwords based on Moroccan phone prefixes."""
    passwords = []
    while len(passwords) < count:
        prefix = random.choice(phone_prefixes)
        suffix_length = random.randint(5, 9)  # Total length between 8 and 12
        suffix = ''.join(random.choices(string.digits, k=suffix_length))
        password = f"{prefix}{suffix}"
        passwords.append(password)
    return passwords


def generate_common_pattern_passwords(count=10000):
    """Generate passwords based on common patterns."""
    passwords = []
    while len(passwords) < count:
        pattern = random.choice(common_patterns)
        suffix = random.choice([
            str(random.randint(100, 999)),
            str(random.randint(1000, 9999)),
            random.choice(years),
            ""
        ])
        password = f"{pattern}{suffix}"
        passwords.append(password)
    return passwords


def generate_combined_passwords(count=10000):
    """Generate combined passwords from multiple categories."""
    passwords = []
    categories = [
        moroccan_names, moroccan_cities, moroccan_terms, common_patterns, phone_prefixes
    ]
    while len(passwords) < count:
        first_part = random.choice(random.choice(categories))
        second_part = random.choice(random.choice(categories))
        password = f"{first_part}{second_part}".lower()
        if 8 <= len(password) <= 12:
            passwords.append(password)
    return passwords


def main():
    random.seed(42)  # For reproducibility
    
    passwords = []
    
    # Generate passwords from each category
    passwords.extend(generate_numeric_passwords(30000))
    passwords.extend(generate_name_based_passwords(20000))
    passwords.extend(generate_city_based_passwords(15000))
    passwords.extend(generate_term_based_passwords(10000))
    passwords.extend(generate_phone_based_passwords(5000))
    passwords.extend(generate_common_pattern_passwords(10000))
    passwords.extend(generate_combined_passwords(10000))
    
    # Remove duplicates and ensure we have exactly 100,000 passwords
    passwords = list(set(passwords))[:100000]
    
    # Ensure all passwords are between 8 and 12 characters
    passwords = [p for p in passwords if 8 <= len(p) <= 12]
    
    # If we have less than 100,000, generate more numeric passwords to fill the gap
    while len(passwords) < 100000:
        passwords.extend(generate_numeric_passwords(100000 - len(passwords)))
        passwords = list(set(passwords))[:100000]
    
    # Write to file
    with open("morocco_passwords.txt", "w") as f:
        for password in passwords:
            f.write(password + "\n")
    
    print(f"Generated {len(passwords)} passwords in morocco_passwords.txt")


if __name__ == "__main__":
    main()