import math
from enum import Enum

class StrengthLevel(Enum):  # checks the lvl for pw strength 
    VERY_WEAK = 1
    WEAK = 2
    MODERATE = 3
    STRONG = 4
    VERY_STRONG = 5

def check_length(password):  # checks the length requirement
    length = len(password)
    if length < 8:
        return 0, "Too short, minimum 8 characters"  # FIXED: was using ; instead of ,
    elif length < 12:
        return 1, "Minimum length met (8-11 characters)"  # FIXED: was using ; instead of ,
    elif length < 16:
        return 2, "Good length met 12-15 characters "  # FIXED: was using ; instead of ,
    else:
        return 3, "Excellent length!"  # FIXED: was using ; instead of ,

def check_uppercase(password):  # checks for uppercase letters
    for char in password:
        if char.isupper():
            return 1, "Contains uppercase letters"
    return 0, "Missing uppercase letters"

def check_lowercase(password):  # checks for lowercase letters
    for char in password:
        if char.islower():
            return 1, "Contains lowercase letters"
    return 0, "Missing lowercase letters"

def check_digits(password):  # checks for numeric digits
    for char in password:
        if char.isdigit():
            return 1, "Contains numbers"
    return 0, "Missing numbers"

def check_symbols(password):  # checks for special symbols
    symbols = "!@#$%^&*()-_+=[]{}`~|,.//\<>?';:"
    for char in password:
        if char in symbols:
            return 2, "Contains special symbols"
    return 0, "Missing special symbols"

def check_common_patterns(password):
    # checks against common pw patterns
    common_patterns = ['12345', 'password', 'abc123', 'monkey',
                       'admin', '123456789', 'football', 'basketball', 'soccer', 'games']

    lower_pwd = password.lower()
    for pattern in common_patterns:
        if pattern in lower_pwd:
            return -2, f"Contains common pattern: '{pattern}'"

    # check for repeated characters
    for i in range(len(password) - 2):
        if password[i] == password[i + 1] == password[i + 2]:
            return -1, "Contains repeated characters"

    # checks for sequential characters
    if has_sequential_chars(password):
        return -1, "Contains sequential characters (like abc, 123, etc.)"
    
    return 0, "No common weak patterns detected"  # FIXED: was missing return statement

def has_sequential_chars(password):  # func of checking sequential characters
    lower_pwd = password.lower()

    # check for abc, bcd, etc
    for i in range(len(lower_pwd) - 2):
        char1, char2, char3 = lower_pwd[i], lower_pwd[i + 1], lower_pwd[i + 2]

        # check alphabetical sequences
        if (char1.isalpha() and char2.isalpha() and char3.isalpha()):  # FIXED: was char3,isalpha()
            if ord(char2) == ord(char1) + 1 and ord(char3) == ord(char2) + 1:  # FIXED: was int() instead of ord()
                return True

        # check numerical sequences
        if (char1.isdigit() and char2.isdigit() and char3.isdigit()):  # FIXED: was missing this check
            if int(char2) == int(char1) + 1 and int(char3) == int(char2) + 1:
                return True

    # check for keyboard sequences 
    keyboard_rows = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm']
    for row in keyboard_rows:
        for i in range(len(row) - 2):
            if row[i:i + 3] in lower_pwd:
                return True

    return False

def calc_entropy(password):  # calc password entropy
    has_lower = has_upper = has_digit = has_symbol = False  # FIXED: variable names didn't match
    symbols = "!@#$%^&*()-_=+`~[]{}\|;':"

    for char in password:
        if char.islower():
            has_lower = True
        elif char.isupper():
            has_upper = True
        elif char.isdigit():
            has_digit = True  # FIXED: was has_digits = True
        elif char in symbols:
            has_symbol = True  # FIXED: was has_symbols = True

    charset_size = 0
    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_symbol:
        charset_size += 32

    if charset_size == 0:
        return 0

    entropy = len(password) * math.log2(charset_size)
    return entropy

def get_strength_rating(score, entropy):  # determines the score
    if score <= 2 or entropy < 28:
        return StrengthLevel.VERY_WEAK, "Very weak!!, extremly vulnerable to attacks"
    elif score <= 4 or entropy < 36:
        return StrengthLevel.WEAK, "Weak!!, prone to get cracked with basic tools"
    elif score <= 6 or entropy < 50:
        return StrengthLevel.MODERATE, "Moderate, acceptable but should be stronger!"
    elif score <= 8 or entropy < 60:
        return StrengthLevel.STRONG, "Strong!, good protections against majority of attacks"
    else:
        return StrengthLevel.VERY_STRONG, "Very strong!!"


def check_password_strength(password):  # main func to check the strength
    results = {
        'checks': [],
        'score': 0,
        'max_score': 10,
        'entropy': 0,
        'strength_level': None,
        'rating_message': ""
    }

    # runs all checks
    checks = [
        check_length(password),
        check_uppercase(password),
        check_lowercase(password),
        check_digits(password),
        check_symbols(password),
        check_common_patterns(password)
    ]

    for points, message in checks:
        results['checks'].append({'points': points, 'message': message})
        results['score'] += points

    # Calculate entropy
    results['entropy'] = calc_entropy(password)

    # Get strength rating
    level, message = get_strength_rating(results['score'], results['entropy'])
    results['strength_level'] = level
    results['rating_message'] = message

    return results


def print_report(results):
    """Print formatted strength report"""
    print("=" * 50)
    print("PASSWORD STRENGTH REPORT (No Regex Version)")
    print("=" * 50)

    print("\nDETAILED CHECKS:")
    print("-" * 50)
    for check in results['checks']:
        symbol = "[OK]" if check['points'] > 0 else "[X]" if check['points'] < 0 else "[!]"
        print(f"{symbol} {check['message']} ({check['points']:+.0f} pts)")

    print("\nSTATISTICS:")
    print("-" * 50)
    print(f"Security Score: {results['score']}/{results['max_score']}")
    print(f"Entropy: {results['entropy']:.1f} bits")

    # Progress bar for score
    bar_length = 20
    filled = int((results['score'] / results['max_score']) * bar_length)
    bar = "#" * filled + "-" * (bar_length - filled)
    print(f"Score Bar: [{bar}]")

    print("\nFINAL RATING:")
    print("-" * 50)
    print(results['rating_message'])
    print("=" * 50)


def generate_suggestions(results, password):
    """Generate improvement suggestions"""
    suggestions = []
    symbols = "!@#$%^&*(),.?\":{}|<>[]\\/-_=+`~;"

    if len(password) < 12:
        suggestions.append("- Increase length to at least 12 characters")

    # Check character types without regex
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in symbols for c in password)

    if not has_upper:
        suggestions.append("- Add uppercase letters (A-Z)")
    if not has_lower:
        suggestions.append("- Add lowercase letters (a-z)")
    if not has_digit:
        suggestions.append("- Add numbers (0-9)")
    if not has_symbol:
        suggestions.append("- Add special symbols (!@#$%^&* etc.)")

    # Check for patterns
    lower_pwd = password.lower()
    if any(pattern in lower_pwd for pattern in ['123', 'password', 'qwerty', 'abc']):
        suggestions.append("- Avoid common words and sequences")

    # Check for repeated characters
    for i in range(len(password) - 2):
        if password[i] == password[i + 1] == password[i + 2]:
            suggestions.append("- Avoid repeating characters (e.g., 'aaa')")
            break

    if suggestions:
        print("\nSUGGESTIONS TO IMPROVE:")
        print("-" * 50)
        for suggestion in suggestions:
            print(suggestion)
        print("=" * 50)


def main():
    print("Password Strength Checker (No Regex Version)")
    print("=" * 50)

    # Example passwords for demonstration
    test_passwords = [
        "12345",  # Very weak
        "password123",  # Weak
        "Hello1",  # Weak (too short)
        "MyP@ssw0rd2024!",  # Strong
        "Tr0ub4dor&3",  # Moderate
        "correcthorsebatterystaple"  # Strong 
    ]

    print("\nDemo with example passwords:\n")
    for pwd in test_passwords:
        print(f"\nTesting: {'*' * len(pwd)}")
        results = check_password_strength(pwd)
        print_report(results)
        generate_suggestions(results, pwd)
        print("\n" + "-" * 50 + "\n")

    # Interactive mode
    print("\nINTERACTIVE MODE")
    print("Type 'quit' to exit\n")

    while True:
        try:
            user_input = input("Enter password to check: ")
            if user_input.lower() == 'quit':
                print("Goodbye!")
                break

            if not user_input:
                print("Please enter a password.")
                continue

            results = check_password_strength(user_input)
            print_report(results)
            generate_suggestions(results, user_input)

        except KeyboardInterrupt:
            print("\nGoodbye!")
            break


if __name__ == "__main__":
    main()