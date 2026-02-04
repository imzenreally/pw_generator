#!/usr/bin/env python3
"""
Secure Password Generator

Generates random passwords that meet the following requirements:
- At least 20 characters long
- Contains all 4 character classes:
  - Uppercase Letters (A-Z)
  - Lowercase Letters (a-z)
  - Numbers (0-9)
  - Punctuation (!@$&()#^*)
- First character cannot be one of: !()[]{}*.#$
"""

import secrets
import string


# Character classes
UPPERCASE = string.ascii_uppercase  # A-Z
LOWERCASE = string.ascii_lowercase  # a-z
DIGITS = string.digits  # 0-9
PUNCTUATION = "!@$&()#^*"  # Limited special characters

ALL_CHAR_CLASSES = [
    ("Uppercase", UPPERCASE),
    ("Lowercase", LOWERCASE),
    ("Digits", DIGITS),
    ("Punctuation", PUNCTUATION),
]

MIN_LENGTH = 20
MIN_CLASSES = 4
FORBIDDEN_FIRST_CHARS = "!()[]{}*.#$"  # Characters that cannot be first


def check_password_classes(password: str) -> dict[str, bool]:
    """Check which character classes are present in the password."""
    return {
        "Uppercase": any(c in UPPERCASE for c in password),
        "Lowercase": any(c in LOWERCASE for c in password),
        "Digits": any(c in DIGITS for c in password),
        "Punctuation": any(c in PUNCTUATION for c in password),
    }


def count_classes(password: str) -> int:
    """Count how many character classes are present in the password."""
    classes = check_password_classes(password)
    return sum(classes.values())


def generate_password(length: int = MIN_LENGTH) -> str:
    """
    Generate a secure random password.
    
    Args:
        length: Desired password length (minimum 20)
    
    Returns:
        A password meeting all requirements
    """
    if length < MIN_LENGTH:
        length = MIN_LENGTH
    
    # Build the combined character pool
    all_chars = UPPERCASE + LOWERCASE + DIGITS + PUNCTUATION
    
    while True:
        # Ensure we have at least one character from 4 different classes
        # Pick 4 random classes to guarantee inclusion
        selected_classes = secrets.SystemRandom().sample(ALL_CHAR_CLASSES, MIN_CLASSES)
        
        # Start with one character from each selected class
        password_chars = [secrets.choice(chars) for _, chars in selected_classes]
        
        # Fill the rest with random characters from the full pool
        remaining_length = length - len(password_chars)
        password_chars.extend(secrets.choice(all_chars) for _ in range(remaining_length))
        
        # Shuffle to avoid predictable positions
        secrets.SystemRandom().shuffle(password_chars)
        password = "".join(password_chars)
        
        # Verify the password meets requirements
        if (count_classes(password) >= MIN_CLASSES and 
            len(password) >= MIN_LENGTH and
            password[0] not in FORBIDDEN_FIRST_CHARS):
            return password


def main():
    """Generate and display a password with its characteristics."""
    password = generate_password()
    classes = check_password_classes(password)
    
    print("=" * 50)
    print("Generated Password:")
    print("=" * 50)
    print(f"\n  {password}\n")
    print("=" * 50)
    print(f"Length: {len(password)} characters")
    print(f"Character classes present ({sum(classes.values())}/4):")
    for class_name, present in classes.items():
        status = "✓" if present else "✗"
        print(f"  {status} {class_name}")
    print("=" * 50)


if __name__ == "__main__":
    main()
