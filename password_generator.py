#!/usr/bin/env python3
"""
Secure Password Generator

Generates random passwords that meet the following requirements:
- At least 20 characters long
- Contains all 4 character classes:
  - Uppercase Letters (A-Z)
  - Lowercase Letters (a-z)
  - Numbers (0-9)
  - Special Chars (!@$&()#^*)
- First character cannot be one of: !()[]{}*.#$
- No character class repeats more than 3 times consecutively
"""

import platform
import secrets
import string
import subprocess


# Character classes
UPPERCASE = string.ascii_uppercase  # A-Z
LOWERCASE = string.ascii_lowercase  # a-z
DIGITS = string.digits  # 0-9
PUNCTUATION = "!@$&()#^*"  # Limited special characters

ALL_CHAR_CLASSES = [
    ("Uppercase", UPPERCASE),
    ("Lowercase", LOWERCASE),
    ("Digits", DIGITS),
    ("Special Chars", PUNCTUATION),
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
        "Special Chars": any(c in PUNCTUATION for c in password),
    }


def count_classes(password: str) -> int:
    """Count how many character classes are present in the password."""
    classes = check_password_classes(password)
    return sum(classes.values())


def get_char_class(char: str) -> str:
    """Return the character class name for a given character."""
    if char in UPPERCASE:
        return "Uppercase"
    elif char in LOWERCASE:
        return "Lowercase"
    elif char in DIGITS:
        return "Digits"
    elif char in PUNCTUATION:
        return "Special Chars"
    return "Unknown"


def has_consecutive_class_run(password: str, max_consecutive: int = 3) -> bool:
    """
    Check if any character class appears more than max_consecutive times in a row.
    
    Args:
        password: The password to check
        max_consecutive: Maximum allowed consecutive characters of the same class
    
    Returns:
        True if there's a run exceeding max_consecutive, False otherwise
    """
    if len(password) <= max_consecutive:
        return False
    
    current_class = get_char_class(password[0])
    consecutive_count = 1
    
    for char in password[1:]:
        char_class = get_char_class(char)
        if char_class == current_class:
            consecutive_count += 1
            if consecutive_count > max_consecutive:
                return True
        else:
            current_class = char_class
            consecutive_count = 1
    
    return False


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
            password[0] not in FORBIDDEN_FIRST_CHARS and
            not has_consecutive_class_run(password)):
            return password


def copy_to_clipboard(text: str) -> bool:
    """
    Copy text to the system clipboard in a platform-agnostic way.
    
    Args:
        text: The text to copy to clipboard
    
    Returns:
        True if successful, False otherwise
    """
    system = platform.system()
    
    try:
        if system == "Darwin":  # macOS
            subprocess.run(["pbcopy"], input=text.encode(), check=True)
        elif system == "Linux":
            # Try xclip first, then xsel
            try:
                subprocess.run(
                    ["xclip", "-selection", "clipboard"],
                    input=text.encode(),
                    check=True
                )
            except FileNotFoundError:
                subprocess.run(
                    ["xsel", "--clipboard", "--input"],
                    input=text.encode(),
                    check=True
                )
        elif system == "Windows":
            subprocess.run(["clip"], input=text.encode(), check=True)
        else:
            return False
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def main():
    """Generate and display a password with its characteristics."""
    password = generate_password()
    classes = check_password_classes(password)
    
    # Copy to clipboard
    clipboard_success = copy_to_clipboard(password)
    
    print("=" * 50)
    print("Password Generated")
    print("=" * 50)
    print("\nPassword Requirements:")
    print(f"  ✓ Length: {len(password)} characters")
    print(f"  ✓ First character is valid")
    print(f"  ✓ No class repeats more than 3x consecutively")
    print("\nCharacter Classes ({}/4):".format(sum(classes.values())))
    for class_name, present in classes.items():
        status = "✓" if present else "✗"
        print(f"  {status} {class_name}")
    print()
    if clipboard_success:
        print("✓ Password copied to clipboard")
    else:
        print("✗ Could not copy to clipboard")
        print("  (Install xclip or xsel on Linux)")
    print("=" * 50)


if __name__ == "__main__":
    main()
