#!/usr/bin/env python3
"""
Shifting XOR Decryptor / Encryptor Tool
========================================
A tool to encrypt and decrypt data using Shifting XOR algorithm.
Supports both fixed and variable (sequential) shift modes.

Author: Fatih Emre
Date: 2025
"""

import sys

# ====================== Banner ======================
BANNER = r"""

   _____ __    _ ______  _
  / ___// /_  (_) __/ /_(_)___  ____ _
  \__ \/ __ \/ / /_/ __/ / __ \/ __ `/
 ___/ / / / / / __/ /_/ / / / / /_/ /
/____/_/ /_/_/_/  \__/_/_/ /_/\__, /
                             /____/

S H I F T I N G    X O R    T O O L


"""

SEPARATOR = "=" * 50

# ====================== Core Functions ======================
def rol8(v, n):
    """Rotate bits of v LEFT by n positions (8-bit)."""
    n &= 7
    if n == 0:
        return v
    return ((v << n) | (v >> (8 - n))) & 0xFF

def ror8(v, n):
    """Rotate bits of v RIGHT by n positions (8-bit)."""
    n &= 7
    if n == 0:
        return v
    return ((v >> n) | (v << (8 - n))) & 0xFF

def hex_to_bytes(hex_str):
    """Convert hex string (space or comma separated) to bytes."""
    hex_str = hex_str.replace(",", "").replace("0x", "").replace(" ", "")
    try:
        return bytes.fromhex(hex_str)
    except ValueError:
        print("[!] Invalid hex string!")
        sys.exit(1)

def bytes_to_hex(data):
    """Convert bytes to formatted hex string."""
    return ", ".join(f"0x{b:02X}" for b in data)

def get_shift_value(i, shift_mode, shift_param):
    """
    Calculate shift value for byte at position i.

    shift_mode:
        "fixed"    -> always return shift_param
        "modulo"   -> (i % shift_param) + 1
        "cycle"    -> (i % len(shift_param)) and get from list
        "formula"  -> eval the formula with i
    """
    if shift_mode == "fixed":
        return shift_param

    elif shift_mode == "modulo":
        # (i % N) + 1 pattern
        return (i % shift_param) + 1

    elif shift_mode == "cycle":
        # Custom cycle from list like [1,2,3,4,5]
        return shift_param[i % len(shift_param)]

    elif shift_mode == "formula":
        # Custom formula, e.g., "(i % 5) + 1"
        try:
            result = eval(shift_param, {"i": i})
            return result & 7  # Keep within 0-7 range
        except:
            return 0

    return 1

# ====================== Key Evolution ======================
def evolve_key_simple(key):
    """Simple: key + 1"""
    return (key + 1) & 0xFF

def evolve_key_rotate_xor(key, plaintext):
    """Advanced: rol8(key, 3) ^ plaintext"""
    return (rol8(key, 3) ^ plaintext) & 0xFF

def evolve_key_rotate_xor_5(key, index):
    """Advanced: rol8(key, 5) ^ (index * 7)"""
    return (rol8(key, 5) ^ ((index * 7) & 0xFF)) & 0xFF

def evolve_key_custom(key, plaintext, index, formula):
    """Custom key evolution formula"""
    try:
        result = eval(formula, {
            "k": key, "p": plaintext, "i": index,
            "rol8": rol8, "ror8": ror8
        })
        return result & 0xFF
    except:
        return key

def shifting_xor_decrypt(ciphertext, shift_mode, shift_param, direction, key, key_mode, key_param=None):
    """
    Decrypt data encrypted with Shifting XOR.

    Encryption was: ciphertext = rol(plaintext, shift) ^ key
    Decryption is:  plaintext = ror(ciphertext ^ key, shift)
    """
    plaintext = bytearray()
    current_key = key

    for i, c in enumerate(ciphertext):
        shift = get_shift_value(i, shift_mode, shift_param)
        xored = c ^ current_key

        if direction == "left":
            p = ror8(xored, shift)
        else:
            p = rol8(xored, shift)

        plaintext.append(p)

        # Key evolution
        if key_mode == "simple":
            current_key = evolve_key_simple(current_key)
        elif key_mode == "rotate_xor":
            current_key = evolve_key_rotate_xor(current_key, p)
        elif key_mode == "rotate_xor_5":
            current_key = evolve_key_rotate_xor_5(current_key, i)
        elif key_mode == "custom":
            current_key = evolve_key_custom(current_key, p, i, key_param)

    return bytes(plaintext)

def shifting_xor_encrypt(plaintext, shift_mode, shift_param, direction, key, key_mode, key_param=None):
    """
    Encrypt data with Shifting XOR.

    Encryption: ciphertext = rol(plaintext, shift) ^ key
    """
    ciphertext = bytearray()
    current_key = key

    for i, p in enumerate(plaintext):
        shift = get_shift_value(i, shift_mode, shift_param)

        if direction == "left":
            rotated = rol8(p, shift)
        else:
            rotated = ror8(p, shift)

        c = rotated ^ current_key
        ciphertext.append(c)

        # Key evolution
        if key_mode == "simple":
            current_key = evolve_key_simple(current_key)
        elif key_mode == "rotate_xor":
            current_key = evolve_key_rotate_xor(current_key, p)
        elif key_mode == "rotate_xor_5":
            current_key = evolve_key_rotate_xor_5(current_key, i)
        elif key_mode == "custom":
            current_key = evolve_key_custom(current_key, p, i, key_param)

    return bytes(ciphertext)

# ====================== Input Helpers ======================
def get_hex_input(prompt):
    """Get hex data from user."""
    print(f"\n{prompt}")
    hex_str = input("  Hex Data > ").strip()
    return hex_to_bytes(hex_str)

def get_shift_mode():
    """Get shift mode from user."""
    while True:
        print("\n  Select shift mode:")
        print("    [1] Fixed    - Same shift for all bytes")
        print("    [2] Cycling  - Shift cycles (e.g. 1,2,3,1,2)")
        print("    [3] Custom   - Your own pattern")
        print("    [4] Formula  - Write formula with 'i'")
        choice = input("  > ").strip()

        if choice == "1":
            return "fixed"
        elif choice == "2":
            return "modulo"
        elif choice == "3":
            return "cycle"
        elif choice == "4":
            return "formula"
        print("  [!] Please enter 1-4.")

def get_shift_param(mode):
    """Get shift parameter based on mode."""
    if mode == "fixed":
        while True:
            try:
                shift = int(input("\n  Enter shift value (1-7): ").strip())
                if 1 <= shift <= 7:
                    return shift
                print("  [!] Shift must be between 1 and 7.")
            except ValueError:
                print("  [!] Please enter a valid number.")

    elif mode == "modulo":
        while True:
            try:
                n = int(input("\n  How many steps to cycle? (e.g., 5 for 1,2,3,4,5,1,2,...): ").strip())
                if n >= 1:
                    return n
                print("  [!] Must be at least 1.")
            except ValueError:
                print("  [!] Please enter a valid number.")

    elif mode == "cycle":
        while True:
            try:
                pattern = input("\n  Enter your shift pattern (comma separated, e.g. 1,3,5): ").strip()
                nums = [int(x.strip()) for x in pattern.split(",")]
                if all(1 <= n <= 7 for n in nums) and len(nums) > 0:
                    return nums
                print("  [!] All values must be between 1 and 7.")
            except ValueError:
                print("  [!] Please enter valid numbers.")

    elif mode == "formula":
        formula = input("\n  Enter formula using 'i' (e.g., (i % 5) + 1): ").strip()
        return formula

    return 1

def get_direction():
    """Get rotation direction from user."""
    while True:
        d = input("\n  Enter direction (left/right): ").strip().lower()
        if d in ("left", "l"):
            return "left"
        elif d in ("right", "r"):
            return "right"
        print("  [!] Please enter 'left' or 'right'.")

def get_key():
    """Get key from user."""
    while True:
        try:
            key_str = input("\n  Enter key (hex, e.g. 0x3d or 3D): ").strip()
            key_str = key_str.replace("0x", "")
            return int(key_str, 16) & 0xFF
        except ValueError:
            print("  [!] Please enter a valid hex value.")

def get_key_mode():
    """Get key evolution mode from user."""
    while True:
        print("\n  Key evolution:")
        print("    [1] Simple     - key + 1 each step")
        print("    [2] RotateXOR  - rol8(key, 3) ^ plaintext")
        print("    [3] RotateXOR5 - rol8(key, 5) ^ (i * 7)")
        print("    [4] Custom     - Write your own formula")
        choice = input("  > ").strip()

        if choice == "1":
            return "simple"
        elif choice == "2":
            return "rotate_xor"
        elif choice == "3":
            return "rotate_xor_5"
        elif choice == "4":
            return "custom"
        print("  [!] Please enter 1-4.")

def get_key_param(mode):
    """Get key parameter if custom mode."""
    if mode == "custom":
        print("\n  Variables: k (key), p (plaintext), i (index)")
        print("  Functions: rol8(v, n), ror8(v, n)")
        print("  Example: (rol8(k, 3) ^ p)")
        formula = input("  Formula > ").strip()
        return formula
    return None

def get_mode():
    """Get operation mode from user."""
    while True:
        print("\n  Select mode:")
        print("    [1] Decrypt (ciphertext -> plaintext)")
        print("    [2] Encrypt (plaintext -> ciphertext)")
        choice = input("  > ").strip()
        if choice == "1":
            return "decrypt"
        elif choice == "2":
            return "encrypt"
        print("  [!] Please enter 1 or 2.")

def print_shift_pattern(shift_mode, shift_param, count):
    """Print the shift pattern that will be used."""
    print(f"\n  Shift pattern (first {count} bytes):")
    pattern = []
    for i in range(count):
        pattern.append(str(get_shift_value(i, shift_mode, shift_param)))
    print(f"  [{', '.join(pattern)}, ...]")

# ====================== Main ======================
def main():
    print(BANNER)
    print(SEPARATOR)

    mode = get_mode()

    print(SEPARATOR)
    if mode == "decrypt":
        print("  [DECRYPT MODE]")
        data = get_hex_input("Enter the ENCRYPTED data (hex):")
    else:
        print("  [ENCRYPT MODE]")
        data = get_hex_input("Enter the PLAINTEXT data (hex):")

    shift_mode = get_shift_mode()
    shift_param = get_shift_param(shift_mode)
    direction = get_direction()
    key = get_key()
    key_mode = get_key_mode()
    key_param = get_key_param(key_mode)

    # Process
    print(SEPARATOR)
    print("  Processing...")
    print(SEPARATOR)

    print(f"\n  Mode       : {mode.upper()}")
    print(f"  Shift Mode : {shift_mode.upper()}")
    if shift_mode == "fixed":
        print(f"  Shift      : {shift_param} bits (same for all)")
    elif shift_mode == "modulo":
        print(f"  Shift      : Cycles through 1 to {shift_param}")
    elif shift_mode == "cycle":
        print(f"  Shift      : Pattern {shift_param} repeating")
    elif shift_mode == "formula":
        print(f"  Shift      : {shift_param}")
    print(f"  Direction  : {direction.upper()}")
    print(f"  Key        : 0x{key:02X}")
    print(f"  Key Evol   : {key_mode}")
    print(f"  Input ({len(data):>2} bytes) : {bytes_to_hex(data)}")

    # Show shift pattern
    print_shift_pattern(shift_mode, shift_param, min(10, len(data)))

    if mode == "decrypt":
        result = shifting_xor_decrypt(data, shift_mode, shift_param, direction, key, key_mode, key_param)
    else:
        result = shifting_xor_encrypt(data, shift_mode, shift_param, direction, key, key_mode, key_param)

    print(f"\n  Result ({len(result):>2} bytes) : {bytes_to_hex(result)}")

    # Try to show as ASCII if possible
    try:
        ascii_repr = result.decode("ascii", errors="replace")
        printable = all(32 <= ord(c) < 127 or c in "\n\r\t" for c in ascii_repr)
        if printable or any(32 <= ord(c) < 127 for c in ascii_repr):
            print(f"  ASCII      : {ascii_repr}")
    except:
        pass

    print(SEPARATOR)

    # Ask if user wants to continue
    again = input("\n  Process another? (y/n): ").strip().lower()
    if again in ("y", "yes"):
        main()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  [!] Interrupted by user.")
        sys.exit(0)
