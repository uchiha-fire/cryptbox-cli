"""
CLI interface and interactive wizard for cryptbox.
Zephyrus Labs (https://zephyrus-labs.tech/)
Lead Developer: Shubham Sharma
"""
import argparse
import getpass
import os
import sys
import time
from typing import List, Optional

from cryptbox import __version__
from cryptbox.core import (
    lock_path,
    unlock_vault,
    inspect_vault,
    AuthenticationError,
)

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner():
    banner = f"""{CYAN}{BOLD}
╔══════════════════════════════════════════════════════════════╗
║               cryptbox-cli  v{__version__}                          ║
║     Zero-Trust Authenticated Vault (AES-256-GCM)             ║
║     Zephyrus Labs (https://zephyrus-labs.tech/)              ║
╚══════════════════════════════════════════════════════════════╝{RESET}"""
    print(banner)


def display_inspect_table(info: dict):
    print(f"\n{BOLD}Vault Cryptographic Inspection:{RESET}")
    print("-" * 65)
    for k, v in info.items():
        label = k.replace("_", " ").title()
        print(f"  {BOLD}{label:<22}:{RESET} {v}")
    print("-" * 65 + "\n")


def run_interactive_wizard(iterations: Optional[int] = None) -> int:
    print_banner()
    print(f"\n{BOLD}Welcome to the cryptbox Security Vault Wizard!{RESET}\n")

    print(f"{BOLD}Select Action:{RESET}")
    print("  [1] 🔒 Lock file or directory into encrypted .box vault")
    print("  [2] 🔓 Unlock an encrypted .box vault")
    print("  [3] 🔍 Inspect vault metadata (No password required)")

    choice = input(f"{BOLD}Choose [1/2/3] (default: 1):{RESET} ").strip() or "1"

    if choice == "3":
        vault_path = input(f"{BOLD}Enter path to .box vault:{RESET} ").strip()
        if not vault_path or not os.path.exists(vault_path):
            print(f"{RED}File not found: '{vault_path}'{RESET}")
            return 1
        info = inspect_vault(vault_path)
        display_inspect_table(info)
        return 0

    if choice == "2":
        vault_path = input(f"{BOLD}Enter path to .box vault to unlock:{RESET} ").strip()
        if not vault_path or not os.path.exists(vault_path):
            print(f"{RED}File not found: '{vault_path}'{RESET}")
            return 1

        default_dest = os.path.splitext(vault_path)[0] + "_restored"
        dest_dir = input(f"{BOLD}Enter destination folder (default: {default_dest}):{RESET} ").strip() or default_dest

        password = getpass.getpass(f"{BOLD}Enter decryption passphrase:{RESET} ")
        if not password:
            print(f"{RED}Passphrase cannot be empty.{RESET}")
            return 1

        try:
            print(f"\n{CYAN}Authenticating and decrypting vault...{RESET}")
            start_t = time.time()
            unlock_vault(vault_path, password, dest_dir, iterations=iterations)
            duration = time.time() - start_t
            print(f"{GREEN}✓ Successfully unlocked in {duration:.2f}s!{RESET}")
            print(f"{GREEN}✓ Contents extracted to: {dest_dir}{RESET}\n")
            return 0
        except AuthenticationError as e:
            print(f"\n{RED}{BOLD}🚨 {e}{RESET}\n")
            return 1
        except Exception as e:
            print(f"{RED}Error: {e}{RESET}")
            return 1

    # Choice 1: Lock
    src_path = input(f"{BOLD}Enter path to file or directory to lock:{RESET} ").strip()
    if not src_path or not os.path.exists(src_path):
        print(f"{RED}Path not found: '{src_path}'{RESET}")
        return 1

    default_out = f"{src_path.rstrip(os.sep)}.box"
    out_path = input(f"{BOLD}Enter destination .box path (default: {default_out}):{RESET} ").strip() or default_out

    while True:
        p1 = getpass.getpass(f"{BOLD}Enter passphrase for vault:{RESET} ")
        if not p1:
            print(f"{RED}Passphrase cannot be empty.{RESET}")
            continue
        p2 = getpass.getpass(f"{BOLD}Confirm passphrase:{RESET} ")
        if p1 != p2:
            print(f"{RED}Passphrases do not match. Please try again.{RESET}")
            continue
        break

    try:
        print(f"\n{CYAN}Deriving 256-bit key (PBKDF2-SHA256) and encrypting AES-256-GCM...{RESET}")
        start_t = time.time()
        lock_path(src_path, p1, out_path, iterations=iterations)
        duration = time.time() - start_t
        vault_size = os.path.getsize(out_path)
        print(f"{GREEN}✓ Vault sealed successfully in {duration:.2f}s!{RESET}")
        print(f"{GREEN}✓ Vault file ({vault_size} bytes): {out_path}{RESET}\n")
        return 0
    except Exception as e:
        print(f"{RED}Error: {e}{RESET}")
        return 1


def main(argv: Optional[List[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    # Fast test internal flag
    fast_test = "--fast-test" in argv
    if fast_test:
        argv = [a for a in argv if a != "--fast-test"]
    iterations = 2000 if fast_test else None

    if not argv or "--interactive" in argv or "-i" in argv:
        return run_interactive_wizard(iterations=iterations)

    parser = argparse.ArgumentParser(
        prog="cryptbox",
        description="Zero-Trust Authenticated File & Folder Vault using AES-256-GCM by Zephyrus Labs",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"cryptbox-cli {__version__} by Zephyrus Labs",
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Sub-commands")

    # Lock parser
    lock_p = subparsers.add_parser("lock", help="Seal a file or folder into an encrypted .box vault")
    lock_p.add_argument("source", help="Source file or directory path")
    lock_p.add_argument("-o", "--output", help="Destination path for .box vault")
    lock_p.add_argument("-p", "--password", help="Passphrase (if omitted, prompts securely)")
    lock_p.add_argument("-f", "--force", action="store_true", help="Overwrite destination if it exists")

    # Unlock parser
    unlock_p = subparsers.add_parser("unlock", help="Authenticate and unpack an encrypted .box vault")
    unlock_p.add_argument("vault", help="Path to .box vault file")
    unlock_p.add_argument("-o", "--dest", help="Destination folder for unpacked contents")
    unlock_p.add_argument("-p", "--password", help="Passphrase (if omitted, prompts securely)")

    # Inspect parser
    inspect_p = subparsers.add_parser("inspect", help="Inspect cryptographic metadata of vault without password")
    inspect_p.add_argument("vault", help="Path to .box vault file")

    args = parser.parse_args(argv)

    if args.subcommand == "inspect":
        info = inspect_vault(args.vault)
        display_inspect_table(info)
        return 0 if info.get("valid") else 1

    if args.subcommand == "lock":
        if not os.path.exists(args.source):
            print(f"{RED}Error: Source path '{args.source}' does not exist.{RESET}", file=sys.stderr)
            return 1
        dest = args.output or f"{args.source.rstrip(os.sep)}.box"
        if os.path.exists(dest) and not args.force:
            print(f"{RED}Error: Output file '{dest}' already exists. Use -f/--force to overwrite.{RESET}", file=sys.stderr)
            return 1
        pwd = args.password
        if not pwd:
            pwd = getpass.getpass("Enter passphrase for vault: ")
        try:
            lock_path(args.source, pwd, dest, iterations=iterations)
            print(f"{GREEN}✓ Vault successfully created: {dest}{RESET}")
            return 0
        except Exception as e:
            print(f"{RED}Error locking vault: {e}{RESET}", file=sys.stderr)
            return 1

    if args.subcommand == "unlock":
        if not os.path.exists(args.vault):
            print(f"{RED}Error: Vault file '{args.vault}' not found.{RESET}", file=sys.stderr)
            return 1
        pwd = args.password
        if not pwd:
            pwd = getpass.getpass("Enter passphrase to unlock vault: ")
        dest = args.dest
        try:
            out_dir = unlock_vault(args.vault, pwd, dest, iterations=iterations)
            print(f"{GREEN}✓ Vault successfully unlocked to: {out_dir}{RESET}")
            return 0
        except AuthenticationError as e:
            print(f"{RED}Authentication Error: {e}{RESET}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"{RED}Error unlocking vault: {e}{RESET}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
