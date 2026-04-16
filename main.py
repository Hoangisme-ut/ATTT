"""
main.py
=======
Unified entry point for the Digital Signature application.

Usage:
    python main.py                         Show quick-start guide
    python main.py genkey alice            Generate RSA keys for alice
    python main.py sign alice --message "Hello" --out signed.json
    python main.py verify --package signed.json --pub alice_public.pem
    python main.py gui                     Launch Tkinter GUI
    python main.py selftest                Run built-in tests

Exit codes:
    0 = success
    1 = handled error (CryptoAppError)
    2 = unexpected error

Note: This file never calls sys.exit() directly to remain test-friendly.
      The if __name__ block converts the return value to sys.exit() only
      when invoked as a script.
"""

import sys

from app.cli.cli_app import main

if __name__ == "__main__":
    sys.exit(main())
