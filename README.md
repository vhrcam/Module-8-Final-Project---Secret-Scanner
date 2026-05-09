## Overview
This project is a Python-based CLI tool that scans files and directories for common hardcoded secrets using regex pattern matching. The tool helps identify sensitive information such as API keys, passwords, tokens, and private keys.

## Features
- Scans individual files or entire directories
- Detects common hardcoded secrets
- Uses regex pattern matching
- Outputs findings with filename, line number, and matched string
- Includes logging functionality
- Command-line interface using argparse

## Secret Patterns Included
The application scans for:
1. AWS Access Keys
2. Generic API Keys
3. Passwords
4. JWT Tokens
5. Private Keys

## How It Works
The scanner reads each file line-by-line and compares the contents against predefined regex patterns. If a match is found, the application reports the filename, line number, secret type, and matched string.

## How to Run
Open a terminal in the project directory and run:

```bash python scanner.py sample_secrets.txt
