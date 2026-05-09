import os
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Generic API Key": r"(?i)api[_-]?key\s*=\s*['\"][A-Za-z0-9\-_]{16,}['\"]",
    "Password": r"(?i)password\s*=\s*['\"].+['\"]",
    "JWT Token": r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+",
    "Private Key": r"-----BEGIN PRIVATE KEY-----"
}


def scan_file(file_path):
    findings = []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line_number, line in enumerate(file, start=1):
                for secret_name, pattern in SECRET_PATTERNS.items():
                    matches = re.findall(pattern, line)

                    for match in matches:
                        findings.append({
                            "file": file_path,
                            "line": line_number,
                            "type": secret_name,
                            "match": match
                        })

    except Exception as e:
        logging.error(f"Error scanning {file_path}: {e}")

    return findings


def scan_path(path):
    all_findings = []

    if os.path.isfile(path):
        all_findings.extend(scan_file(path))

    elif os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            for file in files:
                file_path = os.path.join(root, file)
                all_findings.extend(scan_file(file_path))

    else:
        print("Invalid file or directory path.")
        return

    return all_findings


def print_report(findings):
    if not findings:
        print("No secrets detected.")
        return

    print("\n=== Secret Scanner Report ===\n")

    for finding in findings:
        print(f"File: {finding['file']}")
        print(f"Line: {finding['line']}")
        print(f"Type: {finding['type']}")
        print(f"Match: {finding['match']}")
        print("-" * 40)

        logging.info(
            f"Detected {finding['type']} in {finding['file']} at line {finding['line']}"
        )


def main():
    parser = argparse.ArgumentParser(
        description="Secret Scanner CLI Tool"
    )

    parser.add_argument(
        "path",
        help="Path to file or directory to scan"
    )

    args = parser.parse_args()

    findings = scan_path(args.path)
    print_report(findings)


if __name__ == "__main__":
    main()
