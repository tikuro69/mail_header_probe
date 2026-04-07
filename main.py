import argparse
from pathlib import Path

from parser import parse_mail_header
from checks import run_checks
from formatter import format_report


def main() -> None:
    arg_parser = argparse.ArgumentParser(
        description="Parse a mail header and extract useful review points."
    )
    arg_parser.add_argument(
        "header_path", help="Path to a mail header text file")
    args = arg_parser.parse_args()

    header_path = Path(args.header_path)

    if not header_path.exists():
        print(f"ERROR: File not found: {header_path}")
        raise SystemExit(1)

    if not header_path.is_file():
        print(f"ERROR: Not a file: {header_path}")
        raise SystemExit(1)

    text = header_path.read_text(encoding="utf-8", errors="ignore")
    parsed = parse_mail_header(text)
    findings = run_checks(parsed)

    print(format_report(parsed, findings))


if __name__ == "__main__":
    main()
