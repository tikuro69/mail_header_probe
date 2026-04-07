from typing import List

from parser import ParsedMailHeader
from checks import Finding


YELLOW = "\033[33m"
BLUE = "\033[34m"
RESET = "\033[0m"


def colorize_level(level: str) -> str:
    if level == "WARN":
        return f"{YELLOW}{level}{RESET}"
    if level == "INFO":
        return f"{BLUE}{level}{RESET}"
    return level


def format_report(parsed: ParsedMailHeader, findings: List[Finding]) -> str:
    lines = []

    lines.append("[Summary]")
    lines.append(f"From: {parsed.from_header}")
    lines.append(f"Return-Path: {parsed.return_path}")
    lines.append(f"Reply-To: {parsed.reply_to}")
    lines.append(f"Message-ID: {parsed.message_id}")
    lines.append(f"Subject: {parsed.subject}")
    lines.append(f"Date: {parsed.date}")
    lines.append("")

    lines.append("[Authentication]")
    lines.append(f"SPF: {parsed.spf_result}")
    lines.append(f"DKIM: {parsed.dkim_result}")
    lines.append(f"DMARC: {parsed.dmarc_result}")
    lines.append("")

    lines.append("[Findings]")
    if findings:
        for finding in findings:
            level = colorize_level(finding.level)
            lines.append(f"{level}: {finding.message}")
    else:
        lines.append("No findings.")
    lines.append("")

    lines.append("[Sender IP Candidates]")
    if parsed.sender_ips:
        for ip in parsed.sender_ips:
            lines.append(f"- {ip}")
    else:
        lines.append("- none")
    lines.append("")

    lines.append("[Domain Candidates]")
    if parsed.sender_domains:
        for domain in parsed.sender_domains[:20]:
            lines.append(f"- {domain}")
    else:
        lines.append("- none")
    lines.append("")

    lines.append("[Authentication-Results]")
    if parsed.authentication_results:
        for item in parsed.authentication_results:
            lines.append(f"- {item}")
    else:
        lines.append("- none")
    lines.append("")

    lines.append("[Received-SPF]")
    if parsed.received_spf:
        for item in parsed.received_spf:
            lines.append(f"- {item}")
    else:
        lines.append("- none")
    lines.append("")

    lines.append("[Received Headers]")
    if parsed.received:
        for i, item in enumerate(parsed.received, start=1):
            lines.append(f"{i}. {item}")
    else:
        lines.append("- none")

    return "\n".join(lines)