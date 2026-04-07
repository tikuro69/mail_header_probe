from dataclasses import dataclass
from typing import List

from parser import ParsedMailHeader


@dataclass
class Finding:
    level: str
    message: str


def run_checks(parsed: ParsedMailHeader) -> List[Finding]:
    findings: List[Finding] = []

    findings.extend(check_authentication(parsed))
    findings.extend(check_header_consistency(parsed))
    findings.extend(check_received_chain(parsed))
    findings.extend(check_private_ips(parsed))

    return findings


def check_authentication(parsed: ParsedMailHeader) -> List[Finding]:
    findings: List[Finding] = []

    if parsed.spf_result == "fail":
        findings.append(Finding("WARN", "SPF result is fail."))
    elif parsed.spf_result == "softfail":
        findings.append(Finding("WARN", "SPF result is softfail."))
    elif parsed.spf_result == "pass":
        findings.append(Finding("INFO", "SPF result is pass."))
    elif parsed.spf_result == "unknown":
        findings.append(Finding("INFO", "SPF result could not be determined."))

    if parsed.dkim_result == "fail":
        findings.append(Finding("WARN", "DKIM result is fail."))
    elif parsed.dkim_result == "none":
        findings.append(Finding("WARN", "DKIM result is none."))
    elif parsed.dkim_result == "present":
        findings.append(Finding("INFO", "DKIM-Signature header is present."))
    elif parsed.dkim_result == "pass":
        findings.append(Finding("INFO", "DKIM result is pass."))
    elif parsed.dkim_result == "unknown":
        findings.append(
            Finding("INFO", "DKIM result could not be determined."))

    if parsed.dmarc_result == "fail":
        findings.append(Finding("WARN", "DMARC result is fail."))
    elif parsed.dmarc_result == "none":
        findings.append(Finding("WARN", "DMARC result is none."))
    elif parsed.dmarc_result == "pass":
        findings.append(Finding("INFO", "DMARC result is pass."))
    elif parsed.dmarc_result == "unknown":
        findings.append(
            Finding("INFO", "DMARC result could not be determined."))

    return findings


def check_header_consistency(parsed: ParsedMailHeader) -> List[Finding]:
    findings: List[Finding] = []

    from_domains = extract_domains(parsed.from_header)
    return_path_domains = extract_domains(parsed.return_path)
    reply_to_domains = extract_domains(parsed.reply_to)

    if not parsed.return_path or parsed.return_path == "-":
        findings.append(Finding("WARN", "Return-Path header was not found."))

    if from_domains and return_path_domains:
        if from_domains[0] != return_path_domains[0]:
            findings.append(
                Finding(
                    "INFO",
                    f"From domain and Return-Path domain differ: {from_domains[0]} vs {return_path_domains[0]}",
                )
            )

    if from_domains and reply_to_domains:
        if from_domains[0] != reply_to_domains[0]:
            findings.append(
                Finding(
                    "INFO",
                    f"From domain and Reply-To domain differ: {from_domains[0]} vs {reply_to_domains[0]}",
                )
            )

    if not parsed.message_id or parsed.message_id == "-":
        findings.append(Finding("WARN", "Message-ID header was not found."))

    if not parsed.received:
        findings.append(Finding("WARN", "No Received headers were found."))

    return findings


def check_received_chain(parsed: ParsedMailHeader) -> List[Finding]:
    findings: List[Finding] = []

    if parsed.received:
        findings.append(
            Finding("INFO", f"Received header count: {len(parsed.received)}"))

    if parsed.sender_ips:
        findings.append(
            Finding("INFO", f"Sender IP candidates found: {len(parsed.sender_ips)}"))
    else:
        findings.append(
            Finding("WARN", "No sender IP candidates were extracted."))

    return findings


def extract_domains(text: str) -> List[str]:
    import re

    pattern = r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
    return [item.lower() for item in re.findall(pattern, text or "")]


def check_private_ips(parsed: ParsedMailHeader) -> List[Finding]:
    findings: List[Finding] = []

    private_ips = [ip for ip in parsed.sender_ips if is_private_ipv4(ip)]

    if private_ips:
        findings.append(
            Finding(
                "INFO",
                f"Private IP addresses found in Received chain: {', '.join(private_ips)}",
            )
        )

    return findings


def is_private_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False

    try:
        nums = [int(part) for part in parts]
    except ValueError:
        return False

    if nums[0] == 10:
        return True

    if nums[0] == 192 and nums[1] == 168:
        return True

    if nums[0] == 172 and 16 <= nums[1] <= 31:
        return True

    return False
