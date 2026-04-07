import re
from dataclasses import dataclass, field
from email import policy
from email.parser import Parser
from typing import List


@dataclass
class ParsedMailHeader:
    from_header: str = "-"
    return_path: str = "-"
    reply_to: str = "-"
    message_id: str = "-"
    subject: str = "-"
    date: str = "-"
    authentication_results: List[str] = field(default_factory=list)
    received_spf: List[str] = field(default_factory=list)
    dkim_signature: List[str] = field(default_factory=list)
    received: List[str] = field(default_factory=list)
    sender_ips: List[str] = field(default_factory=list)
    sender_domains: List[str] = field(default_factory=list)
    spf_result: str = "unknown"
    dkim_result: str = "unknown"
    dmarc_result: str = "unknown"


def parse_mail_header(text: str) -> ParsedMailHeader:
    msg = Parser(policy=policy.default).parsestr(text)

    authentication_results = msg.get_all("Authentication-Results", [])
    received_spf = msg.get_all("Received-SPF", [])
    dkim_signature = msg.get_all("DKIM-Signature", [])
    received = msg.get_all("Received", [])

    parsed = ParsedMailHeader(
        from_header=collapse_ws(msg.get("From", "-")),
        return_path=collapse_ws(msg.get("Return-Path", "-")),
        reply_to=collapse_ws(msg.get("Reply-To", "-")),
        message_id=collapse_ws(msg.get("Message-ID", "-")),
        subject=collapse_ws(msg.get("Subject", "-")),
        date=collapse_ws(msg.get("Date", "-")),
        authentication_results=[collapse_ws(v)
                                for v in authentication_results],
        received_spf=[collapse_ws(v) for v in received_spf],
        dkim_signature=[collapse_ws(v) for v in dkim_signature],
        received=[collapse_ws(v) for v in received],
    )

    parsed.sender_ips = extract_sender_ips(parsed.received)
    parsed.sender_domains = extract_sender_domains(
        parsed.from_header,
        parsed.return_path,
        parsed.reply_to,
        parsed.received,
        parsed.authentication_results,
    )

    parsed.spf_result = detect_spf_result(
        parsed.authentication_results, parsed.received_spf)
    parsed.dkim_result = detect_dkim_result(
        parsed.authentication_results, parsed.dkim_signature)
    parsed.dmarc_result = detect_dmarc_result(parsed.authentication_results)

    return parsed


def collapse_ws(value: str) -> str:
    return " ".join(str(value).split())


def extract_sender_ips(received_headers: List[str]) -> List[str]:
    results: List[str] = []
    seen = set()

    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    # 下の Received の方が送信元に近いことが多いので reverse で見る
    for header in reversed(received_headers):
        for ip in re.findall(ip_pattern, header):
            if is_likely_ipv4(ip) and ip not in seen:
                seen.add(ip)
                results.append(ip)

    return results


def extract_sender_domains(
    from_header: str,
    return_path: str,
    reply_to: str,
    received_headers: List[str],
    authentication_results: List[str],
) -> List[str]:
    candidates: List[str] = []

    for value in [from_header, return_path, reply_to]:
        candidates.extend(extract_domains_from_text(value))

    for value in received_headers[:3]:
        candidates.extend(extract_domains_from_text(value))

    for value in authentication_results:
        candidates.extend(extract_domains_from_text(value))

    return dedupe(candidates)


def extract_domains_from_text(text: str) -> List[str]:
    pattern = r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
    found = re.findall(pattern, text)
    cleaned = []

    excluded = {
        "smtp.mailfrom",
        "header.from",
        "header.d",
        "client-ip",
    }

    for item in found:
        item = item.strip(".").lower()
        if item in excluded:
            continue
        if item == "localhost":
            continue
        cleaned.append(item)

    return cleaned


def detect_spf_result(authentication_results: List[str], received_spf: List[str]) -> str:
    joined = " ".join(authentication_results + received_spf).lower()

    for result in ["pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"]:
        if f"spf={result}" in joined:
            return result

    for result in ["pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"]:
        if joined.startswith(result) or f" {result} " in joined:
            return result

    return "unknown"


def detect_dkim_result(authentication_results: List[str], dkim_signature: List[str]) -> str:
    joined = " ".join(authentication_results).lower()

    for result in ["pass", "fail", "none", "temperror", "permerror", "neutral"]:
        if f"dkim={result}" in joined:
            return result

    if dkim_signature:
        return "present"

    return "unknown"


def detect_dmarc_result(authentication_results: List[str]) -> str:
    joined = " ".join(authentication_results).lower()

    for result in ["pass", "fail", "none", "temperror", "permerror", "bestguesspass"]:
        if f"dmarc={result}" in joined:
            return result

    return "unknown"


def is_likely_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False

    for part in parts:
        try:
            value = int(part)
        except ValueError:
            return False
        if value < 0 or value > 255:
            return False

    return True


def dedupe(items: List[str]) -> List[str]:
    seen = set()
    result = []

    for item in items:
        if item and item not in seen:
            seen.add(item)
            result.append(item)

    return result
