"""
rules.py — Rule-based pre-check engine
---------------------------------------
Uses regex patterns to scan a message for common scam indicators.
This runs BEFORE the LLM, so it's instant and costs nothing.

How to use:
    from rules import check_rules
    flags = check_rules("Your SBI account is blocked! OTP 123456")
    # Returns: ['Urgency language', 'OTP/credential request']
"""

import re
from typing import List


# --- Pattern definitions ---
# Each entry is a tuple: (human-readable label, compiled regex)
# re.I = case-insensitive matching

PATTERNS = [
    (
        "Shortened / suspicious URL",
        re.compile(
            r"bit\.ly|tinyurl\.com|t\.me|tiny\.cc|rb\.gy|cutt\.ly|ow\.ly|is\.gd",
            re.I,
        ),
    ),
    (
        "Urgency / threat language",
        re.compile(
            r"\b(urgent|urgently|immediately|blocked|suspended|expired|expires|"
            r"last\s*warning|final\s*notice|action\s*required|account\s*closed|"
            r"deactivat|disabled|restrict)\b",
            re.I,
        ),
    ),
    (
        "OTP / credential request",
        re.compile(
            r"\b(OTP|one[\s\-]time\s*password|PIN|CVV|card\s*number|"
            r"password|passcode|secret\s*code)\b",
            re.I,
        ),
    ),
    (
        "UPI / payment request",
        re.compile(
            r"\b(UPI|collect\s*request|pay\s*now|send\s*money|transfer\s*now|"
            r"payment\s*link|click\s*to\s*pay|approve\s*payment)\b",
            re.I,
        ),
    ),
    (
        "Fake KYC / account verification",
        re.compile(
            r"\b(KYC|e[\s\-]?KYC|know\s*your\s*customer|verify\s*account|"
            r"update\s*details|re[\s\-]?verify|complete\s*verification|"
            r"link\s*aadhar|link\s*aadhaar|link\s*pan)\b",
            re.I,
        ),
    ),
    (
        "Lottery / prize scam",
        re.compile(
            r"\b(won|winner|prize|lottery|lucky\s*draw|reward|cashback\s*of|"
            r"claim\s*your|congratulations\s*you\s*have)\b",
            re.I,
        ),
    ),
    (
        "Job / income scam",
        re.compile(
            r"\b(job\s*offer|work\s*from\s*home|earn\s*(?:rs\.?|₹|\$)?\s*\d+|"
            r"part[\s\-]?time|income\s*opportunity|refer\s*and\s*earn)\b",
            re.I,
        ),
    ),
    (
        "Refund / cashback lure",
        re.compile(
            r"\b(refund|get\s*back|money\s*back|cashback|reimburs)\b",
            re.I,
        ),
    ),
    (
        "Suspicious phone number in message body",
        # Matches standalone 10-digit Indian mobile numbers (starts with 6–9)
        re.compile(r"(?<!\d)[6-9]\d{9}(?!\d)"),
    ),
    (
        "Suspicious hyperlink / click-here bait",
        re.compile(
            r"(click\s*(here|now|below|the\s*link)|tap\s*here|open\s*link|"
            r"follow\s*the\s*link|http[s]?://\S+)",
            re.I,
        ),
    ),
]


def check_rules(message: str) -> List[str]:
    """
    Scan the message against all regex patterns.

    Args:
        message (str): The raw text the user pasted.

    Returns:
        List[str]: Human-readable flag labels for every pattern that matched.
                   Empty list if no red flags found.
    """
    if not message or not message.strip():
        return []

    flags = []
    for label, pattern in PATTERNS:
        if pattern.search(message):
            flags.append(label)

    return flags
