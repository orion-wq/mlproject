"""
prompts.py — LLM Prompt Templates
-----------------------------------
All prompts live here so they're easy to find and tune.
If the LLM gives wrong results, come here first and adjust the wording.

Exports:
    SYSTEM_PROMPT  — tells Gemini what role to play
    build_user_prompt(message, rule_flags, language) — builds the analysis prompt
"""


# --- System prompt ---
# This tells Gemini its role. Sent once per request as a "system instruction".
SYSTEM_PROMPT = """You are a cybersecurity expert and consumer fraud specialist with deep knowledge 
of SMS scams, UPI fraud, phishing emails, and online scams targeting people in India.

Your job is to analyze a suspicious message and decide whether it is a SCAM, SUSPICIOUS, or SAFE.

Rules you MUST follow:
1. Always respond with ONLY valid JSON — no extra text, no markdown, no code fences.
2. Use the exact JSON schema provided in the user message.
3. Be especially alert to: fake bank alerts, UPI collect fraud, OTP theft, fake KYC, 
   lottery scams, job scams, and impersonation of government agencies or banks.
4. If a message asks for OTP, PIN, password, or CVV — it is ALWAYS a SCAM. 
   Legitimate organizations NEVER ask for these.
5. Risk score guide: 0-20 = definitely safe, 21-49 = slightly suspicious, 
   50-74 = likely scam, 75-100 = definite scam.
6. Keep red_flags list concise — max 5 items, each under 10 words.
7. explanation should be 2-3 simple sentences a non-technical person can understand.
8. what_to_do should have 3-5 actionable steps.
"""


def build_user_prompt(message: str, rule_flags: list, language: str) -> str:
    """
    Build the analysis prompt combining the user's message and pre-detected flags.

    Args:
        message (str): The suspicious message the user pasted.
        rule_flags (list): Red flags already found by rules.py (can be empty).
        language (str): "English" or "Hinglish"

    Returns:
        str: The complete prompt to send to the LLM.
    """

    # Instruction for output language
    if language == "Hinglish":
        lang_instruction = (
            "Write the 'explanation' and 'what_to_do' fields in Hinglish "
            "(a natural mix of Hindi and English using Roman script, "
            "like how people text in India). Keep it simple and friendly."
        )
    else:
        lang_instruction = (
            "Write the 'explanation' and 'what_to_do' fields in simple, clear English. "
            "Avoid technical jargon — write as if explaining to someone's parent."
        )

    # Format the pre-detected flags for the prompt
    if rule_flags:
        flags_text = "\n".join(f"  - {f}" for f in rule_flags)
    else:
        flags_text = "  - None detected by rule engine"

    return f"""Analyze the following message for scam indicators.

=== MESSAGE TO ANALYZE ===
{message}
=== END MESSAGE ===

Pre-detected red flags from rule engine (use these as hints, but do your own analysis too):
{flags_text}

{lang_instruction}

Respond with ONLY this JSON (fill in every field, no extra text outside the JSON):
{{
  "verdict": "<SCAM or SUSPICIOUS or SAFE>",
  "risk_score": <integer between 0 and 100>,
  "red_flags": ["<flag 1>", "<flag 2>"],
  "explanation": "<2-3 sentences explaining why this is or isn't a scam>",
  "what_to_do": ["<step 1>", "<step 2>", "<step 3>"]
}}
"""
