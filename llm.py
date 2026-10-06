"""
llm.py — Gemini API Provider
------------------------------
ALL Gemini-specific code lives in this one file.
To swap to a different AI provider (e.g., OpenAI), only edit THIS file.

Exports:
    analyze_message(message, rule_flags, language) -> ScamAnalysis
    ScamAnalysis  (Pydantic model — the structured result)

NOTE: We use response_mime_type="application/json" + manual JSON parsing.
      Passing a Pydantic class as response_schema triggers "automatic function
      calling" mode in newer SDK versions, which causes empty responses.
"""

import json
import os
from typing import List

from google import genai
from pydantic import BaseModel, Field, ValidationError

from prompts import SYSTEM_PROMPT, build_user_prompt


# ---------------------------------------------------------------------------
# Response schema  (Pydantic — used for validation AFTER we get JSON text)
# ---------------------------------------------------------------------------

class ScamAnalysis(BaseModel):
    """Structured result returned by the LLM for every message analysis."""

    verdict: str = Field(description="One of: SCAM, SUSPICIOUS, SAFE")
    risk_score: int = Field(ge=0, le=100, description="0 = safe, 100 = definite scam")
    red_flags: List[str] = Field(description="List of specific scam indicators found")
    explanation: str = Field(description="2-3 simple sentences explaining the verdict")
    what_to_do: List[str] = Field(description="Actionable steps for the user")


# ---------------------------------------------------------------------------
# API key helper
# ---------------------------------------------------------------------------

def _get_api_key() -> str:
    """
    Read the Gemini API key from the environment.
    Local dev  : reads from .env file (loaded by python-dotenv in app.py).
    Production : reads from Streamlit secrets (injected as env vars).
    """
    key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not key:
        raise EnvironmentError(
            "GEMINI_API_KEY not found!\n\n"
            "Local: Create a .env file with GEMINI_API_KEY=your_key\n"
            "Cloud: Add it under App Settings -> Secrets on Streamlit Cloud\n"
            "Get a free key at: https://aistudio.google.com/apikey"
        )
    return key


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------

def analyze_message(
    message: str,
    rule_flags: List[str],
    language: str = "English",
) -> ScamAnalysis:
    """
    Send the message + rule flags to Gemini and return a structured analysis.

    Strategy:
      1. Build a detailed prompt that instructs the model to return JSON.
      2. Call Gemini with response_mime_type="application/json" (no response_schema —
         that triggers automatic function calling which breaks structured output).
      3. Parse response.text as JSON manually.
      4. Validate with Pydantic and return a ScamAnalysis object.

    Args:
        message    : The suspicious message text pasted by the user.
        rule_flags : Red flags already found by rules.py (can be empty list).
        language   : "English" or "Hinglish" for the explanation text.

    Returns:
        ScamAnalysis: Validated Pydantic object with all analysis fields.

    Raises:
        EnvironmentError : API key missing.
        ValueError       : JSON parsing or Pydantic validation failed.
        Exception        : Any other API error, re-raised with context.
    """

    # Step 1: Build client + prompt
    client = genai.Client(api_key=_get_api_key())
    # Combine system prompt + user prompt into a single contents string
    # (system_instruction in config can behave differently across models)
    full_prompt = f"{SYSTEM_PROMPT}\n\n{build_user_prompt(message, rule_flags, language)}"

    # Step 2: Call Gemini — force JSON output via MIME type only (no response_schema)
    # Retry up to 3 times on 503 (model overloaded) errors
    import time
    last_error = None
    for attempt in range(3):
        try:
            response = client.models.generate_content(
                model="gemini-3.8-flash",
                contents=full_prompt,
                config={
                    "response_mime_type": "application/json",
                    # No response_schema — it triggers AFC mode and breaks output
                },
            )
            last_error = None
            break  # success — exit retry loop
        except Exception as e:
            last_error = e
            if "503" in str(e) or "UNAVAILABLE" in str(e):
                if attempt < 2:
                    time.sleep(3)   # wait 3 seconds then retry
                    continue
            raise Exception(f"Gemini API call failed: {e}") from e
    if last_error:
        raise Exception(f"Gemini API unavailable after 3 retries: {last_error}") from last_error

    # Step 3: Extract raw text
    raw_text = response.text if response.text else ""
    if not raw_text.strip():
        raise ValueError(
            "Gemini returned an empty response. "
            "The message may have been blocked by safety filters. "
            "Try rephrasing your input."
        )

    # Step 4: Parse JSON
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as e:
        # Try to extract JSON if wrapped in markdown code fences
        import re
        match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw_text, re.DOTALL)
        if match:
            data = json.loads(match.group(1))
        else:
            raise ValueError(f"Gemini returned invalid JSON: {e}\n\nRaw response:\n{raw_text[:300]}")

    # Step 5: Validate with Pydantic
    try:
        result = ScamAnalysis(**data)
    except (ValidationError, TypeError) as e:
        raise ValueError(f"Response didn't match expected structure: {e}") from e

    # Step 6: Normalize verdict
    result.verdict = result.verdict.upper().strip()
    if result.verdict not in ("SCAM", "SUSPICIOUS", "SAFE"):
        result.verdict = "SUSPICIOUS"  # Safe fallback for unexpected values

    return result
