"""
llm.py — Multi-Provider LLM Integration (Groq, Cerebras, Google Gemini)
------------------------------------------------------------------------
Supports:
  1. Groq (GROQ_API_KEY) — Ultra-fast, free tier available at console.groq.com
  2. Cerebras (CEREBRAS_API_KEY) — High-throughput Llama inference at cloud.cerebras.ai
  3. Google Gemini (GEMINI_API_KEY / GOOGLE_API_KEY)

Exports:
    analyze_message(message, rule_flags, language) -> ScamAnalysis
    ScamAnalysis  (Pydantic model — the structured result)
    get_provider_info() -> tuple[str, str, str]
"""

import json
import os
import re
import time
from typing import List, Tuple

import requests
from pydantic import BaseModel, Field, ValidationError

from prompts import SYSTEM_PROMPT, build_user_prompt


# ---------------------------------------------------------------------------
# Response schema (Pydantic)
# ---------------------------------------------------------------------------

class ScamAnalysis(BaseModel):
    """Structured result returned by the LLM for every message analysis."""

    verdict: str = Field(description="One of: SCAM, SUSPICIOUS, SAFE")
    risk_score: int = Field(ge=0, le=100, description="0 = safe, 100 = definite scam")
    red_flags: List[str] = Field(description="List of specific scam indicators found")
    explanation: str = Field(description="2-3 simple sentences explaining the verdict")
    what_to_do: List[str] = Field(description="Actionable steps for the user")


# ---------------------------------------------------------------------------
# Provider Detection
# ---------------------------------------------------------------------------

def get_provider_info() -> Tuple[str, str, str]:
    """
    Detect which AI provider and API key to use.
    Returns: (provider_name, api_key, model_name)
    """
    groq_key = os.environ.get("GROQ_API_KEY", "").strip()
    cerebras_key = os.environ.get("CEREBRAS_API_KEY", "").strip()
    gemini_key = (
        os.environ.get("GEMINI_API_KEY", "") or os.environ.get("GOOGLE_API_KEY", "")
    ).strip()

    # Helpful fallback: if user pasted Groq or Cerebras key into GEMINI_API_KEY
    if gemini_key.startswith("gsk_") and not groq_key:
        groq_key = gemini_key
    elif gemini_key.startswith("csk-") and not cerebras_key:
        cerebras_key = gemini_key

    # Check for explicit provider preference if set
    preferred = os.environ.get("LLM_PROVIDER", "").strip().lower()

    if preferred == "groq" and groq_key:
        return "Groq", groq_key, os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
    if preferred == "cerebras" and cerebras_key:
        return "Cerebras", cerebras_key, os.environ.get("CEREBRAS_MODEL", "llama-3.3-70b")
    if preferred == "gemini" and gemini_key:
        return "Gemini", gemini_key, os.environ.get("GEMINI_MODEL", "gemini-1.5-flash")

    # Auto-detection order: Groq -> Cerebras -> Gemini
    if groq_key:
        return "Groq", groq_key, os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")
    if cerebras_key:
        return "Cerebras", cerebras_key, os.environ.get("CEREBRAS_MODEL", "llama-3.3-70b")
    if gemini_key:
        return "Gemini", gemini_key, os.environ.get("GEMINI_MODEL", "gemini-1.5-flash")

    raise EnvironmentError(
        "No AI API key found!\n\n"
        "Please add your API key to the .env file:\n"
        "  • For Groq: GROQ_API_KEY=gsk_...\n"
        "  • For Cerebras: CEREBRAS_API_KEY=csk-...\n"
        "  • For Gemini: GEMINI_API_KEY=AIzaSy..."
    )


# ---------------------------------------------------------------------------
# API Call Handlers
# ---------------------------------------------------------------------------

def _call_openai_compatible(
    endpoint: str,
    api_key: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
    provider_name: str,
) -> str:
    """Call an OpenAI-compatible endpoint (Groq, Cerebras) and return content string."""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.1,
    }

    try:
        response = requests.post(endpoint, json=payload, headers=headers, timeout=30)
    except requests.exceptions.RequestException as e:
        raise Exception(f"Failed to connect to {provider_name} API: {e}") from e

    if response.status_code != 200:
        error_msg = response.text
        try:
            err_json = response.json()
            if "error" in err_json:
                err_data = err_json["error"]
                error_msg = err_data.get("message", response.text) if isinstance(err_data, dict) else str(err_data)
        except Exception:
            pass
        raise Exception(f"{provider_name} API error ({response.status_code}): {error_msg}")

    try:
        data = response.json()
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, json.JSONDecodeError) as e:
        raise ValueError(f"Unexpected response format from {provider_name}: {response.text[:300]}") from e


def _call_gemini(api_key: str, model: str, full_prompt: str) -> str:
    """Call Google Gemini API."""
    try:
        from google import genai
    except ImportError:
        raise ImportError("google-genai package is not installed. Run: pip install google-genai")

    client = genai.Client(api_key=api_key)
    last_error = None
    for attempt in range(3):
        try:
            response = client.models.generate_content(
                model=model,
                contents=full_prompt,
                config={"response_mime_type": "application/json"},
            )
            return response.text if response.text else ""
        except Exception as e:
            last_error = e
            if "503" in str(e) or "UNAVAILABLE" in str(e):
                if attempt < 2:
                    time.sleep(3)
                    continue
            raise Exception(f"Gemini API call failed: {e}") from e
    if last_error:
        raise Exception(f"Gemini API unavailable after 3 retries: {last_error}") from last_error
    return ""


# ---------------------------------------------------------------------------
# JSON Extraction Helper
# ---------------------------------------------------------------------------

def _parse_json(raw_text: str, provider_name: str) -> dict:
    raw_text = raw_text.strip()
    if not raw_text:
        raise ValueError(f"{provider_name} returned an empty response.")

    try:
        return json.loads(raw_text)
    except json.JSONDecodeError:
        pass

    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw_text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    first_brace = raw_text.find("{")
    last_brace = raw_text.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        try:
            return json.loads(raw_text[first_brace : last_brace + 1])
        except json.JSONDecodeError:
            pass

    raise ValueError(f"Could not parse valid JSON from {provider_name} response:\n{raw_text[:300]}")


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------

def analyze_message(
    message: str,
    rule_flags: List[str],
    language: str = "English",
) -> ScamAnalysis:
    """Send the message + rule flags to the active LLM provider and return a structured analysis."""
    provider, api_key, model = get_provider_info()
    user_prompt = build_user_prompt(message, rule_flags, language)

    if provider == "Groq":
        raw_text = _call_openai_compatible(
            endpoint="https://api.groq.com/openai/v1/chat/completions",
            api_key=api_key,
            model=model,
            system_prompt=SYSTEM_PROMPT,
            user_prompt=user_prompt,
            provider_name="Groq",
        )
    elif provider == "Cerebras":
        raw_text = _call_openai_compatible(
            endpoint="https://api.cerebras.ai/v1/chat/completions",
            api_key=api_key,
            model=model,
            system_prompt=SYSTEM_PROMPT,
            user_prompt=user_prompt,
            provider_name="Cerebras",
        )
    elif provider == "Gemini":
        full_prompt = f"{SYSTEM_PROMPT}\n\n{user_prompt}"
        raw_text = _call_gemini(api_key=api_key, model=model, full_prompt=full_prompt)
    else:
        raise ValueError(f"Unsupported provider: {provider}")

    data = _parse_json(raw_text, provider)

    try:
        result = ScamAnalysis(**data)
    except (ValidationError, TypeError) as e:
        raise ValueError(f"Response didn't match expected structure: {e}") from e

    result.verdict = result.verdict.upper().strip()
    if result.verdict not in ("SCAM", "SUSPICIOUS", "SAFE"):
        result.verdict = "SUSPICIOUS"

    return result
