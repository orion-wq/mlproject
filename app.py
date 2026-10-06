"""
app.py — Scam Message Detector (Main Streamlit App)
-----------------------------------------------------
This is the entry point. Run with:
    streamlit run app.py

Structure:
  1. Imports & config
  2. Example messages (for "Try example" buttons)
  3. Sidebar (disclaimer)
  4. Main UI — input area
  5. Analysis logic — calls rules.py then llm.py
  6. Results display — verdict badge, risk meter, flags, explanation
"""

import streamlit as st
from dotenv import load_dotenv  # reads .env file for local development

# Load environment variables from .env (safe no-op if file doesn't exist)
load_dotenv(override=True)

from rules import check_rules
from llm import analyze_message, ScamAnalysis


# ---------------------------------------------------------------------------
# 1. Page configuration (must be the FIRST Streamlit command)
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Scam Message Detector",
    page_icon="🔍",
    layout="centered",
)


# ---------------------------------------------------------------------------
# 2. Example messages for the "Try example" buttons
# ---------------------------------------------------------------------------
EXAMPLES = [
    {
        "label": "🏦 Fake Bank Alert",
        "message": (
            "URGENT: Your SBI account has been BLOCKED due to incomplete KYC. "
            "Click bit.ly/sbi-kyc-verify to update your details immediately or "
            "your account will be permanently closed within 24 hours. "
            "Contact: 9876543210"
        ),
    },
    {
        "label": "💸 UPI Collect Scam",
        "message": (
            "Dear customer, you have a UPI collect request of ₹1 from Paytm Rewards. "
            "Accept this small debit to receive ₹5000 cashback directly in your account. "
            "Approve now: pay.paytm-rewards.in/collect?ref=78234"
        ),
    },
    {
        "label": "🎰 Lottery / OTP Scam",
        "message": (
            "Congratulations! Your mobile number has won ₹25,00,000 in the KBC Lucky Draw 2024. "
            "To claim your prize, share the OTP sent to your number with our agent at 9123456789. "
            "Offer valid for 2 hours only. Don't miss this opportunity!"
        ),
    },
]


# ---------------------------------------------------------------------------
# 3. Sidebar — disclaimer
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("## ⚠️ Disclaimer")
    st.warning(
        "This app uses AI which **can make mistakes**. "
        "Always verify with the official organization before taking action."
    )
    st.markdown("---")
    st.markdown("### 🚨 Report Fraud")
    st.markdown(
        "- 🌐 [cybercrime.gov.in](https://cybercrime.gov.in)\n"
        "- 📞 National Helpline: **1930**\n"
        "- 🏦 Contact your bank immediately if you shared any details"
    )
    st.markdown("---")
    st.markdown("### ℹ️ About")
    st.markdown(
        "Uses Google Gemini AI + regex rules to detect SMS scams, "
        "UPI fraud, phishing emails, and more."
    )
    st.caption("Built with Streamlit + Gemini API")


# ---------------------------------------------------------------------------
# 4. Main UI — Header & Input
# ---------------------------------------------------------------------------
st.title("🔍 Scam Message Detector")
st.markdown(
    "Paste a suspicious SMS, UPI request, or email below. "
    "We'll tell you if it's a scam and what to do."
)
st.markdown("---")

# Language selector
language = st.selectbox(
    "📝 Explanation language",
    options=["English", "Hinglish"],
    help="Choose the language for the AI's explanation",
)

# Text input area
# We use session_state to allow "Try example" buttons to pre-fill it
if "message_input" not in st.session_state:
    st.session_state["message_input"] = ""

message = st.text_area(
    "📨 Paste the suspicious message here",
    value=st.session_state["message_input"],
    height=180,
    placeholder="Example: Your account is blocked. Click bit.ly/xyz to verify KYC now...",
    key="message_text_area",
)

# "Try example" buttons — clicking one fills the text area
st.markdown("**Try an example:**")
cols = st.columns(3)
for i, example in enumerate(EXAMPLES):
    with cols[i]:
        if st.button(example["label"], use_container_width=True):
            # Store in session state and rerun to update the text area
            st.session_state["message_input"] = example["message"]
            st.rerun()

st.markdown("---")

# Main Analyze button
analyze_clicked = st.button(
    "🔎 Analyze Message",
    type="primary",
    use_container_width=True,
)


# ---------------------------------------------------------------------------
# 5. Analysis logic — triggered when button is clicked
# ---------------------------------------------------------------------------
if analyze_clicked:

    # Use whichever text is in the area right now
    current_message = st.session_state.get("message_text_area", message)

    # Validate input
    if not current_message or not current_message.strip():
        st.warning("⚠️ Please paste a message first before clicking Analyze.")
        st.stop()

    # Step A: Run the fast rule-based check (no API call)
    with st.spinner("🔎 Running rule-based pre-check..."):
        rule_flags = check_rules(current_message)

    # Step B: Send to Gemini for deep analysis
    with st.spinner("🤖 Asking Gemini AI to analyze..."):
        try:
            result: ScamAnalysis = analyze_message(current_message, rule_flags, language)
        except EnvironmentError as e:
            st.error(str(e))
            st.stop()
        except Exception as e:
            st.error(f"❌ Something went wrong: {e}")
            st.stop()

    # ---------------------------------------------------------------------------
    # 6. Results display
    # ---------------------------------------------------------------------------

    # --- Verdict badge ---
    VERDICT_CONFIG = {
        "SCAM":       {"emoji": "🔴", "color": "#FF4B4B", "bg": "#2D0000"},
        "SUSPICIOUS": {"emoji": "🟡", "color": "#FFA500", "bg": "#2D1A00"},
        "SAFE":       {"emoji": "🟢", "color": "#00C853", "bg": "#002D0A"},
    }
    cfg = VERDICT_CONFIG.get(result.verdict, VERDICT_CONFIG["SUSPICIOUS"])

    st.markdown("## Analysis Result")

    # Colored verdict badge using HTML
    st.markdown(
        f"""
        <div style="
            background-color: {cfg['bg']};
            border: 2px solid {cfg['color']};
            border-radius: 12px;
            padding: 16px 24px;
            text-align: center;
            margin-bottom: 8px;
        ">
            <span style="font-size: 2.5rem;">{cfg['emoji']}</span>
            <span style="
                font-size: 2rem;
                font-weight: 800;
                color: {cfg['color']};
                margin-left: 12px;
            ">{result.verdict}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # --- Risk score meter ---
    st.markdown(f"**🎯 Risk Score: {result.risk_score} / 100**")
    # st.progress takes a value 0.0 to 1.0
    st.progress(result.risk_score / 100)

    # Risk label below the meter
    if result.risk_score <= 20:
        st.caption("✅ Very low risk — likely safe")
    elif result.risk_score <= 49:
        st.caption("⚠️ Moderate risk — proceed with caution")
    elif result.risk_score <= 74:
        st.caption("🚨 High risk — likely a scam")
    else:
        st.caption("🔥 Very high risk — almost certainly a scam")

    st.markdown("---")

    # --- Red flags ---
    st.markdown("### 🚩 Red Flags Detected")
    if result.red_flags:
        for flag in result.red_flags:
            st.markdown(f"- ❗ {flag}")
    else:
        st.markdown("- ✅ No specific red flags found by AI")

    # Also show rule-engine flags if they add something
    if rule_flags:
        with st.expander("📋 Rule engine also detected"):
            for flag in rule_flags:
                st.markdown(f"- 🔸 {flag}")

    st.markdown("---")

    # --- Explanation ---
    st.markdown("### 💬 Explanation")
    st.info(result.explanation)

    # --- What to do ---
    st.markdown("### ✅ What To Do")
    for i, step in enumerate(result.what_to_do, start=1):
        st.markdown(f"**{i}.** {step}")

    st.markdown("---")
    st.caption(
        "⚠️ AI can be wrong. When in doubt, contact your bank directly. "
        "Report fraud at [cybercrime.gov.in](https://cybercrime.gov.in) or call **1930**."
    )
