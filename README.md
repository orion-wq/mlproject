# Scam Message Detector 🔍

A web app that analyzes suspicious SMS, UPI requests, and emails to detect scams using AI powered chatbot.

## Features
- **Rule-based pre-check**: Fast regex detection of common scam patterns (no API cost)
- **AI analysis**: Gemini LLM gives a verdict (SCAM / SUSPICIOUS / SAFE), a 0–100 risk score, red flags, explanation, and what to do
- **Bilingual**: Explanations in English or Hinglish
- **3 example messages**: Try pre-loaded scam samples with one click

## Project Structure
```
app.py          # Streamlit UI (main entry point)
llm.py          # Gemini API logic (swap-friendly)
rules.py        # Regex rule engine
prompts.py      # LLM prompt templates
requirements.txt
.env.example    # Template for your API key
```

## Setup (Local)

### 1. Clone the repo
```bash
git clone https://github.com/YOUR_USERNAME/scam-message-detector.git
cd scam-message-detector
```

### 2. Create a virtual environment
```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Mac/Linux:
source .venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Set your API key
```bash
# Copy the example file
copy .env.example .env   # Windows
cp .env.example .env     # Mac/Linux

# Edit .env and paste your key:
# GEMINI_API_KEY=your_actual_key_here
```
Get a free key at: https://aistudio.google.com/apikey

### 5. Run the app
```bash
streamlit run app.py
```
Open http://localhost:8501 in your browser.

## Deployment (Streamlit Community Cloud)
1. Push this repo to GitHub (must be public)
2. Go to https://share.streamlit.io → New app
3. Select your repo, branch `main`, file `app.py`
4. Under **Advanced settings → Secrets**, add:
   ```
   GEMINI_API_KEY = "your_actual_key_here"
   ```
5. Click Deploy

## ⚠️ Disclaimer
This app uses AI which can make mistakes. Always verify with official sources.
- Report fraud: https://cybercrime.gov.in
- Helpline: 1930
