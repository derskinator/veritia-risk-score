# app.py
import re
import time
import csv
import os
from typing import List, Dict, Tuple

import requests
import streamlit as st

# ====== BRAND CONFIG ======
APP_TITLE = "Veritia.ai — Name Risk Score"
APP_TAGLINE = "See what AI & search can infer about you — and how to fix it."
PRIMARY = "#2C7FFF"  # Accent color

# ====== SCAN SETTINGS ======
SEARCH_PROVIDER = st.secrets.get("apis", {}).get("SEARCH_PROVIDER", "ddg_html")  # "bing" | "serpapi" | "ddg_html"
RESULTS_TO_FETCH = 15
NEGATIVE_KEYWORDS = ["arrest", "lawsuit", "scam", "fraud", "harassment", "controversy", "fired", "charged", "probe", "sued"]
DATA_BROKER_DOMAINS = [
    "spokeo.com","beenverified.com","mylife.com","whitepages.com","radaris.com","intelius.com",
    "nuwber.com","truthfinder.com","peoplefinders.com","pipl.com","thatsthem.com","fastpeoplesearch.com","clustrmaps.com"
]
AUTHORITY_SITES = ["wikipedia.org","wikidata.org","linkedin.com","crunchbase.com","about.me","medium.com","linktr.ee"]

# ====== OPTIONAL API KEYS (via Streamlit Secrets) ======
BING_KEY = st.secrets.get("apis", {}).get("BING_KEY", "")
SERPAPI_KEY = st.secrets.get("apis", {}).get("SERPAPI_KEY", "")
HIBP_KEY = st.secrets.get("apis", {}).get("HIBP_KEY", "")

# ====== LEADS STORAGE CONFIG ======
USE_SHEETS = bool(st.secrets.get("gcp_service_account")) and bool(st.secrets.get("leads"))
CSV_FALLBACK_PATH = "leads.csv"

# ====== SHEETS CLIENT (only if configured) ======
def _get_ws():
    if not USE_SHEETS:
        return None
    import gspread
    from google.oauth2.service_account import Credentials
    sa = st.secrets["gcp_service_account"]
    creds = Credentials.from_service_account_info(sa, scopes=[
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive"
    ])
    gc = gspread.authorize(creds)
    sh = gc.open(st.secrets["leads"]["sheet_name"])
    ws = sh.worksheet(st.secrets["leads"]["worksheet"])
    return ws

def save_lead(name: str, email: str, score: int, city: str, org: str, q: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    row = [ts, name, email, score, city, org, q]
    try:
        if USE_SHEETS:
            ws = _get_ws()
            ws.append_row(row)
        else:
            newfile = not os.path.exists(CSV_FALLBACK_PATH)
            with open(CSV_FALLBACK_PATH, "a", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                if newfile:
                    w.writerow(["ts","name","email","score","city","org","query"])
                w.writerow(row)
    except Exception as e:
        st.warning("Lead save issue (we still show your results).")

# ====== SEARCH HELPERS ======
def normalize(q: str) -> str:
    return re.sub(r"\s+", " ", q.strip())

def ddg_html_search(query: str, n: int = RESULTS_TO_FETCH) -> List[Dict]:
    """DuckDuckGo HTML (no key). Naive parse; production should consider a stable SERP API."""
    try:
        r = requests.get("https://html.duckduckgo.com/html/", params={"q": query}, timeout=15)
        r.raise_for_status()
        urls = re.findall(r'<a rel="nofollow" class="result__a" href="([^"]+)"', r.text)
        # snippet extraction is intentionally minimal to avoid brittle parsing
        results = [{"link": u, "title": "", "snippet": ""} for u in urls[:n]]
        return results
    except Exception:
        return []

def bing_search(query: str, n: int = RESULTS_TO_FETCH) -> List[Dict]:
    if not BING_KEY:
        return []
    url = "https://api.bing.microsoft.com/v7.0/search"
    headers = {"Ocp-Apim-Subscription-Key": BING_KEY}
    params = {"q": query, "count": n, "mkt": "en-US", "safeSearch": "Moderate"}
    r = requests.get(url, headers=headers, params=params, timeout=15)
    r.raise_for_status()
    data = r.json()
    web_pages = data.get("webPages", {}).get("value", [])
    return [{"link": it.get("url",""),
             "title": it.get("name",""),
             "snippet": it.get("snippet","")} for it in web_pages]

def serpapi_google(query: str, n: int = RESULTS_TO_FETCH) -> List[Dict]:
    if not SERPAPI_KEY:
        return []
    url = "https://serpapi.com/search.json"
    params = {"engine": "google", "q": query, "num": n, "api_key": SERPAPI_KEY}
    r = requests.get(url, params=params, timeout=15)
    r.raise_for_status()
    data = r.json()
    org = []
    for it in data.get("organic_results", []):
        org.append({"link": it.get("link",""), "title": it.get("title",""), "snippet": it.get("snippet","")})
    return org

def search_results(query: str, n: int = RESULTS_TO_FETCH) -> List[Dict]:
    if SEARCH_PROVIDER == "bing":
        res = bing_search(query, n)
        if res: return res
    if SEARCH_PROVIDER == "serpapi":
        res = serpapi_google(query, n)
        if res: return res
    # Fallback (default)
    return ddg_html_search(query, n)

# ====== SIGNALS & SCORING ======
def detect_sensitive_patterns(text: str) -> Dict[str, int]:
    """Count potential exposures in snippets (patterns only; we never display PII)."""
    phone = len(re.findall(r"\b(?:\+?\d{1,2}\s*)?(?:\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4})\b", text))
    street = len(re.findall(r"\b\d{1,5}\s+\w+(?:\s+\w+)?\s+(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Lane|Ln|Dr|Drive|Ct|Court)\b", text, flags=re.I))
    email = len(re.findall(r"[\w\.-]+@[\w\.-]+\.\w+", text))
    return {"phones": phone, "addresses": street, "emails": email}

def sentiment_headline_neg(headline: str) -> bool:
    h = (headline or "").lower()
    return any(k in h for k in NEGATIVE_KEYWORDS)

def count_data_brokers(urls: List[str]) -> int:
    return sum(any(db in (u or "") for db in DATA_BROKER_DOMAINS) for u in urls)

def count_authority_hits(urls: List[str]) -> int:
    return sum(any(dom in (u or "") for dom in AUTHORITY_SITES) for u in urls)

def hibp_breach_count(email: str) -> int:
    """Optional breach count via HIBP; we never show breach details."""
    if not email or not HIBP_KEY:
        return 0
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {"hibp-api-key": HIBP_KEY, "user-agent": "veritia-risk-check/1.0"}
    r = requests.get(url, headers=headers, params={"truncateResponse": "true"}, timeout=15)
    if r.status_code == 404:
        return 0
    r.raise_for_status()
    return len(r.json())

def score_from_signals(signals: Dict) -> Tuple[int, Dict[str, int]]:
    """
    Weighting (0 = best, 100 = worst):
      - Data Broker Exposure (0–25)
      - Sensitive Info Exposure (0–25)
      - Identity Drift (0–20)
      - Authority Deficit (0–15)
      - Negative Press (0–10)
      - Breach Risk (0–5)
    """
    s = signals
    subs = {}

    # Data brokers: each hit adds 5pts up to 25
    brokers = s["data_brokers"]
    subs["Data Broker Exposure"] = min(25, brokers * 5)

    # Sensitive: phones + addresses (emails are less sensitive)
    sens = s["sensitive"]["phones"] + s["sensitive"]["addresses"]
    subs["Sensitive Info Exposure"] = min(25, sens * 6)

    # Identity Drift: many different titles/domains => inconsistent narrative
    unique_domains = len(set(s["domains"]))
    unique_titles = len(set(t for t in s["titles"] if t))
    drift = max(0, (unique_titles // 6) + (unique_domains // 8) - 1)
    subs["Identity Drift"] = min(20, drift * 5)

    # Authority deficit: fewer authority sources => higher risk
    auth = s["authority_hits"]
    subs["Authority Deficit"] = 15 if auth == 0 else (10 if auth == 1 else (5 if auth == 2 else 0))

    # Negative press: more negative headlines => higher risk
    subs["Negative Press"] = min(10, s["neg_headlines"] * 3)

    # Breach risk (optional)
    subs["Breach Risk"] = min(5, s.get("breach_count", 0))

    total = sum(subs.values())
    return int(total), subs

def band(score: int) -> str:
    if score >= 70: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"

def quick_fixes(signals: Dict, subs: Dict[str, int]) -> List[str]:
    recs = []
    if subs["Data Broker Exposure"] >= 10:
        recs.append("Submit removal requests to top data brokers (Spokeo, BeenVerified, Whitepages, MyLife).")
    if subs["Sensitive Info Exposure"] >= 10:
        recs.append("Audit public posts & PDFs; remove phone/address; request cache removal where needed.")
    if subs["Authority Deficit"] >= 5:
        recs.append("Publish a canonical bio page with schema.org/Person; create/clean Wikidata; complete LinkedIn.")
    if subs["Identity Drift"] >= 10:
        recs.append("Standardize your headline across LinkedIn, your site, and press mentions.")
    if subs["Negative Press"] >= 6:
        recs.append("Publish counter-narratives on credible sites; pursue structured PR to add positive citations.")
    if subs["Breach Risk"] >= 3:
        recs.append("Change passwords and enable 2FA; remove old emails from public profiles.")
    if not recs:
        recs.append("Maintain quarterly audits; set Google Alerts; keep canonical bio & schema updated.")
    return recs[:5]

# ====== UI ======
st.set_page_config(page_title="Veritia — Name Risk Score", page_icon="👁️", layout="centered")
st.markdown(
    f"<h1 style='text-align:center;margin-bottom:0;'>{APP_TITLE}</h1>"
    f"<p style='text-align:center;color:#8a8f98;margin-top:4px;'>{APP_TAGLINE}</p>",
    unsafe_allow_html=True,
)

with st.form("risk_form"):
    name = st.text_input("Full name*", placeholder="e.g., Alex Johnson")
    city = st.text_input("City / Region (optional)")
    org  = st.text_input("Company / Role (optional)")
    email = st.text_input("Email to receive your report*", placeholder="you@domain.com")
    agree = st.checkbox("I understand this analyzes public results only and will not display/store sensitive personal data.")
    consent = st.checkbox("I agree to receive my results and follow-up by email.")
    submitted = st.form_submit_button("Get My Risk Score")

if submitted:
    if not (name and email and agree and consent):
        st.error("Please complete name, email, and both checkboxes.")
        st.stop()

    q = normalize(" ".join([x for x in [name, city, org] if x]))
    st.info(f"Scanning public results for: **{q}**")

    with st.spinner("Collecting signals..."):
        results = search_results(q, RESULTS_TO_FETCH)
        urls = [r.get("link","") for r in results if r.get("link")]
        titles = [r.get("title","") for r in results]
        snippets = [r.get("snippet","") for r in results]

        # derive domains
        domains = []
        for u in urls:
            d = re.sub(r"^https?://(www\.)?", "", u).split("/")[0] if u else ""
            domains.append(d)

        combined_snippets = " ".join(snippets)
        sens = detect_sensitive_patterns(combined_snippets)
        neg = sum(1 for t in titles if sentiment_headline_neg(t))
        brokers = count_data_brokers(urls)
        authhits = count_authority_hits(urls)
        breach = hibp_breach_count(email) if email else 0

        signals = {
            "data_brokers": brokers,
            "sensitive": sens,
            "neg_headlines": neg,
            "authority_hits": authhits,
            "domains": domains,
            "titles": titles,
            "breach_count": breach,
        }
        score, subs = score_from_signals(signals)
        lvl = band(score)

    # Save lead after successful scan
    save_lead(name=name, email=email, score=score, city=city, org=org, q=q)

    st.markdown("---")
    st.markdown(f"## Overall Risk: **{score}/100** — {lvl}")
    st.progress(min(score, 100) / 100)

    col1, col2 = st.columns(2)
    with col1:
        st.metric("Data Broker Exposure", f"{subs['Data Broker Exposure']}/25")
        st.metric("Sensitive Info Exposure", f"{subs['Sensitive Info Exposure']}/25")
        st.metric("Identity Drift", f"{subs['Identity Drift']}/20")
    with col2:
        st.metric("Authority Deficit", f"{subs['Authority Deficit']}/15")
        st.metric("Negative Press", f"{subs['Negative Press']}/10")
        st.metric("Breach Risk", f"{subs['Breach Risk']}/5")

    st.markdown("### Top Recommendations")
    for rec in quick_fixes(signals, subs):
        st.write("• " + rec)

    with st.expander("What we checked (summary)"):
        st.write(f"- {len(urls)} public results scanned")
        st.write(f"- Data broker hits: {signals['data_brokers']}")
        st.write(f"- Authority sources present: {signals['authority_hits']}")
        st.write(f"- Potential sensitive patterns flagged (not shown): phones={sens['phones']} addresses={sens['addresses']} emails={sens['emails']}")
        if email:
            st.write(f"- Potential breach count (HIBP): {breach}")

    st.caption("This tool analyzes public search results and generic patterns only. "
               "It does not store content from results, reveal private data, or provide doxxing methods.")

    st.markdown("---")
    st.markdown(
        "<div style='text-align:center'>"
        "<b>Want a full Veritia audit?</b><br/>"
        "We’ll fix bios, add schema, remove data broker listings, and align your narrative across AI search."
        "</div>", unsafe_allow_html=True
    )
