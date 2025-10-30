# app.py
import re
import time
import csv
import os
from typing import List, Dict, Tuple

import requests
import streamlit as st
from bs4 import BeautifulSoup

# =========================
# BRAND / UI
# =========================
APP_TITLE = "Veritia.ai — Name Risk Score"
APP_TAGLINE = "See what AI & search can infer about you — and how to fix it."
PRIMARY = "#2C7FFF"  # Accent color

st.set_page_config(page_title="Veritia — Name Risk Score", page_icon="👁️", layout="centered")
st.markdown(
    f"<h1 style='text-align:center;margin-bottom:0;'>{APP_TITLE}</h1>"
    f"<p style='text-align:center;color:#8a8f98;margin-top:4px;'>{APP_TAGLINE}</p>",
    unsafe_allow_html=True,
)

# =========================
# SETTINGS & CONSTANTS
# =========================
SEARCH_PROVIDER = st.secrets.get("apis", {}).get("SEARCH_PROVIDER", "ddg_lite")  # "serpapi" | "bing" | "ddg_lite"
RESULTS_TO_FETCH = int(st.secrets.get("app", {}).get("RESULTS_TO_FETCH", 18))

NEGATIVE_KEYWORDS = [
    "arrest","lawsuit","scam","fraud","harassment","controversy","fired","charged","probe","sued"
]

DATA_BROKER_DOMAINS = [
    "spokeo.com","beenverified.com","mylife.com","whitepages.com","radaris.com","intelius.com",
    "nuwber.com","truthfinder.com","peoplefinders.com","pipl.com","thatsthem.com",
    "fastpeoplesearch.com","clustrmaps.com"
]

# Expanded to strongly favor well-known authority sources
AUTHORITY_SITES = [
    "wikipedia.org","wikidata.org","linkedin.com","crunchbase.com","imdb.com",
    "gov","edu","scholar.google","orcid.org","bloomberg.com","forbes.com","nytimes.com",
    "official"  # heuristic; catches many official brand domains/titles
]

# Keys
BING_KEY = st.secrets.get("apis", {}).get("BING_KEY", "")
SERPAPI_KEY = st.secrets.get("apis", {}).get("SERPAPI_KEY", "")
HIBP_KEY = st.secrets.get("apis", {}).get("HIBP_KEY", "")

# Lead storage (Google Sheets if configured; else CSV)
USE_SHEETS = bool(st.secrets.get("gcp_service_account")) and bool(st.secrets.get("leads"))
CSV_FALLBACK_PATH = "leads.csv"

# =========================
# GOOGLE SHEETS (optional)
# =========================
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
    except Exception:
        st.warning("Lead save issue (we still show your results).")

# =========================
# SEARCH PROVIDERS
# =========================
def ddg_lite_search(query: str, n: int = RESULTS_TO_FETCH) -> List[Dict]:
    """DuckDuckGo Lite HTML (no key). Returns list of {link,title,snippet}."""
    try:
        url = "https://lite.duckduckgo.com/lite/"
        headers = {
            "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/120.0.0.0 Safari/537.36")
        }
        r = requests.get(url, params={"q": query}, headers=headers, timeout=15)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "lxml")

        results = []
        for a in soup.select("a"):
            href = a.get("href") or ""
            text = (a.get_text() or "").strip()
            if href.startswith("http"):
                # try to build a minimal snippet from nearby text nodes
                snippet = ""
                parent = a.find_parent()
                if parent:
                    snippet = " ".join((parent.get_text(" ", strip=True) or "").split())
                    if text and snippet.startswith(text):
                        snippet = snippet[len(text):].strip()
                results.append({"link": href, "title": text, "snippet": snippet})
            if len(results) >= n:
                break
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
    """Run multiple queries, merge & dedupe."""
    base_queries = [
        f'"{query}"',                          # exact match
        f'"{query}" site:linkedin.com',
        f'"{query}" -site:facebook.com -site:instagram.com'
    ]
    per = max(3, n // len(base_queries))
    merged, seen = [], set()
    for q in base_queries:
        if SEARCH_PROVIDER == "serpapi":
            chunk = serpapi_google(q, per)
        elif SEARCH_PROVIDER == "bing":
            chunk = bing_search(q, per)
        else:
            chunk = ddg_lite_search(q, per)
        for r in chunk:
            u = (r.get("link") or "").strip()
            if u and u not in seen:
                seen.add(u)
                merged.append(r)
    return merged[:n]

# =========================
# SIGNALS & SCORING
# =========================
def detect_sensitive_patterns(text: str) -> Dict[str, int]:
    """Pattern counters only (no PII shown/saved)."""
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
    """Optional breach count; safe summary only."""
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
    0 (best) to 100 (worst). Heavier weight on Authority & Brokers for clear separation.
    - Data Broker Exposure: 0–30 (6 pts each, cap 30)
    - Sensitive Info Exposure: 0–25 (6 pts per phone/address pattern, cap 25)
    - Identity Drift: 0–20 (based on domain diversity)
    - Authority Deficit: 0–25 (0=great, 25=none)
    - Negative Press: 0–10 (3 pts each, cap 10)
    - Breach Risk: 0–5 (1 per breach, cap 5)
    """
    s = signals
    subs = {}

    # Data brokers
    brokers = s["data_brokers"]
    subs["Data Broker Exposure"] = min(30, brokers * 6)

    # Sensitive patterns (phones + addresses)
    sens = s["sensitive"]["phones"] + s["sensitive"]["addresses"]
    subs["Sensitive Info Exposure"] = min(25, sens * 6)

    # Identity Drift (domain diversity)
    unique_domains = len(set(s["domains"]))
    if unique_domains >= 10:
        drift_points = 14
    elif unique_domains >= 8:
        drift_points = 10
    elif unique_domains >= 5:
        drift_points = 6
    elif unique_domains >= 3:
        drift_points = 3
    else:
        drift_points = 0
    subs["Identity Drift"] = min(20, drift_points)

    # Authority deficit (stronger bite)
    auth = s["authority_hits"]
    subs["Authority Deficit"] = 25 if auth == 0 else (15 if auth == 1 else (8 if auth == 2 else (3 if auth == 3 else 0)))

    # Negative press
    subs["Negative Press"] = min(10, s["neg_headlines"] * 3)

    # Breach risk
    subs["Breach Risk"] = min(5, s.get("breach_count", 0))

    total = int(sum(subs.values()))
    return total, subs

def band(score: int) -> str:
    if score >= 70: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"

def quick_fixes(signals: Dict, subs: Dict[str, int]) -> List[str]:
    recs = []
    if subs["Data Broker Exposure"] >= 12:
        recs.append("Submit removal requests to top data brokers (Spokeo, BeenVerified, Whitepages, MyLife).")
    if subs["Sensitive Info Exposure"] >= 10:
        recs.append("Audit public posts & PDFs; remove phone/address; request cache removal where needed.")
    if subs["Authority Deficit"] >= 8:
        recs.append("Publish a canonical bio page with schema.org/Person; create/clean Wikidata; complete LinkedIn.")
    if subs["Identity Drift"] >= 6:
        recs.append("Standardize your headline across LinkedIn, your site, and press mentions.")
    if subs["Negative Press"] >= 6:
        recs.append("Publish counter-narratives on credible sites; pursue structured PR to add positive citations.")
    if subs["Breach Risk"] >= 3:
        recs.append("Change passwords and enable 2FA; remove old emails from public profiles.")
    if not recs:
        recs.append("Maintain quarterly audits; set Google Alerts; keep canonical bio & schema updated.")
    return recs[:5]

# =========================
# FORM (Lead Gate)
# =========================
with st.form("risk_form"):
    name = st.text_input("Full name*", placeholder="e.g., Keanu Reeves")
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

    query = " ".join([x for x in [name, city, org] if x]).strip()
    st.info(f"Scanning public results for: **{query}**")

    with st.spinner("Collecting signals..."):
        results = search_results(query, RESULTS_TO_FETCH)
        urls   = [r.get("link","") for r in results if r.get("link")]
        titles = [r.get("title","") for r in results]
        snippets = [r.get("snippet","") for r in results]

        # derive domains
        domains = []
        for u in urls:
            d = re.sub(r"^https?://(www\.)?", "", u).split("/")[0] if u else ""
            domains.append(d)

        # backfill empty titles with hostname (helps DDG-lite)
        for i, t in enumerate(titles):
            if not t and i < len(domains) and domains[i]:
                titles[i] = domains[i].split(".")[0].title()

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

    # Save lead
    save_lead(name=name, email=email, score=score, city=city, org=org, q=query)

    # =========================
    # RESULTS UI
    # =========================
    st.markdown("---")
    st.markdown(f"## Overall Risk: **{score}/100** — {lvl}")
    st.progress(min(score, 100) / 100)

    col1, col2 = st.columns(2)
    with col1:
        st.metric("Data Broker Exposure", f"{subs['Data Broker Exposure']}/30")
        st.metric("Sensitive Info Exposure", f"{subs['Sensitive Info Exposure']}/25")
        st.metric("Identity Drift", f"{subs['Identity Drift']}/20")
    with col2:
        st.metric("Authority Deficit", f"{subs['Authority Deficit']}/25")
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

    with st.expander("Debug (temporary)"):
        st.write("Search provider:", SEARCH_PROVIDER)
        st.write("Authority hits:", signals["authority_hits"])
        st.write("Data broker hits:", signals["data_brokers"])
        st.write("Negative headlines:", signals["neg_headlines"])
        st.write("Unique domains:", len(set(signals["domains"])))
        st.write("Sample URLs:", urls[:8])

    st.caption(
        "This tool analyzes public search results and generic patterns only. "
        "It does not store content from results, reveal private data, or provide doxxing methods."
    )
