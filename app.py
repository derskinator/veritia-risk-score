# app.py
# Veritia.ai — Name Risk Score (Deterministic Authority + Guardrails + Listings)
# -------------------------------------------------------------------------------
# ✅ Multi-stage SERP search (SerpAPI → Bing → DDG-Lite fallback)
# ✅ Deterministic authority via Wikipedia REST + IMDb suggest + Wikidata
# ✅ Authority Shield + Notoriety Floor + HARD GUARDRAILS (celebs vs non-celebs)
# ✅ Low-confidence mode (no hard stop on thin results)
# ✅ Lead capture (email + consent), save to Google Sheets or CSV
# ✅ Listings: “Likely You” vs “Other” with CSV export
# ✅ Safe-by-design: public results only; no PII displayed/saved

import os, re, csv, time, html, textwrap
from io import StringIO
from typing import List, Dict, Tuple
from urllib.parse import urlparse, quote_plus

import requests
import streamlit as st
from bs4 import BeautifulSoup

# =========================
# BRAND / PAGE
# =========================
st.set_page_config(page_title="Veritia — Name Risk Score", page_icon="👁️", layout="centered")
APP_TITLE = "Veritia.ai — Name Risk Score"
APP_TAGLINE = "See what AI & search can infer about you — and how to fix it."
st.markdown(
    f"<h1 style='text-align:center;margin-bottom:0;'>{APP_TITLE}</h1>"
    f"<p style='text-align:center;color:#8a8f98;margin-top:4px;'>{APP_TAGLINE}</p>",
    unsafe_allow_html=True,
)

# =========================
# SETTINGS & CONSTANTS
# =========================
SEARCH_PROVIDER = st.secrets.get("apis", {}).get("SEARCH_PROVIDER", "serpapi")  # serpapi | bing | ddg_lite
RESULTS_TO_FETCH = int(st.secrets.get("app", {}).get("RESULTS_TO_FETCH", 18))
FALLBACK_MIN_RESULTS = 3  # proceed in low-confidence mode if we get this many

NEGATIVE_KEYWORDS = [
    "arrest","lawsuit","scam","fraud","harassment","controversy","fired","charged","probe","sued"
]

DATA_BROKER_DOMAINS = [
    "spokeo.com","beenverified.com","mylife.com","whitepages.com","radaris.com","intelius.com",
    "nuwber.com","truthfinder.com","peoplefinders.com","pipl.com","thatsthem.com",
    "fastpeoplesearch.com","clustrmaps.com"
]

AUTHORITY_SITES_MEDIA = [
    "bloomberg.com","forbes.com","nytimes.com","britannica.com","scholar.google",
    "theguardian.com","washingtonpost.com","bbc.com","reuters.com","apnews.com"
]
AUTHORITY_SITES_DIRECT = ["wikipedia.org","wikidata.org","linkedin.com","imdb.com","crunchbase.com","orcid.org"]

SOCIAL_DOMAINS = ["facebook.com","instagram.com","tiktok.com","x.com","twitter.com","threads.net"]

BING_KEY = st.secrets.get("apis", {}).get("BING_KEY", "")
SERPAPI_KEY = st.secrets.get("apis", {}).get("SERPAPI_KEY", "")
HIBP_KEY = st.secrets.get("apis", {}).get("HIBP_KEY", "")

USE_SHEETS = bool(st.secrets.get("gcp_service_account")) and bool(st.secrets.get("leads"))
CSV_FALLBACK_PATH = "leads.csv"

# Listings scoring knobs
NAME_EXACT_WEIGHT = 40
NAME_TOKEN_WEIGHT = 8
CITY_ORG_BONUS = 6
DOMAIN_AUTH_BONUS = 6
BROKER_PENALTY = -10
GENERIC_SOCIAL_PENALTY = -6
MIN_LIKELY_SCORE = 25

# Store raw SerpAPI JSON for knowledge panel detection (optional)
serpapi_last_raw = None

# =========================
# LEAD STORAGE
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

def save_lead(name: str, email: str, score: str, city: str, org: str, q: str, confidence: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    row = [ts, name, email, score, city, org, q, confidence]
    try:
        if USE_SHEETS:
            ws = _get_ws()
            ws.append_row(row)
        else:
            newfile = not os.path.exists(CSV_FALLBACK_PATH)
            with open(CSV_FALLBACK_PATH, "a", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                if newfile:
                    w.writerow(["ts","name","email","score","city","org","query","confidence"])
                w.writerow(row)
    except Exception:
        st.warning("Lead save issue (we still show your results).")

# =========================
# SEARCH PROVIDERS
# =========================
def domain_from_url(u: str) -> str:
    try:
        netloc = urlparse(u).netloc.lower()
        if netloc.startswith("www."): netloc = netloc[4:]
        return netloc
    except Exception:
        return ""

def ddg_lite_search(query: str, n: int) -> List[Dict]:
    try:
        url = "https://lite.duckduckgo.com/lite/"
        headers = {"User-Agent": "Mozilla/5.0"}
        r = requests.get(url, params={"q": query}, headers=headers, timeout=15)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "lxml")
        results = []
        for a in soup.select("a"):
            href = (a.get("href") or "").strip()
            if not href.startswith("http"):
                continue
            title = (a.get_text() or "").strip()
            parent = a.find_parent()
            snippet = ""
            if parent:
                snippet = " ".join((parent.get_text(" ", strip=True) or "").split())
                if title and snippet.startswith(title):
                    snippet = snippet[len(title):].strip()
            results.append({"link": href, "title": title, "snippet": snippet})
            if len(results) >= n:
                break
        return results
    except Exception:
        return []

def bing_search(query: str, n: int) -> List[Dict]:
    if not BING_KEY: return []
    url = "https://api.bing.microsoft.com/v7.0/search"
    headers = {"Ocp-Apim-Subscription-Key": BING_KEY}
    params = {"q": query, "count": n, "mkt": "en-US", "safeSearch": "Moderate"}
    r = requests.get(url, headers=headers, params=params, timeout=15)
    r.raise_for_status()
    data = r.json()
    return [{"link": it.get("url",""), "title": it.get("name",""), "snippet": it.get("snippet","")}
            for it in data.get("webPages", {}).get("value", [])]

def serpapi_google(query: str, n: int) -> List[Dict]:
    global serpapi_last_raw
    if not SERPAPI_KEY: return []
    url = "https://serpapi.com/search.json"
    params = {"engine": "google", "q": query, "num": n, "api_key": SERPAPI_KEY}
    r = requests.get(url, params=params, timeout=15)
    r.raise_for_status()
    data = r.json()
    serpapi_last_raw = data
    out = []
    for it in data.get("organic_results", []):
        out.append({"link": it.get("link",""), "title": it.get("title",""), "snippet": it.get("snippet","")})
    return out

def _provider_search(provider: str, query: str, n: int):
    if provider == "serpapi":
        return serpapi_google(query, n)
    if provider == "bing":
        return bing_search(query, n)
    return ddg_lite_search(query, n)

def search_results(query: str, n: int) -> List[Dict]:
    def run_queries(qs, providers):
        seen, merged = set(), []
        per = max(4, n // max(1, len(qs)))
        for prov in providers:
            for q in qs:
                for r in _provider_search(prov, q, per) or []:
                    u = (r.get("link") or "").strip()
                    if not u or u in seen:
                        continue
                    seen.add(u)
                    merged.append(r)
                    if len(merged) >= n:
                        return merged
        return merged

    primary = SEARCH_PROVIDER if SEARCH_PROVIDER in ("serpapi","bing") else "ddg_lite"
    provider_order = [primary] + [p for p in ("serpapi","bing","ddg_lite") if p != primary]

    stage1_q = [
        f'"{query}"',
        f'"{query}" site:linkedin.com',
        f'"{query}" -site:facebook.com -site:instagram.com'
    ]
    res = run_queries(stage1_q, [primary])
    if len(res) >= FALLBACK_MIN_RESULTS:
        return res[:n]

    stage2_q = [query, f"{query} profile", f"{query} linkedin"]
    res2 = run_queries(stage2_q, [primary])
    if len(res2) >= FALLBACK_MIN_RESULTS:
        return res2[:n]

    res3 = run_queries(stage1_q + stage2_q, provider_order[1:])
    return res3[:n]

# =========================
# DETERMINISTIC AUTHORITY (Open Data)
# =========================
def wikipedia_exact_person(name: str) -> bool:
    try:
        title = name.replace(" ", "_")
        url = f"https://en.wikipedia.org/api/rest_v1/page/summary/{title}"
        r = requests.get(url, headers={"User-Agent": "veritia/1.0"}, timeout=10)
        if r.status_code != 200:
            return False
        data = r.json()
        if data.get("title","").lower() != name.lower(): return False
        if data.get("type") == "disambiguation": return False
        desc = (data.get("description") or "").lower()
        extract = (data.get("extract") or "").lower()
        hints = ["actor","actress","singer","politician","athlete","director","writer","producer",
                 "public figure","businessman","businesswoman","film","television","musician"]
        return any(k in desc for k in hints) or any(k in extract for k in hints)
    except Exception:
        return False

def imdb_has_name_hit(name: str) -> bool:
    try:
        url = "https://v2.sg.media-imdb.com/suggestion/{}/{}.json".format(name[0].lower(), name.replace(" ", "%20"))
        r = requests.get(url, headers={"User-Agent": "veritia/1.0"}, timeout=10)
        if r.status_code != 200:
            return False
        data = r.json()
        parts = [p.lower() for p in name.split() if p]
        for item in data.get("d", []):
            if not item.get("id","").startswith("nm"):
                continue
            label = (item.get("l","") + " " + item.get("s","")).lower()
            if all(p in label for p in parts[:2]):
                return True
        return False
    except Exception:
        return False

def wikidata_is_notable_person(name: str) -> bool:
    """Strong deterministic check via Wikidata: human (Q5) + many sitelinks."""
    try:
        s = requests.get(
            "https://www.wikidata.org/w/api.php",
            params={"action": "wbsearchentities", "search": name, "language": "en", "format": "json", "limit": 1},
            timeout=10,
            headers={"User-Agent": "veritia/1.0"},
        )
        s.raise_for_status()
        hits = s.json().get("search", [])
        if not hits: return False
        qid = hits[0].get("id")
        if not qid: return False

        e = requests.get(
            f"https://www.wikidata.org/wiki/Special:EntityData/{qid}.json",
            timeout=10,
            headers={"User-Agent": "veritia/1.0"},
        )
        e.raise_for_status()
        ent = e.json().get("entities", {}).get(qid, {})
        claims = ent.get("claims", {})
        is_human = any(
            snak.get("mainsnak", {}).get("datavalue", {}).get("value", {}).get("id") == "Q5"
            for snak in claims.get("P31", [])
        )
        sitelink_count = len(ent.get("sitelinks", {}))
        return bool(is_human and sitelink_count >= 10)
    except Exception:
        return False

# =========================
# SIGNALS & SCORING
# =========================
def detect_sensitive_patterns(text: str) -> Dict[str, int]:
    phone = len(re.findall(r"\b(?:\+?\d{1,2}\s*)?(?:\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4})\b", text))
    street = len(re.findall(r"\b\d{1,5}\s+\w+(?:\s+\w+)?\s+(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Lane|Ln|Dr|Drive|Ct|Court)\b", text, flags=re.I))
    email = len(re.findall(r"[\w\.-]+@[\w\.-]+\.\w+", text))
    return {"phones": phone, "addresses": street, "emails": email}

def sentiment_headline_neg(headline: str) -> bool:
    h = (headline or "").lower()
    return any(k in h for k in NEGATIVE_KEYWORDS)

def count_data_brokers(urls: List[str]) -> int:
    return sum(any(db in u for db in DATA_BROKER_DOMAINS) for u in urls)

def count_authority_hits(urls: List[str]) -> int:
    hits = 0
    for u in urls:
        d = domain_from_url(u)
        if not d: continue
        if any(d.endswith(auth) for auth in AUTHORITY_SITES_DIRECT): hits += 1; continue
        if d.endswith(".gov") or d.endswith(".edu"): hits += 1; continue
        if any(dom in d for dom in AUTHORITY_SITES_MEDIA): hits += 1
    return hits

def hibp_breach_count(email: str) -> int:
    if not email or not HIBP_KEY: return 0
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {"hibp-api-key": HIBP_KEY, "user-agent": "veritia-risk-check/1.0"}
    r = requests.get(url, headers=headers, params={"truncateResponse": "true"}, timeout=15)
    if r.status_code == 404: return 0
    r.raise_for_status()
    return len(r.json())

def score_from_signals(signals: Dict) -> Tuple[int, Dict[str, int]]:
    """
    0 (best) to 100 (worst).
    - Data Broker Exposure: 0–36 (6 per hit)
    - Sensitive Info Exposure: 0–20 (5 per phone/address pattern)
    - Identity Drift: 0–20 (domain diversity)
    - Authority Deficit: 0–30 (0=great, 30=none)
    - Negative Press: 0–10 (3 per negative headline)
    - Breach Risk: 0–5 (1 per breach)
    """
    subs = {}
    brokers = signals["data_brokers"]
    subs["Data Broker Exposure"] = min(36, brokers * 6)

    sens = signals["sensitive"]["phones"] + signals["sensitive"]["addresses"]
    subs["Sensitive Info Exposure"] = min(20, sens * 5)

    unique_domains = len(set(signals["domains"]))
    if unique_domains >= 10: drift_points = 14
    elif unique_domains >= 8: drift_points = 10
    elif unique_domains >= 5: drift_points = 6
    elif unique_domains >= 3: drift_points = 3
    else: drift_points = 0
    subs["Identity Drift"] = min(20, drift_points)

    auth = signals["authority_hits"]
    subs["Authority Deficit"] = 30 if auth == 0 else (18 if auth == 1 else (10 if auth == 2 else (4 if auth == 3 else 0)))

    subs["Negative Press"] = min(10, signals["neg_headlines"] * 3)
    subs["Breach Risk"] = min(5, signals.get("breach_count", 0))

    total = int(sum(subs.values()))
    return total, subs

# =========================
# AUTHORITY SHIELD & GUARDRAILS
# =========================
def has_wikipedia_from_urls(urls): 
    return any("wikipedia.org/wiki/" in u for u in urls)

def has_imdb_from_urls(urls): 
    return any("imdb.com" in u for u in urls)

def major_press_hits(urls):
    majors = [
        "nytimes.com","guardian.com","washingtonpost.com","bbc.com","bloomberg.com",
        "forbes.com","reuters.com","apnews.com","variety.com","hollywoodreporter.com",
        "rollingstone.com","vanityfair.com","latimes.com"
    ]
    return sum(any(m in u for m in majors) for u in urls)

def serpapi_has_knowledge_panel() -> bool:
    try:
        return bool(serpapi_last_raw and serpapi_last_raw.get("knowledge_graph"))
    except Exception:
        return False

def authority_shield_factor(authority_hits:int, urls:list, wiki_bool:bool, imdb_bool:bool, kp_bool:bool) -> float:
    shield = 1.0
    if wiki_bool or has_wikipedia_from_urls(urls): shield *= 0.5
    if imdb_bool or has_imdb_from_urls(urls):      shield *= 0.7
    if major_press_hits(urls) >= 3:                shield *= 0.6
    if authority_hits >= 4:                        shield *= 0.6
    if kp_bool:                                     shield *= 0.6
    return max(0.25, shield)

def notoriety_floor(wiki_bool:bool, imdb_bool:bool, authority_hits:int, kp_bool:bool) -> int:
    if wiki_bool or imdb_bool or authority_hits >= 5 or kp_bool:
        return 7
    return 0

def risk_band(score: int) -> str:
    if score >= 70: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"

# =========================
# LISTINGS SCORING & BUCKETING
# =========================
def tokenize_name(full: str):
    return [t for t in re.findall(r"[A-Za-z]+", full or "") if t]

def has_exact_phrase(phrase: str, text: str) -> bool:
    if not phrase or not text: return False
    p = re.escape(phrase.strip())
    return bool(re.search(rf"\b{p}\b", text, flags=re.I))

def contains_all_tokens(tokens, text: str) -> bool:
    if not tokens or not text: return False
    low = text.lower()
    return all(t.lower() in low for t in tokens)

def classify_domain(url: str):
    d = domain_from_url(url)
    tags = []
    if any(db in d for db in DATA_BROKER_DOMAINS): tags.append("broker")
    if any(dom in d for dom in AUTHORITY_SITES_MEDIA) or \
       any(d.endswith(auth) for auth in AUTHORITY_SITES_DIRECT) or \
       d.endswith(".edu") or d.endswith(".gov"):
        tags.append("authority")
    if any(s in d for s in SOCIAL_DOMAINS): tags.append("social")
    return d, tags

def listing_relevance(name: str, city: str, org: str, item: Dict) -> Dict:
    title = (item.get("title") or "").strip()
    snippet = (item.get("snippet") or "").strip()
    url = (item.get("link") or "").strip()

    name_tokens = tokenize_name(name)
    score = 0
    reasons = []

    if has_exact_phrase(name, title):
        score += NAME_EXACT_WEIGHT; reasons.append("Exact name in title")
    elif has_exact_phrase(name, snippet):
        score += NAME_EXACT_WEIGHT // 2; reasons.append("Exact name in snippet")

    if contains_all_tokens(name_tokens, title + " " + snippet):
        score += NAME_TOKEN_WEIGHT * len(name_tokens); reasons.append("All name tokens present")

    if city and has_exact_phrase(city, title + " " + snippet):
        score += CITY_ORG_BONUS; reasons.append("City match")
    if org and contains_all_tokens(tokenize_name(org), title + " " + snippet):
        score += CITY_ORG_BONUS; reasons.append("Company/role match")

    domain, tags = classify_domain(url)
    if "authority" in tags:
        score += DOMAIN_AUTH_BONUS; reasons.append("Authority domain")
    if "broker" in tags:
        score += BROKER_PENALTY; reasons.append("Data broker")
    if "social" in tags and not has_exact_phrase(name, title):
        score += GENERIC_SOCIAL_PENALTY; reasons.append("Generic social")

    return {"url": url, "domain": domain, "title": title or domain, "snippet": snippet,
            "score": score, "reasons": reasons, "tags": tags}

def rank_listings_for_person(name: str, city: str, org: str, raw_results: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
    scored = [listing_relevance(name, city, org, r) for r in raw_results if r.get("link")]
    scored.sort(key=lambda x: (x["score"], -len(x["domain"])), reverse=True)
    likely = [r for r in scored if r["score"] >= MIN_LIKELY_SCORE][:15]
    other = [r for r in scored if r["score"] < MIN_LIKELY_SCORE][:15]
    return likely, other

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

st.caption(f"Search provider: **{SEARCH_PROVIDER}**")

# =========================
# RUN
# =========================
if submitted:
    if not (name and email and agree and consent):
        st.error("Please complete name, email, and both checkboxes.")
        st.stop()

    query = " ".join([x for x in [name, city, org] if x]).strip()
    st.info(f"Scanning public results for: **{query}**")

    # Deterministic authority checks (do not depend on SERP)
    wiki_flag = wikipedia_exact_person(name)
    imdb_flag = imdb_has_name_hit(name)
    wikidata_flag = wikidata_is_notable_person(name)
    kp_flag = False

    with st.spinner("Collecting signals..."):
        results = search_results(query, RESULTS_TO_FETCH)

        urls     = [r.get("link","") for r in results if r.get("link")]
        titles   = [r.get("title","") for r in results]
        snippets = [r.get("snippet","") for r in results]
        domains  = [domain_from_url(u) for u in urls]

        low_confidence = len(urls) < FALLBACK_MIN_RESULTS

        # Listings bucketing (Likely You vs Other)
        likely_listings, other_listings = rank_listings_for_person(name, city, org, results)

        # Backfill empty titles with hostnames (helps DDG-lite)
        for i, t in enumerate(titles):
            if not t and i < len(domains) and domains[i]:
                titles[i] = domains[i].split(".")[0].title()

        combined_snippets = " ".join(snippets)
        sens     = detect_sensitive_patterns(combined_snippets)
        neg      = sum(1 for t in titles if sentiment_headline_neg(t))
        brokers  = count_data_brokers(urls)
        authhits = count_authority_hits(urls)

        if serpapi_last_raw and SEARCH_PROVIDER == "serpapi":
            kp_flag = bool(serpapi_last_raw.get("knowledge_graph"))

        breach   = 0  # Optional: enable HIBP lookups
        # if email and HIBP_KEY:
        #     breach = hibp_breach_count(email)

        signals = {
            "data_brokers": brokers,
            "sensitive": sens,
            "neg_headlines": neg,
            "authority_hits": authhits,
            "domains": domains,
            "titles": titles,
            "breach_count": breach,
        }

        # ---- SCORING ----
        raw_score, subs = score_from_signals(signals)

        shield = authority_shield_factor(authhits, urls, wiki_flag, imdb_flag, kp_flag)
        adjusted_score = int(round(raw_score * shield))

        # Stronger celeb detection (any of these should trip)
        is_celebrity = (
            wiki_flag or imdb_flag or kp_flag or wikidata_flag or
            authhits >= 3 or major_press_hits(urls) >= 2
        )

        # Hard guardrails
        if is_celebrity:
            adjusted_score = min(adjusted_score, 12)
            adjusted_score = max(adjusted_score, 7)  # never zero
        else:
            high_brokers = subs["Data Broker Exposure"] >= 6
            weak_authority = subs["Authority Deficit"] >= 18
            some_drift = subs["Identity Drift"] >= 6
            if weak_authority and high_brokers:
                adjusted_score = max(adjusted_score, 50)
            elif weak_authority and some_drift:
                adjusted_score = max(adjusted_score, 35)

        # Light exposure boost if many likely matches for non-celeb
        if not is_celebrity and len(likely_listings) >= 5:
            adjusted_score = min(100, adjusted_score + 5)

        lvl = risk_band(adjusted_score)

    # Save lead
    conf_label = "low" if low_confidence else "normal"
    save_lead(name=name, email=email, score=str(adjusted_score), city=city, org=org, q=query, confidence=conf_label)

    # =========================
    # RESULTS UI
    # =========================
    st.markdown("---")
    badge = " (low confidence)" if low_confidence else ""
    st.markdown(f"## Overall Risk: **{adjusted_score}/100** — {lvl}{badge}")
    if low_confidence:
        st.info("Limited public results were found; this score is computed with reduced confidence.")
    st.progress(min(adjusted_score, 100) / 100)

    c1, c2 = st.columns(2)
    with c1:
        st.metric("Data Broker Exposure", f"{subs['Data Broker Exposure']}/36")
        st.metric("Sensitive Info Exposure", f"{subs['Sensitive Info Exposure']}/20")
        st.metric("Identity Drift", f"{subs['Identity Drift']}/20")
    with c2:
        st.metric("Authority Deficit", f"{subs['Authority Deficit']}/30")
        st.metric("Negative Press", f"{subs['Negative Press']}/10")
        st.metric("Breach Risk", f"{subs['Breach Risk']}/5")

    st.markdown("### Top Recommendations")
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

    for rec in quick_fixes(signals, subs):
        st.write("• " + rec)

    # ======= Listings UI =======
    st.markdown("### Listings that appear to be about you")
    st.caption("These are public search results that likely reference your name. We do not display or store any private information.")

    def render_badges(tags, reasons):
        b = []
        for t in tags:
            if t == "authority": b.append("🟢 authority")
            elif t == "broker":  b.append("🔴 broker")
            elif t == "social":  b.append("🟡 social")
        for r in reasons[:2]:
            b.append(f"• {r}")
        return "  ·  ".join(b)

    def render_listing(item):
        safe_title = html.escape(item["title"])
        safe_snip = html.escape(textwrap.shorten(item["snippet"], width=200, placeholder="…"))
        badges = render_badges(item["tags"], item["reasons"])
        st.markdown(f"""
**[{safe_title}]({item['url']})**  
<span style="color:#6b7280">{html.escape(item['domain'])}</span> • score {item['score']}  
{safe_snip}  
<span style="color:#6b7280">{badges}</span>
""", unsafe_allow_html=True)

    if likely_listings:
        st.write(f"**Likely You** ({len(likely_listings)})")
        for it in likely_listings:
            render_listing(it)
    else:
        st.write("_No strong matches yet. Try adding a city or company to your query._")

    with st.expander("Other results (probably not you)"):
        if other_listings:
            for it in other_listings:
                render_listing(it)
        else:
            st.write("_None to show._")

    # CSV export of listings
    csv_buf = StringIO()
    writer = csv.writer(csv_buf)
    writer.writerow(["bucket","score","title","url","domain","tags","reasons","snippet"])
    for it in likely_listings:
        writer.writerow(["likely", it["score"], it["title"], it["url"], it["domain"], ";".join(it["tags"]), ";".join(it["reasons"]), it["snippet"]])
    for it in other_listings:
        writer.writerow(["other", it["score"], it["title"], it["url"], it["domain"], ";".join(it["tags"]), ";".join(it["reasons"]), it["snippet"]])
    st.download_button("Download listings as CSV", data=csv_buf.getvalue(), file_name="veritia_listings.csv", mime="text/csv")

    with st.expander("What we checked (summary)"):
        st.write(f"- {len(urls)} public results scanned")
        st.write(f"- Data broker hits: {signals['data_brokers']}")
        st.write(f"- Authority sources present (SERP): {signals['authority_hits']}")
        st.write(f"- Deterministic authority: Wikipedia={wiki_flag}, IMDb={imdb_flag}, Wikidata={wikidata_flag}, KnowledgePanel={kp_flag}")
        st.write(f"- Potential sensitive patterns flagged (not shown): phones={sens['phones']} addresses={sens['addresses']} emails={sens['emails']}")

    with st.expander("Debug"):
        st.write("Provider:", SEARCH_PROVIDER, "| Confidence:", conf_label)
        st.write("Raw score:", raw_score, "Shield factor:", round(shield, 2), "Adjusted:", adjusted_score)
        st.write("Celebrity detected:", is_celebrity)
        st.write("SERP authority hits:", signals["authority_hits"], "| MajorPress:", major_press_hits(urls))
        st.write("Open-data authority:", {"Wikipedia": wiki_flag, "IMDb": imdb_flag, "Wikidata": wikidata_flag, "KnowledgePanel": kp_flag})
        st.write("Data broker hits:", signals["data_brokers"])
        st.write("Negative headlines:", signals["neg_headlines"])
        st.write("Unique domains:", len(set(signals["domains"])))
        st.write("Sample URLs:", urls[:10])

    st.caption("We analyze public search results and patterns only. We never display or store private information.")

