# app.py
# Veritia.ai — Deterministic Risk (No-Keys Required) + Listings + Guardrails
# -------------------------------------------------------------------------
# Runs accurately with NO paid search keys:
# - Celebrity detection: Wikipedia REST + IMDb suggest + Wikidata
# - Exposure detection: per-domain DDG-lite site: queries (brokers, authority, news)
# - Listings: scored & bucketed "Likely You" vs "Other"
# Optional: SerpAPI/Bing improve general listings, but not required

import os, re, csv, time, html, textwrap
from io import StringIO
from typing import List, Dict, Tuple
from urllib.parse import urlparse, quote_plus

import requests
import streamlit as st
from bs4 import BeautifulSoup

# --------------------------
# PAGE
# --------------------------
st.set_page_config(page_title="Veritia — Name Risk Score", page_icon="👁️", layout="centered")
st.markdown(
    "<h1 style='text-align:center;margin-bottom:0;'>Veritia.ai — Name Risk Score</h1>"
    "<p style='text-align:center;color:#8a8f98;margin-top:4px;'>See what AI & search can infer about you — and how to fix it.</p>",
    unsafe_allow_html=True,
)

# --------------------------
# SECRETS / SETTINGS
# --------------------------
SEARCH_PROVIDER = st.secrets.get("apis", {}).get("SEARCH_PROVIDER", "ddg_lite").lower()  # serpapi|bing|ddg_lite
SERPAPI_KEY = st.secrets.get("apis", {}).get("SERPAPI_KEY", "")
BING_KEY    = st.secrets.get("apis", {}).get("BING_KEY", "")

RESULTS_TO_FETCH = int(st.secrets.get("app", {}).get("RESULTS_TO_FETCH", 18))
FALLBACK_MIN_RESULTS = 3

USE_SHEETS = bool(st.secrets.get("gcp_service_account")) and bool(st.secrets.get("leads"))
CSV_FALLBACK_PATH = "leads.csv"

# --------------------------
# CONSTANTS
# --------------------------
NEGATIVE_KEYWORDS = ["arrest","lawsuit","scam","fraud","harassment","controversy","fired","charged","probe","sued"]

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

NEWS_DOMAINS = [
    "nytimes.com","washingtonpost.com","bbc.com","theguardian.com","reuters.com","apnews.com",
    "latimes.com","wsj.com","cnn.com","foxnews.com","nbcnews.com","cnbc.com","bloomberg.com","forbes.com"
]

SOCIAL_DOMAINS = ["facebook.com","instagram.com","tiktok.com","x.com","twitter.com","threads.net","youtube.com","linkedin.com"]

# Listings scoring knobs
NAME_EXACT_WEIGHT = 40
NAME_TOKEN_WEIGHT = 8
CITY_ORG_BONUS = 6
DOMAIN_AUTH_BONUS = 6
BROKER_PENALTY = -10
GENERIC_SOCIAL_PENALTY = -6
MIN_LIKELY_SCORE = 25

# Provider cache
serpapi_last_raw = None

# --------------------------
# UTIL
# --------------------------
def domain_from_url(u: str) -> str:
    try:
        d = urlparse(u).netloc.lower()
        return d[4:] if d.startswith("www.") else d
    except Exception:
        return ""

def ddg_lite_search(query: str, n: int) -> List[Dict]:
    """DuckDuckGo Lite HTML fallback. Returns list of {link,title,snippet} or [] with warning."""
    try:
        url = "https://lite.duckduckgo.com/lite/"
        r = requests.get(url, params={"q": query}, headers={"User-Agent":"Mozilla/5.0"}, timeout=15)
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
    except Exception as e:
        st.warning(f"DDG-lite error: {type(e).__name__}: {e}")
        return []

def serpapi_google(query: str, n: int) -> List[Dict]:
    global serpapi_last_raw
    if not SERPAPI_KEY:
        return []
    try:
        url = "https://serpapi.com/search.json"
        r = requests.get(url, params={"engine":"google","q":query,"num":n,"api_key":SERPAPI_KEY}, timeout=15)
        r.raise_for_status()
        data = r.json()
        serpapi_last_raw = data
        return [{"link": it.get("link",""), "title": it.get("title",""), "snippet": it.get("snippet","")} 
                for it in data.get("organic_results", [])]
    except Exception as e:
        st.warning(f"SerpAPI error: {type(e).__name__}: {e}")
        return []

def bing_search(query: str, n: int) -> List[Dict]:
    if not BING_KEY:
        return []
    try:
        url = "https://api.bing.microsoft.com/v7.0/search"
        r = requests.get(url, headers={"Ocp-Apim-Subscription-Key": BING_KEY}, params={"q":query,"count":n}, timeout=15)
        r.raise_for_status()
        data = r.json()
        vals = data.get("webPages", {}).get("value", [])
        return [{"link": it.get("url",""), "title": it.get("name",""), "snippet": it.get("snippet","")} for it in vals]
    except Exception as e:
        st.warning(f"Bing error: {type(e).__name__}: {e}")
        return []

def provider_search(query: str, n: int) -> List[Dict]:
    """General listings provider chain: SerpAPI -> Bing -> DDG Lite."""
    for prov in [SEARCH_PROVIDER, "serpapi", "bing", "ddg_lite"]:
        if prov == "serpapi" and SERPAPI_KEY:
            res = serpapi_google(query, n)
        elif prov == "bing" and BING_KEY:
            res = bing_search(query, n)
        else:
            res = ddg_lite_search(query, n)
        if res:
            return res[:n]
    return []

# --------------------------
# DETERMINISTIC CELEBRITY CHECKS
# --------------------------
def wikipedia_exact_person(name: str) -> bool:
    try:
        title = name.replace(" ", "_")
        url = f"https://en.wikipedia.org/api/rest_v1/page/summary/{title}"
        r = requests.get(url, headers={"User-Agent":"veritia/1.0"}, timeout=10)
        if r.status_code != 200: return False
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
        url = f"https://v2.sg.media-imdb.com/suggestion/{name[0].lower()}/{name.replace(' ','%20')}.json"
        r = requests.get(url, headers={"User-Agent":"veritia/1.0"}, timeout=10)
        if r.status_code != 200: return False
        parts = [p.lower() for p in name.split() if p]
        for item in r.json().get("d", []):
            if not item.get("id","").startswith("nm"): 
                continue
            label = (item.get("l","") + " " + item.get("s","")).lower()
            if all(p in label for p in parts[:2]):
                return True
        return False
    except Exception:
        return False

def wikidata_is_notable_person(name: str) -> bool:
    try:
        s = requests.get("https://www.wikidata.org/w/api.php",
            params={"action":"wbsearchentities","search":name,"language":"en","format":"json","limit":1},
            headers={"User-Agent":"veritia/1.0"}, timeout=10)
        s.raise_for_status()
        hits = s.json().get("search", [])
        if not hits: return False
        qid = hits[0].get("id")
        if not qid: return False
        e = requests.get(f"https://www.wikidata.org/wiki/Special:EntityData/{qid}.json",
                         headers={"User-Agent":"veritia/1.0"}, timeout=10)
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

def serpapi_has_knowledge_panel() -> bool:
    try:
        return bool(serpapi_last_raw and serpapi_last_raw.get("knowledge_graph"))
    except Exception:
        return False

# --------------------------
# PER-DOMAIN “SITE:” SCANS
# --------------------------
def ddg_site_scan_exact(name: str, domain: str, limit: int = 5) -> List[Dict]:
    """Run a site:domain "<name>" query to count & fetch matches. No API key needed."""
    q = f'site:{domain} "{name}"'
    return ddg_lite_search(q, limit)

def count_matches_on_domains(name: str, domains: List[str], per_domain_limit=3) -> Tuple[int, List[Dict]]:
    total = 0
    hits: List[Dict] = []
    for d in domains:
        res = ddg_site_scan_exact(name, d, per_domain_limit)
        # Count only clear matches (title/snippet contain the exact phrase)
        for r in res:
            text = (r.get("title","") + " " + r.get("snippet","")).lower()
            if re.search(rf'\b{re.escape(name.lower())}\b', text):
                total += 1
                hits.append(r)
    return total, hits

# --------------------------
# SIGNALS & SCORING
# --------------------------
def detect_sensitive_patterns(text: str) -> Dict[str, int]:
    phone = len(re.findall(r"\b(?:\+?\d{1,2}\s*)?(?:\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4})\b", text))
    address = len(re.findall(r"\b\d{1,5}\s+\w+(?:\s+\w+)?\s+(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Lane|Ln|Dr|Drive|Ct|Court)\b", text, flags=re.I))
    email = len(re.findall(r"[\w\.-]+@[\w\.-]+\.\w+", text))
    return {"phones": phone, "addresses": address, "emails": email}

def risk_band(score: int) -> str:
    if score >= 70: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"

# --------------------------
# LISTINGS SCORING
# --------------------------
def tokenize_name(full: str):
    return [t for t in re.findall(r"[A-Za-z]+", full or "") if t]

def has_exact_phrase(phrase: str, text: str) -> bool:
    if not phrase or not text: return False
    return bool(re.search(rf"\b{re.escape(phrase.strip())}\b", text, flags=re.I))

def contains_all_tokens(tokens, text: str) -> bool:
    if not tokens or not text: return False
    low = text.lower()
    return all(t.lower() in low for t in tokens)

def classify_domain(url: str):
    d = domain_from_url(url)
    tags = []
    if any(db in d for db in DATA_BROKER_DOMAINS): tags.append("broker")
    if any(dom in d for dom in AUTHORITY_SITES_MEDIA) or any(d.endswith(auth) for auth in AUTHORITY_SITES_DIRECT) or d.endswith(".gov") or d.endswith(".edu"):
        tags.append("authority")
    if any(s in d for s in SOCIAL_DOMAINS): tags.append("social")
    return d, tags

def listing_relevance(name: str, city: str, org: str, item: Dict) -> Dict:
    title = (item.get("title") or "").strip()
    snippet = (item.get("snippet") or "").strip()
    url = (item.get("link") or "").strip()
    name_tokens = tokenize_name(name)
    score, reasons = 0, []

    if has_exact_phrase(name, title):   score += NAME_EXACT_WEIGHT; reasons.append("Exact name in title")
    elif has_exact_phrase(name, snippet): score += NAME_EXACT_WEIGHT//2; reasons.append("Exact name in snippet")
    if contains_all_tokens(name_tokens, title + " " + snippet):
        score += NAME_TOKEN_WEIGHT * len(name_tokens); reasons.append("All name tokens present")
    if city and has_exact_phrase(city, title + " " + snippet): score += CITY_ORG_BONUS; reasons.append("City match")
    if org and contains_all_tokens(tokenize_name(org), title + " " + snippet): score += CITY_ORG_BONUS; reasons.append("Company/role match")

    domain, tags = classify_domain(url)
    if "authority" in tags: score += DOMAIN_AUTH_BONUS; reasons.append("Authority domain")
    if "broker" in tags:    score += BROKER_PENALTY; reasons.append("Data broker")
    if "social" in tags and not has_exact_phrase(name, title): score += GENERIC_SOCIAL_PENALTY; reasons.append("Generic social")

    return {"url": url, "domain": domain, "title": title or domain, "snippet": snippet, "score": score, "reasons": reasons, "tags": tags}

def rank_listings_for_person(name: str, city: str, org: str, raw_results: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
    scored = [listing_relevance(name, city, org, r) for r in raw_results if r.get("link")]
    scored.sort(key=lambda x: (x["score"], -len(x["domain"])), reverse=True)
    likely = [r for r in scored if r["score"] >= MIN_LIKELY_SCORE][:15]
    other  = [r for r in scored if r["score"] < MIN_LIKELY_SCORE][:15]
    return likely, other

# --------------------------
# LEADS
# --------------------------
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
    return sh.worksheet(st.secrets["leads"]["worksheet"])

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
                if newfile: w.writerow(["ts","name","email","score","city","org","query","confidence"])
                w.writerow(row)
    except Exception:
        st.warning("Lead save issue (results still shown).")

# --------------------------
# FORM
# --------------------------
with st.form("risk_form"):
    name = st.text_input("Full name*", placeholder="e.g., Keanu Reeves")
    city = st.text_input("City / Region (optional)")
    org  = st.text_input("Company / Role (optional)")
    email = st.text_input("Email to receive your report*", placeholder="you@domain.com")
    agree = st.checkbox("I understand this analyzes public results only and will not display/store sensitive personal data.")
    consent = st.checkbox("I agree to receive my results and follow-up by email.")
    submitted = st.form_submit_button("Get My Risk Score")

st.caption(f"Search provider preference: **{SEARCH_PROVIDER}** (keys optional)")

# --------------------------
# RUN
# --------------------------
if submitted:
    if not (name and email and agree and consent):
        st.error("Please complete name, email, and both checkboxes.")
        st.stop()

    q_person = " ".join([x for x in [name, city, org] if x]).strip()
    st.info(f"Scanning public results for: **{q_person}**")

    # 1) Deterministic celebrity flags (do NOT depend on SERP providers)
    wiki_flag     = wikipedia_exact_person(name)
    imdb_flag     = imdb_has_name_hit(name)
    wikidata_flag = wikidata_is_notable_person(name)
    kp_flag       = serpapi_has_knowledge_panel()  # only true if SerpAPI used earlier

    # 2) Per-domain exposure scans (deterministic, no keys needed)
    broker_count, broker_hits = count_matches_on_domains(name, DATA_BROKER_DOMAINS, per_domain_limit=2)
    authority_count, authority_hits = count_matches_on_domains(name, AUTHORITY_SITES_DIRECT + AUTHORITY_SITES_MEDIA, per_domain_limit=2)
    news_count, news_hits = count_matches_on_domains(name, NEWS_DOMAINS, per_domain_limit=2)

    # Optional general listings (uses provider chain; falls back to DDG-lite)
    general_results = provider_search(q_person, RESULTS_TO_FETCH)
    urls     = [r.get("link","") for r in general_results if r.get("link")]
    titles   = [r.get("title","") for r in general_results]
    snippets = [r.get("snippet","") for r in general_results]
    combined_snippets = " ".join(snippets)

    # 3) Low-confidence flag for general listings
    low_confidence = len(urls) < FALLBACK_MIN_RESULTS

    # 4) Build “Likely You” vs “Other” from general results
    likely_listings, other_listings = rank_listings_for_person(name, city, org, general_results)

    # 5) Signals
    sens = detect_sensitive_patterns(combined_snippets)
    neg  = sum(1 for t in titles if any(k in (t or "").lower() for k in NEGATIVE_KEYWORDS))

    # Compose signals needed for score buckets
    signals = {
        "data_brokers": broker_count,
        "authority_hits": authority_count,  # from deterministic scans
        "neg_headlines": news_count + neg,  # deterministic news + generic neg headlines
        "domains": [domain_from_url(u) for u in urls],
        "sensitive": sens,
        "breach_count": 0,
    }

    # 6) Subscores (explicit, simple & stable)
    subs = {}
    subs["Data Broker Exposure"]   = min(36, signals["data_brokers"] * 6)
    sens_points = signals["sensitive"]["phones"] + signals["sensitive"]["addresses"]
    subs["Sensitive Info Exposure"] = min(20, sens_points * 5)
    unique_domains = len(set(signals["domains"]))
    subs["Identity Drift"]         = 14 if unique_domains >= 10 else 10 if unique_domains >= 8 else 6 if unique_domains >= 5 else 3 if unique_domains >= 3 else 0
    auth = signals["authority_hits"]
    subs["Authority Deficit"]      = 30 if auth == 0 else 18 if auth == 1 else 10 if auth == 2 else 4 if auth == 3 else 0
    subs["Negative Press"]         = min(10, signals["neg_headlines"] * 3)
    subs["Breach Risk"]            = 0  # off by default

    raw_score = int(sum(subs.values()))

    # 7) Guardrails (bulletproof separation)
    is_celebrity = (wiki_flag or imdb_flag or wikidata_flag or kp_flag or auth >= 3 or news_count >= 2)

    # Base shield for celebs (they have authority; lower risk)
    shield = 0.6 if is_celebrity else 1.0
    adjusted = int(round(raw_score * shield))

    if is_celebrity:
        adjusted = min(adjusted, 12)
        adjusted = max(adjusted, 7)
    else:
        high_brokers   = subs["Data Broker Exposure"] >= 6
        weak_authority = subs["Authority Deficit"]   >= 18
        some_drift     = subs["Identity Drift"]      >= 6
        if weak_authority and high_brokers:
            adjusted = max(adjusted, 50)
        elif weak_authority and some_drift:
            adjusted = max(adjusted, 35)
        # exposure boost if many likely matches
        if len(likely_listings) >= 5:
            adjusted = min(100, adjusted + 5)

    lvl = risk_band(adjusted)
    conf_label = "low" if low_confidence else "normal"

    # 8) Save lead
    save_lead(name=name, email=email, score=str(adjusted), city=city, org=org, q=q_person, confidence=conf_label)

    # --------------------------
    # UI
    # --------------------------
    st.markdown("---")
    badge = " (low confidence)" if low_confidence else ""
    st.markdown(f"## Overall Risk: **{adjusted}/100** — {lvl}{badge}")
    st.progress(min(adjusted, 100) / 100)

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
    recs = []
    if subs["Data Broker Exposure"] >= 12: recs.append("Submit removal requests to top data brokers (Spokeo, BeenVerified, Whitepages, MyLife).")
    if subs["Sensitive Info Exposure"] >= 10: recs.append("Audit public posts & PDFs; remove phone/address; request cache removal where needed.")
    if subs["Authority Deficit"] >= 8: recs.append("Publish a canonical bio page with schema.org/Person; create/clean Wikidata; complete LinkedIn.")
    if subs["Identity Drift"] >= 6: recs.append("Standardize your name/headline across your site, LinkedIn, and press mentions.")
    if subs["Negative Press"] >= 6: recs.append("Publish counter-narratives on credible sites; pursue structured PR to add positive citations.")
    if not recs: recs.append("Maintain quarterly audits; set Google Alerts; keep canonical bio & schema updated.")
    for r in recs[:5]:
        st.write("• " + r)

    # Listings (from general provider chain)
    st.markdown("### Listings that appear to be about you")
    st.caption("These are public search results that likely reference your name. We do not display or store private information.")
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
        st.markdown(f"""
**[{safe_title}]({item['url']})**  
<span style="color:#6b7280">{html.escape(item['domain'])}</span> • score {item['score']}  
{safe_snip}  
<span style="color:#6b7280">{render_badges(item['tags'], item['reasons'])}</span>
""", unsafe_allow_html=True)

    if likely_listings:
        st.write(f"**Likely You** ({len(likely_listings)})")
        for it in likely_listings: render_listing(it)
    else:
        st.write("_No strong matches yet. Try adding a city or company to your query._")
    with st.expander("Other results (probably not you)"):
        if other_listings:
            for it in other_listings: render_listing(it)
        else:
            st.write("_None to show._")

    # CSV export
    csv_buf = StringIO()
    w = csv.writer(csv_buf)
    w.writerow(["bucket","score","title","url","domain","tags","reasons","snippet"])
    for it in likely_listings:
        w.writerow(["likely", it["score"], it["title"], it["url"], it["domain"], ";".join(it["tags"]), ";".join(it["reasons"]), it["snippet"]])
    for it in other_listings:
        w.writerow(["other", it["score"], it["title"], it["url"], it["domain"], ";".join(it["tags"]), ";".join(it["reasons"]), it["snippet"]])
    st.download_button("Download listings as CSV", data=csv_buf.getvalue(), file_name="veritia_listings.csv", mime="text/csv")

    # Debug
    with st.expander("What we checked (summary)"):
        st.write(f"- Data broker matches (site: scans): {broker_count}")
        st.write(f"- Authority matches (site: scans): {authority_count}")
        st.write(f"- News matches (site: scans): {news_count}")
        st.write(f"- Deterministic flags: Wikipedia={wiki_flag}, IMDb={imdb_flag}, Wikidata={wikidata_flag}, KnowledgePanel={kp_flag}")
        st.write(f"- General listings fetched: {len(urls)} (confidence: {('low' if low_confidence else 'normal')})")
        st.write(f"- Sensitive patterns (not shown): phones={sens['phones']} addresses={sens['addresses']} emails={sens['emails']}")

    with st.expander("Debug details"):
        st.write("Raw score:", raw_score, "| Adjusted:", adjusted, "| Band:", lvl)
        st.write("Subscores:", subs)
        st.write("Sample broker hits:", [h.get("link") for h in broker_hits[:5]])
        st.write("Sample authority hits:", [h.get("link") for h in authority_hits[:5]])
        st.write("Sample news hits:", [h.get("link") for h in news_hits[:5]])

