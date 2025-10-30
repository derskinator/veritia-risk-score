# app.py
# Veritia.ai — Name Risk Score (Stable on Streamlit) ✅
# ----------------------------------------------------
# • Works great with SerpAPI or Bing keys (recommended)
# • Still runs without paid keys (falls back to DDG-lite where possible)
# • Avoids Streamlit Cloud timeouts by letting you DISABLE scraping with a secret
# • Pulls real listings, buckets “Likely You”, enforces celeb vs non-celeb guardrails

import os, re, csv, time, html, textwrap
from io import StringIO
from typing import List, Dict, Tuple
from urllib.parse import urlparse

import requests
import streamlit as st
from bs4 import BeautifulSoup

# =========================
# PAGE
# =========================
st.set_page_config(page_title="Veritia — Name Risk Score", page_icon="👁️", layout="centered")
st.markdown(
    "<h1 style='text-align:center;margin-bottom:0;'>Veritia.ai — Name Risk Score</h1>"
    "<p style='text-align:center;color:#8a8f98;margin-top:4px;'>See what AI & search can infer about you — and how to fix it.</p>",
    unsafe_allow_html=True,
)

# =========================
# SECRETS / SETTINGS
# =========================
SEARCH_PROVIDER = (st.secrets.get("apis", {}).get("SEARCH_PROVIDER", "serpapi") or "serpapi").lower()  # serpapi|bing|ddg_lite
SERPAPI_KEY     = st.secrets.get("apis", {}).get("SERPAPI_KEY", "")
BING_KEY        = st.secrets.get("apis", {}).get("BING_KEY", "")

RESULTS_TO_FETCH = int(st.secrets.get("app", {}).get("RESULTS_TO_FETCH", 18))
FALLBACK_MIN_RESULTS = 3

# IMPORTANT: To avoid Streamlit Cloud egress timeouts, you can disable site: scans.
# Set in Secrets:
# [app]
# SITE_SCAN_MODE = "none"   # "none" (no DDG scraping) | "auto" (try DDG site: scans)
SITE_SCAN_MODE = (st.secrets.get("app", {}).get("SITE_SCAN_MODE", "none")).lower()

USE_SHEETS = bool(st.secrets.get("gcp_service_account")) and bool(st.secrets.get("leads"))
CSV_FALLBACK_PATH = "leads.csv"

# =========================
# CONSTANTS
# =========================
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

# Provider cache (for knowledge panel)
serpapi_last_raw = None

# =========================
# UTIL / PROVIDERS
# =========================
def domain_from_url(u: str) -> str:
    try:
        d = urlparse(u).netloc.lower()
        return d[4:] if d.startswith("www.") else d
    except Exception:
        return ""

def ddg_lite_search(query: str, n: int) -> List[Dict]:
    """DuckDuckGo Lite HTML fallback (may timeout on Streamlit Cloud)."""
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
        st.warning("SerpAPI key missing; skipping SerpAPI search.")
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
        st.warning("Bing key missing; skipping Bing search.")
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
    """
    Reliable listings getter:
      1) Use configured provider if possible
      2) Fallback chain: serpapi -> bing -> ddg_lite
    """
    order = []
    if SEARCH_PROVIDER in ("serpapi","bing","ddg_lite"):
        order.append(SEARCH_PROVIDER)
    for p in ("serpapi","bing","ddg_lite"):
        if p not in order:
            order.append(p)

    for prov in order:
        if prov == "serpapi":
            res = serpapi_google(query, n)
        elif prov == "bing":
            res = bing_search(query, n)
        else:
            if SITE_SCAN_MODE == "none":
                # In no-scrape mode, skip ddg_lite entirely to avoid timeouts
                continue
            res = ddg_lite_search(query, n)
        if res:
            return res[:n]
    return []

# =========================
# DETERMINISTIC CELEBRITY CHECKS
# =========================
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

# =========================
# OPTIONAL SITE: SCANS (use only if SITE_SCAN_MODE="auto")
# =========================
def ddg_site_scan_exact(name: str, domain: str, limit: int = 5) -> List[Dict]:
    q = f'site:{domain} "{name}"'
    return ddg_lite_search(q, limit)

def count_matches_on_domains(name: str, domains: List[str], per_domain_limit=3) -> Tuple[int, List[Dict]]:
    total = 0
    hits: List[Dict] = []
    for d in domains:
        res = ddg_site_scan_exact(name, d, per_domain_limit)
        for r in res:
            text = (r.get("title","") + " " + r.get("snippet","")).lower()
            if re.search(rf'\b{re.escape(name.lower())}\b', text):
                total += 1
                hits.append(r)
    return total, hits

def estimate_counts_from_urls(urls: list) -> dict:
    """Fallback when site: scans are disabled/unreachable — estimate from general listings' domains."""
    def dom(u):
        try:
            d = urlparse(u).netloc.lower()
            return d[4:] if d.startswith("www.") else d
        except Exception:
            return ""
    domains = [dom(u) for u in urls]
    broker_count = sum(any(b in d for b in DATA_BROKER_DOMAINS) for d in domains)
    authority_count = 0
    for d in domains:
        if not d: continue
        if d.endswith(".gov") or d.endswith(".edu"):
            authority_count += 1
        elif any(d.endswith(a) for a in AUTHORITY_SITES_DIRECT):
            authority_count += 1
        elif any(m in d for m in AUTHORITY_SITES_MEDIA):
            authority_count += 1
    news_count = sum(any(n in d for n in NEWS_DOMAINS) for d in domains)
    return {"broker": broker_count, "authority": authority_count, "news": news_count}

# =========================
# SIGNALS / SCORING
# =========================
def detect_sensitive_patterns(text: str) -> Dict[str, int]:
    phone = len(re.findall(r"\b(?:\+?\d{1,2}\s*)?(?:\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4})\b", text))
    address = len(re.findall(r"\b\d{1,5}\s+\w+(?:\s+\w+)?\s+(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Lane|Ln|Dr|Drive|Ct|Court)\b", text, flags=re.I))
    email = len(re.findall(r"[\w\.-]+@[\w\.-]+\.\w+", text))
    return {"phones": phone, "addresses": address, "emails": email}

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
    return bool(re.search(rf"\b{re.escape(phrase.strip())}\b", text, flags=re.I))

def contains_all_tokens(tokens, text: str) -> bool:
    if not tokens or not text: return False
    low = text.lower()
    return all(t.lower() in low for t in tokens)

def classify_domain(url: str):
    d = domain_from_url(url)
    tags = []
    if any(db in d for db in DATA_BROKER_DOMAINS): tags.append("broker")
    if any(dom in d for d in AUTHORITY_SITES_MEDIA) or any(d.endswith(auth) for auth in AUTHORITY_SITES_DIRECT) or d.endswith(".gov") or d.endswith(".edu"):
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

# =========================
# LEADS
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

# =========================
# FORM
# =========================
with st.form("risk_form"):
    name = st.text_input("Full name*", placeholder="e.g., Keanu Reeves")
    city = st.text_input("City / Region (optional)")
    org  = st.text_input("Company / Role (optional)")
    email = st.text_input("Email to receive your report*", placeholder="you@domain.com")
    agree = st.checkbox("I understand this analyzes public results only and will not display/store sensitive personal data.")
    consent = st.checkbox("I agree to receive my results and follow-up by email.")
    submitted = st.form_submit_button("Get My Risk Score")

st.caption(f"Search provider preference: **{SEARCH_PROVIDER}** • Site scans: **{SITE_SCAN_MODE}**")

# =========================
# RUN
# =========================
if submitted:
    if not (name and email and agree and consent):
        st.error("Please complete name, email, and both checkboxes.")
        st.stop()

    q_person = " ".join([x for x in [name, city, org] if x]).strip()
    st.info(f"Scanning public results for: **{q_person}**")

    # A) Deterministic celebrity flags (do NOT depend on paid APIs)
    wiki_flag     = wikipedia_exact_person(name)
    imdb_flag     = imdb_has_name_hit(name)
    wikidata_flag = wikidata_is_notable_person(name)
    kp_flag       = serpapi_has_knowledge_panel()  # true only if SerpAPI search ran earlier in this session

    # B) General listings (used for UI + estimation + buckets)
    general_results = provider_search(q_person, RESULTS_TO_FETCH)
    urls     = [r.get("link","") for r in general_results if r.get("link")]
    titles   = [r.get("title","") for r in general_results]
    snippets = [r.get("snippet","") for r in general_results]
    low_confidence = len(urls) < FALLBACK_MIN_RESULTS

    # C) Exposure discovery
    if SITE_SCAN_MODE == "auto":
        # Try site: scans (may timeout on Streamlit Cloud; warnings will show if so)
        broker_count,   _broker_hits   = count_matches_on_domains(name, DATA_BROKER_DOMAINS, per_domain_limit=2)
        authority_count, _auth_hits    = count_matches_on_domains(name, AUTHORITY_SITES_DIRECT + AUTHORITY_SITES_MEDIA, per_domain_limit=2)
        news_count,     _news_hits     = count_matches_on_domains(name, NEWS_DOMAINS, per_domain_limit=2)
        # If all three came back zero and we have listings, fall back to estimates
        if broker_count == 0 and authority_count == 0 and news_count == 0 and urls:
            est = estimate_counts_from_urls(urls)
            broker_count, authority_count, news_count = est["broker"], est["authority"], est["news"]
    else:
        # “none” — no scraping; estimate from general listings only
        est = estimate_counts_from_urls(urls)
        broker_count, authority_count, news_count = est["broker"], est["authority"], est["news"]

    # D) Build “Likely You” vs “Other”
    likely_listings, other_listings = rank_listings_for_person(name, city, org, general_results)

    # E) Signals
    combined_snippets = " ".join(snippets)
    sens  = detect_sensitive_patterns(combined_snippets)
    neg_h = sum(1 for t in titles if any(k in (t or "").lower() for k in NEGATIVE_KEYWORDS))

    # Compose subscores
    subs = {}
    subs["Data Broker Exposure"]    = min(36, broker_count * 6)
    sens_points = sens["phones"] + sens["addresses"]
    subs["Sensitive Info Exposure"] = min(20, sens_points * 5)
    unique_domains = len(set(domain_from_url(u) for u in urls))
    subs["Identity Drift"]          = 14 if unique_domains >= 10 else 10 if unique_domains >= 8 else 6 if unique_domains >= 5 else 3 if unique_domains >= 3 else 0
    subs["Authority Deficit"]       = 30 if authority_count == 0 else 18 if authority_count == 1 else 10 if authority_count == 2 else 4 if authority_count == 3 else 0
    subs["Negative Press"]          = min(10, (news_count + neg_h) * 3)
    subs["Breach Risk"]             = 0  # off by default

    raw_score = int(sum(subs.values()))

    # F) Guardrails: hard separation (celebs must score low)
    is_celebrity = (wiki_flag or imdb_flag or wikidata_flag or kp_flag or authority_count >= 3 or news_count >= 2)
    # Base shield (celebs get more authority protection)
    shield = 0.6 if is_celebrity else 1.0
    adjusted = int(round(raw_score * shield))

    if is_celebrity:
        adjusted = min(adjusted, 12)
        adjusted = max(adjusted, 7)   # never zero
    else:
        high_brokers   = subs["Data Broker Exposure"] >= 6
        weak_authority = subs["Authority Deficit"]   >= 18
        some_drift     = subs["Identity Drift"]      >= 6
        if weak_authority and high_brokers:
            adjusted = max(adjusted, 50)
        elif weak_authority and some_drift:
            adjusted = max(adjusted, 35)
        if len(likely_listings) >= 5:
            adjusted = min(100, adjusted + 5)

    lvl = risk_band(adjusted)

    # G) Save lead
    conf_label = "low" if low_confidence else "normal"
    save_lead(name=name, email=email, score=str(adjusted), city=city, org=org, q=q_person, confidence=conf_label)

    # =========================
    # UI
    # =========================
    st.markdown("---")
    st.markdown(f"## Overall Risk: **{adjusted}/100** — {lvl}{' (low confidence)' if low_confidence else ''}")
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
    for r in recs[:5]: st.write("• " + r)

    # Listings
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
        st.write(f"- Deterministic flags: Wikipedia={wiki_flag}, IMDb={imdb_flag}, Wikidata={wikidata_flag}, KnowledgePanel={kp_flag}")
        st.write(f"- General listings fetched: {len(urls)} (confidence: {conf_label})")
        st.write(f"- Estimated/Scanned counts — Brokers: {broker_count}, Authority: {authority_count}, News: {news_count}")
        st.write(f"- Sensitive patterns (not shown): phones={sens['phones']} addresses={sens['addresses']} emails={sens['emails']}")
        st.write(f"- Raw score: {raw_score} → Adjusted: {adjusted} ({lvl})")

