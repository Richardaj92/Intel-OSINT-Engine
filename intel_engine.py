import json
import os
import re
from datetime import datetime, timezone
from html import unescape
from urllib.parse import urljoin, urlparse

import feedparser
import requests
from dotenv import load_dotenv

load_dotenv()

WEBHOOK_URL = os.getenv("WEBHOOK_MAIN") or os.getenv("WEBHOOK_URL")

FEEDS = [
    {
        "name": "CISA Alerts",
        "url": "https://www.cisa.gov/uscert/ncas/alerts.xml",
        "sector": "Cybersecurity",
    },
    {
        "name": "Weather Alerts",
        "url": "https://alerts.weather.gov/cap/us.php?x=0",
        "sector": "Weather",
    },
    {
        "name": "FEMA News",
        "url": "https://www.fema.gov/news/feed",
        "sector": "Emergency Management",
    },
    {
        "name": "ABC13 Houston Local News",
        "url": "https://abc13.com/feed",
        "sector": "Harris County, Texas",
        "urgent_only": True,
    },
    {
        "name": "KHOU Houston Local News",
        "url": "https://www.khou.com/feeds/syndication/rss/news/local",
        "sector": "Harris County, Texas",
        "urgent_only": True,
    },
    {
        "name": "KPRC Houston Local News",
        "url": "https://www.click2houston.com/news/local/houston-news/?outputType=rss",
        "sector": "Harris County, Texas",
        "urgent_only": True,
    },
    {
        "name": "Montgomery County, MD Government News",
        "url": "https://www.montgomerycountymd.gov/news/rss.aspx",
        "sector": "Montgomery County, Maryland",
    },
    {
        "name": "Montgomery County, MD Police Releases",
        "url": "https://www2.montgomerycountymd.gov/mcgportalapps/press_RSS.aspx?dept=Police",
        "sector": "Montgomery County, Maryland",
    },
    {
        "name": "NPR Business",
        "url": "https://feeds.npr.org/1006/rss.xml",
        "sector": "National Business and Infrastructure",
        "urgent_only": True,
    },
    {
        "name": "NPR Technology",
        "url": "https://feeds.npr.org/1019/rss.xml",
        "sector": "National Technology and Cybersecurity",
        "urgent_only": True,
    },
    {
        "name": "CNBC U.S. Business News",
        "url": "https://www.cnbc.com/id/10001147/device/rss/rss.html",
        "sector": "National Business and Infrastructure",
        "urgent_only": True,
    },
    {
        "name": "CNBC Technology",
        "url": "https://www.cnbc.com/id/19854910/device/rss/rss.html",
        "sector": "National Technology and Cybersecurity",
        "urgent_only": True,
    },
    {
        "name": "CNBC Transportation",
        "url": "https://www.cnbc.com/id/19854912/device/rss/rss.html",
        "sector": "National Transportation",
        "urgent_only": True,
    },
    {
        "name": "AP Top Stories",
        "url": "https://flipboard.com/@associatedpress/top-stories-u7govdf1z.rss",
        "sector": "National Breaking News",
        "urgent_only": True,
    },
]

# National and local news feeds can be noisy. Forward stories that indicate
# significant disruption, safety events, severe weather, or cyber incidents.
URGENT_NEWS_TERMS = re.compile(
    r"\b(?:"
    r"outage|service\s+disruption|service\s+down|system\s+(?:failure|outage)|"
    r"app\s+(?:down|outage)|website\s+(?:down|outage)|online\s+(?:banking|service)\s+(?:down|outage)|"
    r"ground\s+stop|flights?\s+(?:grounded|cancelled|canceled)|flight\s+disruptions?|"
    r"widespread\s+(?:delays?|disruption|outage)|nationwide\s+(?:delays?|disruption|outage)|"
    r"evacuat(?:e|ion)|wildfire|hurricanes?|tornado(?:es)?|flash\s+floods?|"
    r"severe\s+(?:weather|thunderstorms?)|thunderstorms?|flood(?:ing|ed)?|"
    r"(?:weather|flood|flash\s+flood|hurricane|tornado|tropical\s+storm|winter\s+storm)\s+"
    r"(?:advisory|watch|warning)s?|tropical\s+storm|damaging\s+winds?|large\s+hail|"
    r"emergency|explosion|mass\s+shooting|active\s+shooter|critical\s+infrastructure|"
    r"cyberattack|cyber\s+attack|ransomware|data\s+breach|security\s+breach|"
    r"recall|boil\s+water|power\s+(?:failure|outage)|utility\s+outage|"
    r"earthquake|tsunami|hazmat|hazardous\s+materials|public\s+health\s+emergency"
    r")\b",
    re.IGNORECASE,
)

# Houston-area major highways. A story qualifies when it mentions an incident
# or disruption on I-10 or I-45; it does not need to use the word "outage."
MAJOR_HIGHWAY_TERMS = re.compile(
    r"\b(?:I\s*[- ]?\s*10|IH\s*[- ]?\s*10|Interstate\s+10|"
    r"I\s*[- ]?\s*45|IH\s*[- ]?\s*45|Interstate\s+45)\b",
    re.IGNORECASE,
)
ROAD_INCIDENT_TERMS = re.compile(
    r"\b(?:clos(?:e|ed|es|ing|ure|ures)|shut\s+down|blocked|"
    r"crash(?:es)?|accident(?:s)?|collision(?:s)?|overturned|"
    r"flood(?:ed|ing)|high\s+water|icy|ice|hazardous\s+conditions|"
    r"lane\s+closures?|ramps?\s+closed|traffic\s+diverted|major\s+delays?)\b",
    re.IGNORECASE,
)

# Forward public reporting of significant law-enforcement deployments without
# treating every routine police mention as urgent. SWAT deployments qualify
# with an operational action; other agencies require crime context as well.
LAW_ENFORCEMENT_AGENCIES = re.compile(
    r"\b(?:SWAT|FBI|Texas\s+Rangers?|police|sheriff(?:'s)?|deput(?:y|ies)|"
    r"law\s+enforcement|federal\s+agents?)\b",
    re.IGNORECASE,
)
POLICE_OPERATION_TERMS = re.compile(
    r"\b(?:dispatched|deployed|respond(?:ed|ing)|in\s+the\s+area|"
    r"on\s+scene|search(?:ing)?|manhunt|standoff|barricaded|"
    r"serv(?:ing|ed)\s+(?:a\s+)?(?:search\s+)?warrant|"
    r"execut(?:ing|ed)\s+(?:a\s+)?(?:search\s+)?warrant|"
    r"tactical\s+operation|law\s+enforcement\s+operation|"
    r"investigat(?:e|ing|ion)|assisting\s+(?:local\s+)?police|"
    r"asking\s+the\s+public\s+to\s+(?:avoid|stay\s+away))\b",
    re.IGNORECASE,
)
CRIMINAL_ACTIVITY_TERMS = re.compile(
    r"\b(?:criminal\s+activity|suspect|shooting|homicide|murder|robbery|"
    r"kidnap(?:ping|ped)|hostage|violent\s+crime|armed\s+and\s+dangerous|"
    r"assault|stabbing|burglary|terrorism|bomb\s+threat|drug\s+trafficking|"
    r"wanted\s+for|fugitive|crime\s+scene|officer\s+involved)\b",
    re.IGNORECASE,
)

# Extract image URLs from common RSS/Atom image fields or embedded entry HTML.
IMAGE_TAG_URL = re.compile(
    r"<img\b[^>]*?\b(?:src|data-src)\s*=\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)


def clean_text(value):
    if value is None:
        return ""

    if not isinstance(value, str):
        value = str(value)

    value = re.sub(r"<[^>]+>", " ", value)
    value = unescape(value)
    value = value.replace("\r", " ").replace("\n", " ")
    value = " ".join(value.split())
    return value.strip()


def is_urgent_news(title, summary):
    text = f"{title} {summary}"
    if URGENT_NEWS_TERMS.search(text):
        return True

    if MAJOR_HIGHWAY_TERMS.search(text) and ROAD_INCIDENT_TERMS.search(text):
        return True

    if LAW_ENFORCEMENT_AGENCIES.search(text) and POLICE_OPERATION_TERMS.search(text):
        is_swat_deployment = re.search(r"\bSWAT\b", text, re.IGNORECASE)
        if is_swat_deployment or CRIMINAL_ACTIVITY_TERMS.search(text):
            return True

    return False


def determine_link(feed_info, entry):
    # The NWS feed can expose machine-oriented alert/CAP URLs. Link readers
    # to the public-facing active alerts page instead.
    feed_url = (feed_info or {}).get("url", "").lower()
    feed_name = (feed_info or {}).get("name", "").lower()
    if "weather.gov" in feed_url or "weather" in feed_name:
        return "https://www.weather.gov/alerts"

    link = entry.get("link")
    if isinstance(link, str) and link.startswith("http"):
        return link

    if "cisa.gov" in feed_url:
        return "https://www.cisa.gov/"
    if "fema.gov" in feed_url:
        return "https://www.fema.gov/"

    return (feed_info or {}).get("url", "")


def _image_url(value, base_url):
    """Return an absolute HTTP(S) image URL, or None for invalid values."""
    if not isinstance(value, str):
        return None

    value = unescape(value.strip())
    if not value:
        return None

    absolute_url = urljoin(base_url or "", value)
    if urlparse(absolute_url).scheme.lower() not in {"http", "https"}:
        return None
    return absolute_url


def extract_thumbnail(entry):
    """Find an article thumbnail from common RSS/Atom image representations."""
    base_url = entry.get("link", "")
    candidates = []

    # Media RSS commonly provides media:thumbnail and media:content fields.
    for field in ("media_thumbnail", "media_content"):
        for media in entry.get(field, []) or []:
            if isinstance(media, dict):
                candidates.append(media.get("url"))

    # Standard RSS enclosures and Atom links can expose image media types.
    for enclosure in entry.get("enclosures", []) or []:
        if isinstance(enclosure, dict):
            media_type = str(enclosure.get("type", "")).lower()
            href = enclosure.get("href") or enclosure.get("url")
            if media_type.startswith("image/") or re.search(
                r"\.(?:png|jpe?g|gif|webp)(?:$|[?#])", str(href), re.IGNORECASE
            ):
                candidates.append(href)

    for item in entry.get("links", []) or []:
        if isinstance(item, dict):
            media_type = str(item.get("type", "")).lower()
            href = item.get("href")
            if media_type.startswith("image/") or item.get("rel") == "enclosure":
                candidates.append(href)

    # Some feeds only include the image inside the summary or content HTML.
    html_values = [entry.get("summary", ""), entry.get("description", "")]
    for content in entry.get("content", []) or []:
        if isinstance(content, dict):
            html_values.append(content.get("value", ""))
    for html_value in html_values:
        if isinstance(html_value, str):
            candidates.extend(IMAGE_TAG_URL.findall(html_value))

    for candidate in candidates:
        image_url = _image_url(candidate, base_url)
        if image_url:
            return image_url

    return None


def classify_severity(text):
    text = (text or "").lower()

    if any(keyword in text for keyword in [
        "evacuation",
        "fatal",
        "explosion",
        "fire",
        "emergency",
        "severe",
        "danger",
        "ground stop",
        "widespread outage",
        "nationwide outage",
        "cyberattack",
        "ransomware",
        "data breach",
        "hurricane",
        "flash flood",
        "severe thunderstorm",
        "swat",
        "standoff",
        "manhunt",
    ]):
        return "High", 0xFF0000

    if any(keyword in text for keyword in [
        "warning",
        "alert",
        "storm",
        "outage",
        "hazard",
        "power",
        "wind",
        "flood",
        "closed",
        "closure",
        "crash",
        "accident",
        "blocked",
        "police operation",
        "deployed",
        "dispatched",
    ]):
        return "Medium", 0xFF9900

    return "Low", 0x00AAFF


def load_seen():
    try:
        with open("seen_alerts.json", "r", encoding="utf-8") as file:
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return set()

    if isinstance(data, dict):
        return set(data.get("seen", []))

    if isinstance(data, list):
        return set(data)

    return set()


def save_seen(seen):
    with open("seen_alerts.json", "w", encoding="utf-8") as file:
        json.dump(sorted(seen), file, indent=2)


def send_alert(title, summary, link, sector, source, thumbnail_url=None):
    severity, color = classify_severity(f"{title} {summary}")
    summary = clean_text(summary)

    if len(summary) > 1000:
        summary = summary[:997] + "..."

    embed = {
        "title": f"🛰️ {title[:250]}",
        "url": link,
        "description": summary or "No summary available.",
        "color": color,
        "fields": [
            {"name": "Severity", "value": severity, "inline": True},
            {"name": "Sector", "value": sector, "inline": True},
            {"name": "Source", "value": source, "inline": True},
        ],
        "footer": {"text": "Overwatch Intel • OSINT Monitoring"},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if thumbnail_url:
        embed["thumbnail"] = {"url": thumbnail_url}

    payload = {
        "username": "Overwatch Intel",
        "embeds": [embed],
    }

    try:
        response = requests.post(WEBHOOK_URL, json=payload, timeout=30)

        if response.status_code in [200, 204]:
            print(f"[SUCCESS] {source}: {title}")
        else:
            print(f"[ERROR] Discord returned {response.status_code} for {source}")
            print(response.text[:500])

    except Exception as exc:
        print(f"[WEBHOOK ERROR] {exc}")


def process_feed(feed_info, seen):
    feed_name = feed_info.get("name", "Unknown Feed")
    try:
        feed_url = feed_info.get("url")
        print(f"[CHECKING] {feed_name} -> {feed_url}")

        feed = feedparser.parse(feed_url)
        print(f"[DEBUG] {feed_name}: found {len(feed.entries)} entries")

        for entry in feed.entries[:10]:
            article_id = entry.get("id") or entry.get("link") or entry.get("title")
            if not article_id:
                continue

            article_id = str(article_id)
            if article_id in seen:
                continue

            title = clean_text(entry.get("title", "Untitled Alert"))

            raw_summary = entry.get("summary")
            if not raw_summary and entry.get("description"):
                raw_summary = entry.get("description")
            if not raw_summary:
                summary_detail = entry.get("summary_detail") or {}
                raw_summary = summary_detail.get("value") or "No summary available."

            summary = clean_text(raw_summary)
            if feed_info.get("urgent_only") and not is_urgent_news(title, summary):
                print(f"[SKIP] Non-urgent story from {feed_name}: {title}")
                continue

            link = determine_link(feed_info, entry)
            thumbnail_url = extract_thumbnail(entry)

            send_alert(
                title=title,
                summary=summary,
                link=link,
                sector=feed_info["sector"],
                source=feed_name,
                thumbnail_url=thumbnail_url,
            )

            seen.add(article_id)

    except Exception as exc:
        print(f"[FEED ERROR] {feed_name} -> {exc}")


def main():
    print("===== OVERWATCH INTEL =====")

    if not WEBHOOK_URL:
        print("WEBHOOK_MAIN secret missing.")
        return

    seen = load_seen()

    for feed in FEEDS:
        process_feed(feed, seen)

    save_seen(seen)
    print(f"Scan completed @ {datetime.now()}")


if __name__ == "__main__":
    main()
