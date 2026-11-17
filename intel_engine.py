import json
import os
import re
from datetime import datetime, timezone
from html import unescape

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

# News feeds can be noisy. Only forward stories that indicate a significant
# disruption, safety event, severe weather, or cybersecurity incident.
URGENT_NEWS_TERMS = re.compile(
    r"\b(?:"
    r"outage|service\s+disruption|service\s+down|system\s+(?:failure|outage)|"
    r"app\s+(?:down|outage)|website\s+(?:down|outage)|online\s+(?:banking|service)\s+(?:down|outage)|"
    r"ground\s+stop|flights?\s+(?:grounded|cancelled|canceled)|flight\s+disruptions?|"
    r"widespread\s+(?:delays?|disruption|outage)|nationwide\s+(?:delays?|disruption|outage)|"
    r"evacuat(?:e|ion)|wildfire|hurricane|tornado|flash\s+flood|severe\s+weather|"
    r"emergency|explosion|mass\s+shooting|active\s+shooter|critical\s+infrastructure|"
    r"cyberattack|cyber\s+attack|ransomware|data\s+breach|security\s+breach|"
    r"recall|boil\s+water|power\s+(?:failure|outage)|utility\s+outage|"
    r"earthquake|tsunami|hazmat|hazardous\s+materials|public\s+health\s+emergency"
    r")\b",
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


def send_alert(title, summary, link, sector, source):
    severity, color = classify_severity(f"{title} {summary}")
    summary = clean_text(summary)

    if len(summary) > 1000:
        summary = summary[:997] + "..."

    payload = {
        "username": "Overwatch Intel",
        "embeds": [{
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
        }],
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
            if feed_info.get("urgent_only") and not URGENT_NEWS_TERMS.search(f"{title} {summary}"):
                print(f"[SKIP] Non-urgent story from {feed_name}: {title}")
                continue

            link = determine_link(feed_info, entry)

            send_alert(
                title=title,
                summary=summary,
                link=link,
                sector=feed_info["sector"],
                source=feed_name,
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
