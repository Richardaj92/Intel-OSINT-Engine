import os
import json
import feedparser
import requests
import html
import re
from datetime import datetime, timezone

WEBHOOK_URL = os.getenv("WEBHOOK_MAIN")

SEEN_FILE = "seen_alerts.json"

FEEDS = [

    # CYBER
    {
        "name": "CISA",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "sector": "Cyber Intel"
    },

    {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "sector": "Cyber Intel"
    },

    {
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "sector": "Cyber Intel"
    },

    # HOUSTON
    {
        "name": "ABC13 Houston",
        "url": "https://abc13.com/feed/",
        "sector": "Houston Local"
    },

    # WEATHER
    {
        "name": "Texas Weather Alerts",
        "url": "https://api.weather.gov/alerts/active.atom?area=TX",
        "sector": "Weather"
    },

    {
        "name": "Virginia Weather Alerts",
        "url": "https://api.weather.gov/alerts/active.atom?area=VA",
        "sector": "DMV Weather"
    },

    {
        "name": "Maryland Weather Alerts",
        "url": "https://api.weather.gov/alerts/active.atom?area=MD",
        "sector": "DMV Weather"
    },

    {
        "name": "Washington DC Weather Alerts",
        "url": "https://api.weather.gov/alerts/active.atom?area=DC",
        "sector": "DMV Weather"
    },

    # FEMA
    {
        "name": "FEMA",
        "url": "https://www.fema.gov/feeds/press-release.xml",
        "sector": "Emergency Management"
    },

    # ENERGY
    {
        "name": "EIA Energy News",
        "url": "https://www.eia.gov/rss/eia.xml",
        "sector": "Energy"
    }
]

CRITICAL_KEYWORDS = [
    "ransomware",
    "zero-day",
    "critical vulnerability",
    "active exploitation",
    "active shooter",
    "chemical release",
    "explosion",
    "tornado warning",
    "hurricane warning",
    "evacuation",
    "missile",
    "airstrike"
]

HIGH_KEYWORDS = [
    "cyberattack",
    "breach",
    "exploit",
    "vulnerability",
    "flash flood",
    "severe thunderstorm",
    "ground stop",
    "ground delay",
    "outage",
    "state of emergency",
    "hazmat",
    "all lanes blocked",
    "road closure"
]

def load_seen():
    if os.path.exists(SEEN_FILE):
        with open(SEEN_FILE, "r") as f:
            return set(json.load(f))
    return set()

def save_seen(seen):
    with open(SEEN_FILE, "w") as f:
        json.dump(list(seen), f, indent=2)

def clean_text(text):
    if not text:
        return "No summary available."

    text = re.sub(r"<[^>]+>", " ", text)
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text).strip()

    return text

def classify_severity(text):

    text = text.lower()

    if any(word in text for word in CRITICAL_KEYWORDS):
        return "🔴 CRITICAL", 15158332

    if any(word in text for word in HIGH_KEYWORDS):
        return "🟠 HIGH", 15105570

    return "🔵 MONITOR", 3447003

def send_alert(title, summary, link, sector, source):

    severity, color = classify_severity(
        f"{title} {summary}"
    )

    payload = {
        "username": "Overwatch Intel",
        "embeds": [
            {
                "title": f"🛰️ {title[:250]}",
                "url": link,
                "description": summary[:1000],
                "color": color,
                "fields": [
                    {
                        "name": "Severity",
                        "value": severity,
                        "inline": True
                    },
                    {
                        "name": "Sector",
                        "value": sector,
                        "inline": True
                    },
                    {
                        "name": "Source",
                        "value": source,
                        "inline": True
                    }
                ],
                "footer": {
                    "text": "Overwatch Intel • OSINT Monitoring"
                },
                "timestamp": datetime.now(
                    timezone.utc
                ).isoformat()
            }
        ]
    }

    response = requests.post(
        WEBHOOK_URL,
        json=payload,
        timeout=30
    )

    if response.status_code in [200, 204]:
        print(f"[SUCCESS] {source} - {title}")
    else:
        print(f"[ERROR] {response.status_code}")

def process_feed(feed_info, seen):

    try:

        feed = feedparser.parse(
            feed_info["url"]
        )

        for entry in feed.entries[:10]:

            article_id = (
                entry.get("id")
                or entry.get("link")
                or entry.get("title")
            )

            if article_id in seen:
                continue

            title = clean_text(
                entry.get("title", "Untitled")
            )

            summary = clean_text(
                entry.get(
                    "summary",
                    "No summary available."
                )
            )

            link = entry.get(
                "link",
                feed_info["url"]
            )

            send_alert(
                title=title,
                summary=summary,
                link=link,
                sector=feed_info["sector"],
                source=feed_info["name"]
            )

            seen.add(article_id)

    except Exception as e:
        print(
            f"[ERROR] {feed_info['name']} - {e}"
        )

def main():

    if not WEBHOOK_URL:
        print("WEBHOOK_MAIN not configured.")
        return

    seen = load_seen()

    for feed_info in FEEDS:
        process_feed(feed_info, seen)

    save_seen(seen)

    print("Overwatch Intel scan completed.")

if __name__ == "__main__":
    main()
