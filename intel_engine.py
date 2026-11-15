import os
import json
import html
import re
from datetime import datetime, timezone

import feedparser
import requests

WEBHOOK_URL = os.getenv("WEBHOOK_MAIN")
SEEN_FILE = "seen_alerts.json"

# =========================
# OVERWATCH INTEL FEEDS
# =========================

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

    # WEATHER
    {
        "name": "Texas Weather",
        "url": "https://api.weather.gov/alerts/active.atom?area=TX",
        "sector": "Weather"
    },

    {
        "name": "Virginia Weather",
        "url": "https://api.weather.gov/alerts/active.atom?area=VA",
        "sector": "DMV Weather"
    },

    {
        "name": "Maryland Weather",
        "url": "https://api.weather.gov/alerts/active.atom?area=MD",
        "sector": "DMV Weather"
    },

    {
        "name": "Washington DC Weather",
        "url": "https://api.weather.gov/alerts/active.atom?area=DC",
        "sector": "DMV Weather"
    },

    # FEMA
    {
        "name": "FEMA",
        "url": "https://www.fema.gov/feeds/press-release.xml",
        "sector": "Emergency Management"
    }
]

# =========================
# SEVERITY
# =========================

CRITICAL_KEYWORDS = [
    "ransomware",
    "zero-day",
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
    "road closure"
]


# =========================
# UTILITIES
# =========================

def load_seen():
    if os.path.exists(SEEN_FILE):
        try:
            with open(SEEN_FILE, "r") as f:
                return set(json.load(f))
        except:
            pass

    return set()


def save_seen(seen):
    with open(SEEN_FILE, "w") as f:
        json.dump(list(seen), f, indent=2)


def clean_text(text):

    if not text:
        return "No summary available."

    text = re.sub(r"<[^>]+>", " ", text)
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text)

    return text.strip()


def classify_severity(text):

    text = text.lower()

    for keyword in CRITICAL_KEYWORDS:
        if keyword in text:
            return "🔴 CRITICAL", 15158332

    for keyword in HIGH_KEYWORDS:
        if keyword in text:
            return "🟠 HIGH", 15105570

    return "🔵 MONITOR", 3447003


# =========================
# DISCORD
# =========================

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
        print(
            f"[SUCCESS] {source}: {title}"
        )
    else:
        print(
            f"[ERROR] {response.status_code}"
        )


# =========================
# FEED PROCESSOR
# =========================

def process_feed(feed_info, seen):

    try:

        feed = feedparser.parse(
            feed_info["url"]
        )

        print(
            f"[CHECKING] {feed_info['name']}"
        )

        for entry in feed.entries[:10]:

            article_id = (
                entry.get("id")
                or entry.get("link")
                or entry.get("title")
            )

            if not article_id:
                continue

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

            link = entry.get("link")

            if (
                not link
                or not isinstance(link, str)
                or not link.startswith("http")
            ):
                link = feed_info["url"]

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
            f"[ERROR] {feed_info['name']} -> {e}"
        )


# =========================
# MAIN
# =========================

def main():

    if not WEBHOOK_URL:

        print(
            "WEBHOOK_MAIN environment variable missing."
        )

        return

    seen = load_seen()

    for feed_info in FEEDS:
        process_feed(feed_info, seen)

    save_seen(seen)

    print(
        f"Overwatch Intel completed scan @ "
        f"{datetime.now()}"
    )


if __name__ == "__main__":
    main()
