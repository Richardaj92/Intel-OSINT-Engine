import os
import json
import feedparser
import requests
from datetime import datetime

WEBHOOK_URL = os.getenv("WEBHOOK_MAIN")

SEEN_FILE = "seen_alerts.json"

FEEDS = [
    {
        "name": "CISA",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "sector": "Cyber Intel"
    },
    {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "sector": "Cyber Intel"
    }
]

def load_seen():
    if os.path.exists(SEEN_FILE):
        with open(SEEN_FILE, "r") as f:
            return set(json.load(f))
    return set()

def save_seen(seen):
    with open(SEEN_FILE, "w") as f:
        json.dump(list(seen), f)

def classify_severity(text):
    text = text.lower()

    critical = [
        "ransomware",
        "zero-day",
        "critical vulnerability",
        "active exploitation"
    ]

    high = [
        "cyberattack",
        "breach",
        "exploit",
        "vulnerability"
    ]

    if any(word in text for word in critical):
        return "🔴 CRITICAL", 15158332

    if any(word in text for word in high):
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
                "title": title[:250],
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
                "timestamp": datetime.utcnow().isoformat()
            }
        ]
    }

    r = requests.post(WEBHOOK_URL, json=payload)

    if r.status_code in [200, 204]:
        print(f"[SUCCESS] {title}")
    else:
        print(f"[ERROR] {r.status_code}")

def main():
    seen = load_seen()

    for feed_info in FEEDS:
        feed = feedparser.parse(feed_info["url"])

        for entry in feed.entries[:5]:
            article_id = entry.get("id") or entry.get("link")

            if article_id in seen:
                continue

            title = entry.get("title", "Untitled")

            summary = entry.get(
                "summary",
                "No summary available."
            )

            link = entry.get("link", "")

            send_alert(
                title=title,
                summary=summary,
                link=link,
                sector=feed_info["sector"],
                source=feed_info["name"]
            )

            seen.add(article_id)

    save_seen(seen)

if __name__ == "__main__":
    main()
