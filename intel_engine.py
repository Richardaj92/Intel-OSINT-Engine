import os
import re
import html
import json
import time
import requests
import feedparser
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

SEEN_FILE = "seen_alerts.json"
MAIN_WEBHOOK = os.getenv("WEBHOOK_MAIN", "").strip()

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

CRITICAL_KEYWORDS = [
    "ground stop", "explosion", "refinery", "pipeline", "active shooter",
    "shelter in place", "hurricane", "tornado warning", "zero-day", "ransomware",
    "blackout", "grid failure", "chemical release", "hazmat", "all lanes blocked",
    "freeway closed", "high water", "missile", "airstrike", "state of emergency"
]

HIGH_KEYWORDS = [
    "ground delay", "severe thunderstorm", "flash flood", "outage", "cyberattack",
    "breach", "opec", "tanker", "strait of hormuz", "gulf coast", "ship channel",
    "emergency", "evacuation", "faa", "heavy truck", "shooting", "stabbing",
    "indictment", "sanctions", "vulnerability", "exploit"
]

NOISE_BLOCKLIST = [
    "astros", "texans", "rockets", "dynamo", "commanders", "capitals", "wizards",
    "nationals", "nfl", "nba", "mlb", "nhl", "touchdown", "playoffs", "rodeo",
    "celebrity", "kardashian", "movie review", "box office", "recipe", "horoscope",
    "best deals", "black friday", "cyber monday", "sponsored"
]


def load_seen():
    if os.path.exists(SEEN_FILE):
        with open(SEEN_FILE, "r") as f:
            return set(json.load(f))
    return set()


def save_seen(seen_set):
    trimmed = list(seen_set)[-600:]
    with open(SEEN_FILE, "w") as f:
        json.dump(trimmed, f, indent=2)


def clean_text(raw_text):
    if not raw_text:
        return "No summary provided."
    no_html = re.sub(r"<[^>]+>", " ", raw_text)
    decoded = html.unescape(no_html)
    cleaned = re.sub(r"\s+", " ", decoded).strip()
    return cleaned if cleaned else "No summary provided."


def is_noise(text):
    text_lower = text.lower()
    return any(bad in text_lower for bad in NOISE_BLOCKLIST)


def classify_severity(text):
    text_lower = text.lower()
    if any(kw in text_lower for kw in CRITICAL_KEYWORDS):
        return "🔴 CRITICAL", 15158332
    elif any(kw in text_lower for kw in HIGH_KEYWORDS):
        return "🟠 HIGH", 15105570
    return "🔵 MONITOR", 3447003


def send_discord_alert(title, description, url, sector, source_name, severity_label, color):
    if not MAIN_WEBHOOK or not MAIN_WEBHOOK.startswith("http"):
        print("[ERROR] Missing or invalid WEBHOOK_MAIN secret.")
        return

    clean_desc = clean_text(description)
    if len(clean_desc) > 420:
        clean_desc = clean_desc[:417] + "..."

    payload = {
        "username": "Overwatch Intel",
        "embeds": [
            {
                "title": clean_text(title)[:250],
                "url": url if url else None,
                "description": clean_desc,
                "color": color,
                "fields": [
                    {"name": "Severity", "value": severity_label, "inline": True},
                    {"name": "Sector", "value": sector, "inline": True},
                    {"name": "Source", "value": source_name, "inline": True}
                ],
                "footer": {"text": "Overwatch Intel • Verified OSINT"},
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        ]
    }
    res = requests.post(MAIN_WEBHOOK, json=payload)
    if res.status_code not in (200, 204):
        print(f"[ERROR] Webhook failed ({source_name}): {res.status_code} - {res.text}")
    else:
        print(f"[DELIVERED] [{source_name}] {title}")
    time.sleep(1.5)


def check_faa_nas(seen):
    target_airports = {"IAH", "HOU", "DCA", "IAD", "BWI", "DFW", "JFK", "LAX", "ORD", "ATL"}
    faa_url = "https://faa.gov"

    try:
        resp = requests.get(faa_url, headers=HEADERS, timeout=15)
        if resp.status_code != 200:
            return
        root = ET.fromstring(resp.content)

        for delay_type in root.findall(".//Delay_type"):
            dtype_name = delay_type.findtext("Name", "Airspace Delay")
            for ground in delay_type.findall(".//Ground_Delay") + delay_type.findall(".//Ground_Stop"):
                arpt = ground.findtext("ARPT", "")
                if arpt in target_airports:
                    reason = ground.findtext("Reason", "Unspecified operational impact")
                    end_time = ground.findtext("End_Time", ground.findtext("Max", "Active"))
                    alert_id = f"FAA-{arpt}-{dtype_name}-{reason}-{end_time}"

                    if alert_id not in seen:
                        title = f"FAA {dtype_name}: {arpt}"
                        desc = f"Airport: {arpt} | Reason: {reason} | Duration/Max: {end_time}"
                        sev, col = classify_severity(f"{dtype_name} {reason}")
                        send_discord_alert(
                            title=title,
                            description=desc,
                            url="https://faa.gov",
                            sector="Aviation",
                            source_name="FAA NAS",
                            severity_label=sev,
                            color=col
                        )
                        seen.add(alert_id)
    except Exception as e:
        print(f"[ERROR] FAA parser: {e}")


def check_houston_transtar(seen):
    transtar_url = "https://houstontranstar.org"
    major_triggers = ["hazmat", "heavy truck", "all lanes", "high water", "fire", "fatality", "overturned", "closure"]

    try:
        resp = requests.get(transtar_url, headers=HEADERS, timeout=15)
        if resp.status_code != 200:
            return
        root = ET.fromstring(resp.content)

        for inc in root.findall(".//Incident"):
            inc_id = inc.findtext("ID", "")
            road = inc.findtext("Roadway", "Houston Roadway")
            cross = inc.findtext("CrossStreet", "")
            inc_type = inc.findtext("Type", "Incident")
            lanes = inc.findtext("LanesAffected", "")
            status = inc.findtext("Status", "")

            if "cleared" in status.lower():
                continue

            blob = f"{inc_type} {lanes}".lower()
            if not any(t in blob for t in major_triggers):
                continue

            alert_id = f"TRANSTAR-{inc_id}-{lanes}"
            if alert_id not in seen:
                title = f"Major Incident: {road} at {cross}"
                desc = f"Type: {inc_type} | Impact: {lanes} | Status: {status}"
                sev, col = classify_severity(blob)
                send_discord_alert(
                    title=title,
                    description=desc,
                    url="https://houstontranstar.org",
                    sector="Houston Traffic",
                    source_name="Houston TranStar",
                    severity_label=sev,
                    color=col
                )
                seen.add(alert_id)
    except Exception as e:
        print(f"[ERROR] TranStar parser: {e}")


def check_rss_feeds(seen):
    feeds = [
        {
            "url": "https://google.com",
            "sector": "Global Breaking",
            "source": "Reuters",
            "limit": 3
        },
        {
            "url": "https://google.com",
            "sector": "Global Breaking",
            "source": "Associated Press",
            "limit": 3
        },
        {
            "url": "https://aljazeera.com",
            "sector": "Global Breaking",
            "source": "Al Jazeera",
            "limit": 3
        },
        {
            "url": "https://cisa.gov",
            "sector": "Cyber Intel",
            "source": "CISA",
            "limit": 3
        },
        {
            "url": "https://bleepingcomputer.com",
            "sector": "Cyber Intel",
            "source": "BleepingComputer",
            "limit": 3
        },
        {
            "url": "https://feedburner.com",
            "sector": "Cyber Intel",
            "source": "The Hacker News",
            "limit": 2
        },
        {
            "url": "https://oilprice.com",
            "sector": "Energy & Oil/Gas",
            "source": "OilPrice.com",
            "limit": 3
        },
        {
            "url": "https://khou.com",
            "sector": "Houston Local",
            "source": "KHOU 11",
            "limit": 3
        },
        {
            "url": "https://weather.gov",
            "sector": "Houston Weather",
            "source": "NWS Houston",
            "filter_keywords": ["Harris", "Chambers", "Galveston", "Brazoria", "Fort Bend", "Houston", "Baytown", "Ship Channel"],
            "limit": 5
        },
        {
            "url": "https://nbcwashington.com",
            "sector": "DMV Local",
            "source": "NBC4 Washington",
            "limit": 3
        },
        {
            "url": "https://weather.gov",
            "sector": "DMV Weather",
            "source": "NWS DC",
            "limit": 3
        },
        {
            "url": "https://weather.gov",
            "sector": "DMV Weather",
            "source": "NWS Maryland",
            "filter_keywords": ["Montgomery", "Prince George", "Howard", "Anne Arundel", "Charles", "Frederick"],
            "limit": 3
        },
        {
            "url": "https://weather.gov",
            "sector": "DMV Weather",
