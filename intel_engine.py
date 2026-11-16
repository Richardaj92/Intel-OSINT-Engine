import os
import json
import html
import re
from datetime import datetime, timezone

import feedparser
import requests

# ==========================
# OVERWATCH INTEL
# ==========================

WEBHOOK_URL = os.getenv("WEBHOOK_MAIN")
SEEN_FILE = "seen_alerts.json"

# ==========================
# FEEDS
# ==========================

FEEDS = [

    # CYBER INTEL

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

    # NEWS

    {
        "name": "AP News",
        "url": "https://feeds.apnews.com/rss/apf-topnews",
        "sector": "National News"
    },

    # TRAVEL

    {
        "name": "State Department",
        "url": "https://travel.state.gov/content/travel/en/traveladvisories/traveladvisories.rss.xml",
        "sector": "Travel Risk"
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
        "name": "DC Weather",
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

# ==========================
# SEVERITY
# ==========================

CRITICAL_KEYWORDS = [
    "active shooter",
    "ransomware",
    "zero-day",
    "active exploitation",
    "critical vulnerability",
    "explosion",
    "chemical release",
    "hurricane warning",
    "tornado warning",
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
    "hazmat",
    "road closure",
    "ground stop",
    "ground delay",
    "outage",
    "state of emergency"
]

# ==========================
# FILE FUNCTIONS
# ==========================

def load_seen():

    if os.path.exists(SEEN_FILE):

        try:

            with open(SEEN_FILE, "r") as f:
                return set(json.load(f))

        except Exception:
            pass

    return set()


def save_seen(seen):

    with open(SEEN_FILE, "w") as f:
        json.dump(list(seen), f, indent=2)

# ==========================
# CLEAN TEXT
# ==========================

def clean_text(text):

    if not text:
        return "No summary available."

    text = re.sub(r"<[^>]+>", " ", text)
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text)

    return text.strip()

# ==========================
# SEVERITY ENGINE
# ==========================

def classify_severity(text):

    text = text.lower()

    for keyword in CRITICAL_KEYWORDS:

        if keyword in text:
            return "🔴 CRITICAL", 15158332

    for keyword in HIGH_KEYWORDS:

        if keyword in text:
            return "🟠 HIGH", 15105570

    return "🔵 MONITOR", 3447003

# ==========================
# SOURCE LINKS
# ==========================

def determine_link(feed_info, entry):

    link = entry.get("link")

    if (
        link
        and isinstance(link, str)
        and link.startswith("http")
    ):
        return link

    if "weather.gov" in feed