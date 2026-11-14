import os
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
    "freeway closed", "high water"
]
HIGH_KEYWORDS = [
    "ground delay", "severe thunderstorm", "flash flood", "outage", "cyberattack",
    "breach", "opec", "tanker", "strait of hormuz", "gulf coast", "ship channel",
    "emergency", "evacuation", "faa", "heavy truck", "multi-vehicle"
]

def load_seen():
    if os.path.exists(SEEN_FILE):
        with open(SEEN_FILE, "r") as f:
            return set(json.load(f))
    return set()

def save_seen(seen_set):
    trimmed = list(seen_set)[-500:]
    with open(SEEN_FILE, "w") as f:
        json.dump(trimmed, f, indent=2)

def classify_severity(text):
    text_lower = text.lower()
    if any(kw in text_lower for kw in CRITICAL_KEYWORDS):
        return "🔴 CRITICAL", 15158332
    elif any(kw in text_lower for kw in HIGH_KEYWORDS):
        return "🟠 HIGH", 15105570
    return "🔵 MONITOR", 3447003

def send_discord_alert(title, description, url, sector, severity_label, color):
    if not MAIN_WEBHOOK or not MAIN_WEBHOOK.startswith("http"):
        print("[ERROR] Missing or invalid WEBHOOK_MAIN secret.")
        return

    payload = {
        "username": "Overwatch Intel",  # <-- Change this to your favorite name!
        "embeds": [
            {
                "title": title[:250],
                "url": url if url else None,
                "description": description[:450] + ("..." if len(description) > 450 else ""),
                "color": color,
                "fields": [
                    {"name": "Severity", "value": severity_label, "inline": True},
                    {"name": "Sector", "value": sector, "inline": True}
                ],
                "footer": {"text": "Overwatch OSINT • Houston & DMV Desk"},
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        ]
    }
    res = requests.post(MAIN_WEBHOOK, json=payload)
    if res.status_code not in (200, 204):
        print(f"[ERROR] Webhook failed ({sector}): {res.status_code} - {res.text}")
    else:
        print(f"[DELIVERED] {sector}: {title}")
    time.sleep(1.5)

# 1. FAA NAS AIRSPACE (Houston + DMV + Major Hubs)
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
                        desc = f"**Airport:** {arpt}\n**Reason:** {reason}\n**Duration/Max:** {end_time}"
                        sev, col = classify_severity(f"{dtype_name} {reason}")
                        send_discord_alert(title, desc, "https://faa.gov", "Aviation / FAA", sev, col)
                        seen.add(alert_id)
    except Exception as e:
        print(f"[ERROR] FAA parser: {e}")

# 2. HOUSTON TRANSTAR MAJOR INCIDENTS (Filtered for high-impact closures/hazmat)
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
                title = f"TranStar Major Incident: {road} at {cross}"
                desc = f"**Type:** {inc_type}\n**Impact:** {lanes}\n**Status:** {status}"
                sev, col = classify_severity(blob)
                send_discord_alert(title, desc, "https://traffic.houstontranstar.org/", "Houston TranStar", sev, col)
                seen.add(alert_id)
    except Exception as e:
        print(f"[ERROR] TranStar parser: {e}")

# 3. RSS FEEDS (Houston, DMV, Energy, Cyber)
def check_rss_feeds(seen):
    feeds = [
        # CYBER
        {
            "url": "https://cisa.gov",
            "sector": "Cyber / CISA"
        },
        {
            "url": "https://bleepingcomputer.com",
            "sector": "Cyber / Threat Intel"
        },
        # ENERGY / OIL & GAS
        {
            "url": "https://oilprice.com",
            "sector": "Energy & Oil/Gas"
        },
        # HOUSTON WEATHER & LOCAL NEWS
        {
            "url": "https://weather.gov",
            "sector": "Houston / NWS Weather",
            "filter_keywords": ["Harris", "Chambers", "Galveston", "Brazoria", "Fort Bend", "Houston", "Baytown", "Ship Channel"]
        },
        {
            "url": "https://click2houston.com",
            "sector": "Houston Local News"
        },
        # DMV (DC / MARYLAND / VIRGINIA) NEWS & WEATHER
        {
            "url": "https://wtop.com",
            "sector": "DMV Local News"
        },
        {
            "url": "https://weather.gov",
            "sector": "DMV / NWS Weather"
        },
        {
            "url": "https://weather.gov",
            "sector": "DMV / NWS Weather",
            "filter_keywords": ["Montgomery", "Prince George", "Howard", "Anne Arundel", "Charles", "Frederick"]
        },
        {
            "url": "https://weather.gov",
            "sector": "DMV / NWS Weather",
            "filter_keywords": ["Fairfax", "Arlington", "Alexandria", "Loudoun", "Prince William"]
        }
    ]

    for feed_cfg in feeds:
        try:
            resp = requests.get(feed_cfg["url"], headers=HEADERS, timeout=15)
            parsed = feedparser.parse(resp.content)

            for entry in parsed.entries[:3]:
                alert_id = entry.get("id", entry.get("link"))
                if not alert_id or alert_id in seen:
                    continue

                title = entry.get("title", "Breaking Alert")
                summary = entry.get("summary", "No summary provided.")
                link = entry.get("link", "")

                if "filter_keywords" in feed_cfg:
                    blob = f"{title} {summary}".lower()
                    if not any(kw.lower() in blob for kw in feed_cfg["filter_keywords"]):
                        continue

                sev, col = classify_severity(f"{title} {summary}")
                send_discord_alert(
                    title=title,
                    description=summary,
                    url=link,
                    sector=feed_cfg["sector"],
                    severity_label=sev,
                    color=col
                )
                seen.add(alert_id)
        except Exception as e:
            print(f"[ERROR] Feed ({feed_cfg['sector']}): {e}")

if __name__ == "__main__":
    print("Starting GSOC Intelligence Cycle...")
    seen_alerts = load_seen()
    check_faa_nas(seen_alerts)
    check_houston_transtar(seen_alerts)
    check_rss_feeds(seen_alerts)
    save_seen(seen_alerts)
    print("Cycle complete.")
