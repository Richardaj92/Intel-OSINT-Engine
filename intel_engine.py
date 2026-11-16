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

    if "weather.gov" in feed_info["url"]:
        return "https://www.weather.gov/"

    if "cisa.gov" in feed_info["url"]:
        return "https://www.cisa.gov/"

    if "fema.gov" in feed_info["url"]:
        return "https://www.fema.gov/"

    return feed_info["url"]


# ==========================
# DISCORD ALERT
# ==========================

def send_alert(title, summary, link, sector, source):

    severity, color = classify_severity(
        f"{title} {summary}"
    )

    summary = clean_text(summary)

    if len(summary) > 1000:
        summary = summary[:997] + "..."

    payload = {
        "username": "Overwatch Intel",

        "embeds": [
            {
                "title": f"🛰️ {title[:250]}",
                "url": link,
                "description": summary,
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

    try:

        response = requests.post(
            WEBHOOK_URL,
            json=payload,
            timeout=30
        )

        if response.status_code in [200, 204]:
            print(f"[SUCCESS] {source}: {title}")

        else:
            print(
                f"[ERROR] Discord returned "
                f"{response.status_code}"
            )

    except Exception as e:

        print(
            f"[WEBHOOK ERROR] {e}"
        )


# ==========================
# FEED PROCESSING
# ==========================

def process_feed(feed_info, seen):

    try:

        print(f"[CHECKING] {feed_info['name']}")

        feed = feedparser.parse(
            feed_info["url"]
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
                entry.get(
                    "title",
                    "Untitled Alert"
                )
            )

            summary = clean_text(
                entry.get(
                    "summary",
                    "No summary available."
                )
            )

            link = determine_link(
                feed_info,
                entry
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
            f"[FEED ERROR] "
            f"{feed_info['name']} -> {e}"
        )


# ==========================
# MAIN
# ==========================

def main():

    print("===== OVERWATCH INTEL =====")

    if not WEBHOOK_URL:

        print(
            "WEBHOOK_MAIN secret missing."
        )

        return

    seen = load_seen()

    for feed in FEEDS:

        process_feed(
            feed,
            seen
        )

    save_seen(seen)

    print(
        f"Scan completed @ "
        f"{datetime.now()}"
    )


if __name__ == "__main__":
    main()