# Overwatch Intel

Overwatch Intel is an informational monitoring project that collects selected public RSS feeds, filters for potentially significant events, and sends alert summaries to a Discord webhook.

## Project goals

This project was created for professional development: to strengthen practical skills in open-source intelligence (OSINT) collection, workflow automation, information filtering, and event/threat monitoring. It is also an opportunity to explore how public reporting can be organized into a concise, useful alert feed.

## Monitoring focus

Configured sources and filters may surface reports related to:

- National business, technology, and significant service outages
- Severe weather and emergency advisories
- Houston-area incidents, including major I-10 and I-45 closures or disruptions
- Selected law-enforcement operations reported by monitored sources
- Cybersecurity and infrastructure alerts from public sources

Coverage depends on the feeds configured in `intel_engine.py` and the terms used by the filters. The project does not independently verify every report.

## How it works

The Python script checks configured RSS feeds, filters new entries, and posts matching summaries to a Discord webhook. Previously processed entries are tracked in `seen_alerts.json` to avoid repeat notifications.

## Setup

1. Install the dependencies listed by the project.
2. Set `WEBHOOK_MAIN` or `WEBHOOK_URL` to your Discord webhook URL.
3. Run `intel_engine.py`.

Keep webhook URLs and other credentials private. Never commit secrets to the repository.

## Disclaimer

Overwatch Intel is for informational and educational purposes only. Alerts rely on third-party sources and automated keyword filters, so they may be delayed, incomplete, inaccurate, or miss relevant events. This project is not an emergency notification service, and an alert should not be treated as confirmation of an event. For urgent situations, follow official information and instructions from emergency services, transportation agencies, and weather authorities.

## Maintainer

Created and maintained by **Richard Juarez**.
