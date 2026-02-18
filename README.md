# reddit-monitor - Reddit Monitoring & Reply Tool
# Flask Web App mit Reddit-Scraping, Slack-Integration und Voice-Reply

## Features:
- 🔍 Reddit-Monitoring (9-17 Uhr, alle 10-15 Minuten)
- 🎯 Filter nach Guardrails (Keywords, Flair, Upvotes)
- 📱 Web-Oberfläche zur Konfiguration
- 🗣️ Voice-to-Text für Slack-Replies (Whisper)
- 🤖 Automatische Reddit-Kommentare
- 📊 Slack-Integration mit Webhooks

## Tech Stack:
- Python 3.9+ mit Flask
- Playwright für Headless-Browser
- Slack SDK für Webhooks
- Whisper CLI für Voice-Transkription
- SQLite für User-Daten
- Bootstrap für Web-UI

## Installation:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Konfiguration:
1. Web-Server starten: `python run.py`
2. Browser öffnen: `http://localhost:5000`
3. Reddit-Account hinterlegen
4. Subreddits konfigurieren
5. Guardrails definieren
6. Slack-Integration einrichten

## Projekt-Struktur:
- `app/` - Core-Logik
- `web/` - Flask-Webserver
- `data/` - Konfiguration & Logs
- `tests/` - Unit-Tests

## Lizenz: MIT