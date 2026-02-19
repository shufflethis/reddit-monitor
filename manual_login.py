"""
Manual Reddit login helper.
Opens a visible browser - log in manually, cookies get saved automatically.
After login, upvotes/comments work without captcha.
"""
import json
import time
from pathlib import Path
from patchright.sync_api import sync_playwright

DATA_DIR = Path("data")
COOKIES_FILE = DATA_DIR / "reddit_cookies.json"
BROWSER_PROFILE_DIR = str(DATA_DIR / "reddit_browser_profile")

print("Opening browser... log dich bei Reddit ein!")
print("Nach dem Login warte ich 10 Sekunden und speichere die Cookies.")
print()

with sync_playwright() as pw:
    ctx = pw.chromium.launch_persistent_context(
        BROWSER_PROFILE_DIR,
        headless=False,
        viewport={"width": 1280, "height": 900},
        locale="de-DE",
        args=[
            "--disable-blink-features=AutomationControlled",
            "--no-first-run",
            "--no-default-browser-check",
        ],
    )
    page = ctx.pages[0] if ctx.pages else ctx.new_page()
    # old.reddit.com hat oft keinen Captcha-Gate
    page.goto("https://old.reddit.com/login", timeout=30000)

    print(">>> Browser ist offen. Bitte einloggen!")
    print(">>> Warte bis Login erkannt wird (max 5 Minuten)...")

    # Wait until redirected away from login page or cookies appear
    for i in range(600):  # 10 minutes max
        time.sleep(1)
        try:
            url = page.url
        except Exception:
            print("Browser wurde geschlossen.")
            break
        if "/login" not in url and "reddit.com" in url:
            print(f"Login erkannt! URL: {url}")
            time.sleep(3)  # wait a bit for cookies to settle
            break
        if i % 30 == 0 and i > 0:
            print(f"  ... warte noch ({i}s) - aktuelle URL: {url}")
    else:
        print("Timeout nach 10 Minuten.")

    # Extract and save cookies
    try:
        all_cookies = ctx.cookies()
    except Exception:
        print("Konnte Cookies nicht lesen. Browser war schon zu.")
        ctx.close()
        exit(1)
    reddit_cookies = {}
    for c in all_cookies:
        if "reddit.com" in c.get("domain", ""):
            reddit_cookies[c["name"]] = c["value"]

    if reddit_cookies:
        COOKIES_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(COOKIES_FILE, "w") as f:
            json.dump(reddit_cookies, f, indent=2)
        print(f"Cookies gespeichert! ({len(reddit_cookies)} cookies)")

        # Verify
        import requests
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        for name, value in reddit_cookies.items():
            session.cookies.set(name, value, domain=".reddit.com")

        resp = session.get("https://old.reddit.com/api/me.json", timeout=10)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            name = data.get("name")
            if name:
                print(f"Login bestaetigt! Eingeloggt als u/{name}")
                print("Upvotes/Comments sollten jetzt funktionieren!")
            else:
                print("Cookies gespeichert aber Login konnte nicht verifiziert werden.")
        else:
            print(f"Verifikation fehlgeschlagen: HTTP {resp.status_code}")
    else:
        print("Keine Reddit-Cookies gefunden. Bist du sicher dass du eingeloggt bist?")

    ctx.close()
    print("Browser geschlossen. Fertig!")
