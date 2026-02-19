"""
Reddit actions (upvote, comment) using stealth browser + AI captcha solving.
Strategy:
  1. Use Patchright (stealth Playwright fork) — undetectable browser
  2. Persistent browser profile — cookies/session survive restarts
  3. Reddit REST API with session cookies (fast, no browser per action)
  4. If cookies expired: stealth browser login + Recognizer AI captcha solver
"""

import json
import logging
import re
import time
from pathlib import Path

import requests as http_requests

from .config import DATA_DIR

logger = logging.getLogger(__name__)

COOKIES_FILE = DATA_DIR / "reddit_cookies.json"
BROWSER_PROFILE_DIR = str(DATA_DIR / "reddit_browser_profile")

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)


# ── Cookie Management ────────────────────────────────────────────────

def _load_cookies() -> dict:
    if COOKIES_FILE.exists():
        try:
            with open(COOKIES_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_cookies(cookies: dict):
    COOKIES_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(COOKIES_FILE, 'w') as f:
        json.dump(cookies, f, indent=2)
    logger.info("Reddit cookies saved to disk")


# ── Session from Cookies ─────────────────────────────────────────────

def _get_session(cookies: dict = None) -> http_requests.Session:
    session = http_requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    if cookies:
        for name, value in cookies.items():
            session.cookies.set(name, value, domain=".reddit.com")
    return session


def _is_logged_in(session: http_requests.Session) -> bool:
    try:
        resp = session.get("https://old.reddit.com/api/me.json", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            name = data.get("data", {}).get("name")
            if name:
                logger.info(f"Session valid for u/{name}")
                return True
    except Exception as e:
        logger.debug(f"Session check failed: {e}")
    return False


def _get_modhash(session: http_requests.Session) -> str:
    try:
        resp = session.get("https://old.reddit.com/api/me.json", timeout=10)
        if resp.status_code == 200:
            return resp.json().get("data", {}).get("modhash", "")
    except Exception:
        pass
    return ""


# ── Stealth Browser Login ────────────────────────────────────────────

def _login_stealth(username: str, password: str) -> dict:
    """Login via Patchright stealth browser + AI captcha solver.
    Returns dict of cookies on success, empty dict on failure."""
    from patchright.sync_api import sync_playwright

    logger.info(f"Stealth browser login for u/{username}...")
    Path(BROWSER_PROFILE_DIR).mkdir(parents=True, exist_ok=True)

    with sync_playwright() as pw:
        context = pw.chromium.launch_persistent_context(
            BROWSER_PROFILE_DIR,
            headless=True,
            user_agent=USER_AGENT,
            viewport={"width": 1920, "height": 1080},
            locale="en-US",
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-first-run",
                "--no-default-browser-check",
            ],
        )

        page = context.pages[0] if context.pages else context.new_page()

        try:
            # ── Check if already logged in from persistent context ──
            page.goto("https://www.reddit.com/", timeout=20000)
            page.wait_for_load_state("domcontentloaded")
            time.sleep(2)

            # Check for login state via cookie
            reddit_cookies = _extract_cookies(context)
            if reddit_cookies:
                session = _get_session(reddit_cookies)
                if _is_logged_in(session):
                    logger.info("Already logged in via persistent context!")
                    return reddit_cookies

            # ── Navigate to login page ──
            logger.info("Navigating to Reddit login...")
            page.goto("https://www.reddit.com/login/", timeout=20000)
            page.wait_for_load_state("domcontentloaded")
            time.sleep(3)

            # ── Fill credentials ──
            username_sel = 'input#login-username, input[name="username"]'
            password_sel = 'input#login-password, input[name="password"]'

            page.wait_for_selector(username_sel, timeout=10000)
            page.fill(username_sel, username)
            time.sleep(0.5)
            page.fill(password_sel, password)
            time.sleep(0.5)

            # ── Click login ──
            page.click('button[type="submit"]')
            logger.info("Login form submitted, waiting...")
            time.sleep(5)

            # ── Check if captcha appeared ──
            captcha_solved = False
            for attempt in range(3):
                # Check if we're past the login page
                if "/login" not in page.url:
                    logger.info("Login succeeded (no captcha)!")
                    break

                # Look for reCAPTCHA iframe
                captcha_frame = page.query_selector(
                    'iframe[src*="recaptcha"], iframe[title*="reCAPTCHA"]'
                )
                if captcha_frame:
                    logger.info(f"reCAPTCHA detected, solving with AI (attempt {attempt + 1}/3)...")
                    try:
                        captcha_solved = _solve_recaptcha(page)
                        if captcha_solved:
                            logger.info("Captcha solved! Resubmitting...")
                            time.sleep(2)
                            # Try clicking submit again after captcha
                            submit_btn = page.query_selector('button[type="submit"]')
                            if submit_btn:
                                submit_btn.click()
                            time.sleep(5)
                    except Exception as e:
                        logger.warning(f"Captcha solve attempt {attempt + 1} failed: {e}")
                        time.sleep(2)
                else:
                    # No captcha visible, wait a bit more
                    time.sleep(3)

            # ── Verify login result ──
            time.sleep(3)
            cookies = _extract_cookies(context)
            if cookies:
                session = _get_session(cookies)
                if _is_logged_in(session):
                    logger.info("Stealth browser login successful!")
                    return cookies

            # Check URL as fallback
            if "/login" not in page.url:
                cookies = _extract_cookies(context)
                if cookies:
                    logger.info("Login appears successful (redirected)")
                    return cookies

            logger.warning("Stealth login failed — could not verify session")
            return {}

        except Exception as e:
            logger.error(f"Stealth login error: {e}")
            return {}

        finally:
            context.close()


def _solve_recaptcha(page) -> bool:
    """Solve reCAPTCHA using Recognizer AI (YOLO + CLIP, runs locally)."""
    try:
        from recognizer.agents.playwright import SyncChallenger

        challenger = SyncChallenger(page, click_timeout=3000)
        challenger.solve_recaptcha()
        logger.info("Recognizer solved the captcha")
        return True
    except Exception as e:
        logger.warning(f"Recognizer captcha solve failed: {e}")
        return False


def _extract_cookies(context) -> dict:
    """Extract reddit.com cookies from browser context"""
    all_cookies = context.cookies()
    reddit_cookies = {}
    for c in all_cookies:
        if "reddit.com" in c.get("domain", ""):
            reddit_cookies[c["name"]] = c["value"]
    return reddit_cookies


# ── Session Management ───────────────────────────────────────────────

def _ensure_session(username: str, password: str) -> http_requests.Session:
    """Get a valid Reddit session, logging in via stealth browser if needed."""
    # Try saved cookies first
    cookies = _load_cookies()
    if cookies:
        session = _get_session(cookies)
        if _is_logged_in(session):
            return session
        logger.info("Saved cookies expired, need fresh login")

    # Stealth browser login
    new_cookies = _login_stealth(username, password)
    if new_cookies:
        _save_cookies(new_cookies)
        session = _get_session(new_cookies)
        if _is_logged_in(session):
            return session

    raise Exception(
        "Reddit Login fehlgeschlagen. Captcha konnte nicht geloest werden. "
        "Versuche es spaeter erneut oder logge dich manuell ein."
    )


# ── URL Parsing ──────────────────────────────────────────────────────

def _url_to_fullname(url: str) -> str:
    """Extract Reddit post fullname (t3_xxx) from URL"""
    match = re.search(r'/comments/([a-z0-9]+)', url)
    if match:
        return f"t3_{match.group(1)}"
    match = re.search(r'/r/\w+/(\w+)', url)
    if match:
        return f"t3_{match.group(1)}"
    return ""


# ── Public API: Upvote ───────────────────────────────────────────────

def run_upvote(username: str, password: str, post_url: str, **kwargs) -> bool:
    """Upvote a Reddit post"""
    post_id = _url_to_fullname(post_url)
    if not post_id:
        logger.error(f"Could not extract post ID from URL: {post_url}")
        return False

    try:
        session = _ensure_session(username, password)
        modhash = _get_modhash(session)

        resp = session.post("https://old.reddit.com/api/vote", data={
            "id": post_id, "dir": "1", "uh": modhash,
        }, headers={
            "X-Modhash": modhash, "Referer": post_url,
        }, timeout=15)

        if resp.status_code == 200:
            logger.info(f"Upvoted {post_id} successfully")
            return True
        else:
            logger.error(f"Upvote failed: HTTP {resp.status_code} — {resp.text[:200]}")
            return False
    except Exception as e:
        logger.error(f"Upvote error: {e}")
        raise


# ── Public API: Comment ──────────────────────────────────────────────

def run_comment(username: str, password: str, post_url: str, text: str, **kwargs) -> bool:
    """Post a comment on a Reddit post"""
    post_id = _url_to_fullname(post_url)
    if not post_id:
        logger.error(f"Could not extract post ID from URL: {post_url}")
        return False

    try:
        session = _ensure_session(username, password)
        modhash = _get_modhash(session)

        resp = session.post("https://old.reddit.com/api/comment", data={
            "thing_id": post_id, "text": text, "uh": modhash,
        }, headers={
            "X-Modhash": modhash, "Referer": post_url,
        }, timeout=15)

        if resp.status_code == 200:
            data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
            errors = data.get("json", {}).get("errors", [])
            if errors:
                logger.error(f"Comment errors: {errors}")
                return False
            logger.info(f"Comment posted on {post_id}")
            return True
        else:
            logger.error(f"Comment failed: HTTP {resp.status_code} — {resp.text[:200]}")
            return False
    except Exception as e:
        logger.error(f"Comment error: {e}")
        raise


# ── Test Auth ────────────────────────────────────────────────────────

def test_reddit_auth(username: str, password: str) -> dict:
    """Test Reddit login. Returns status dict."""
    if not username or not password:
        return {"success": False, "error": "Username und Passwort eingeben"}

    try:
        session = _ensure_session(username, password)
        resp = session.get("https://old.reddit.com/api/me.json", timeout=10)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            return {
                "success": True,
                "username": data.get("name", ""),
                "karma": data.get("link_karma", 0) + data.get("comment_karma", 0),
            }
        return {"success": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}
