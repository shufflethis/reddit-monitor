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


def _is_logged_in(session: http_requests.Session, retries: int = 2) -> bool:
    for attempt in range(retries):
        try:
            resp = session.get("https://old.reddit.com/api/me.json", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                name = data.get("data", {}).get("name")
                if name:
                    logger.info(f"Session valid for u/{name}")
                    return True
            elif resp.status_code in (429, 500, 502, 503):
                logger.warning(f"Session check got HTTP {resp.status_code}, retrying ({attempt+1}/{retries})...")
                time.sleep(3)
                continue
        except Exception as e:
            logger.warning(f"Session check failed: {e}, retrying ({attempt+1}/{retries})...")
            time.sleep(3)
            continue
        break
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
            headless=False,
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

            # ── Step 1: Solve pre-login "Prove your humanity" captcha ──
            for attempt in range(3):
                # Check if we see the captcha gate or already the login form
                username_field = page.query_selector('input#login-username, input[name="username"]')
                if username_field:
                    logger.info("Login form visible, no pre-login captcha needed")
                    break

                # Check for "Prove your humanity" page with reCAPTCHA
                has_captcha = page.query_selector(
                    'iframe[src*="recaptcha"], iframe[title*="reCAPTCHA"], '
                    'iframe[src*="captcha"], .g-recaptcha'
                )
                prove_humanity = page.query_selector('text="Prove your humanity"')

                if has_captcha or prove_humanity:
                    logger.info(f"Pre-login captcha detected! Solving with AI (attempt {attempt + 1}/3)...")
                    try:
                        solved = _solve_recaptcha(page)
                        if solved:
                            logger.info("Pre-login captcha solved! Waiting for login form...")
                            time.sleep(5)
                            # Page should now show the actual login form
                            continue
                    except Exception as e:
                        logger.warning(f"Pre-login captcha attempt {attempt + 1} failed: {e}")
                        # Reload and try again
                        page.goto("https://www.reddit.com/login/", timeout=20000)
                        page.wait_for_load_state("domcontentloaded")
                        time.sleep(3)
                else:
                    logger.info("No captcha detected, waiting...")
                    time.sleep(3)

            # ── Step 2: Fill credentials ──
            username_sel = 'input#login-username, input[name="username"]'
            password_sel = 'input#login-password, input[name="password"]'

            try:
                page.wait_for_selector(username_sel, timeout=15000)
            except Exception:
                logger.error("Login form did not appear after captcha solve")
                page.screenshot(path="/tmp/reddit_login_debug.png")
                return {}

            logger.info("Filling in credentials...")
            page.fill(username_sel, username)
            time.sleep(0.5)
            page.fill(password_sel, password)
            time.sleep(0.5)

            # ── Step 3: Submit login ──
            submit_btn = page.query_selector('button[type="submit"]')
            if submit_btn:
                submit_btn.click()
                logger.info("Login form submitted, waiting...")
            else:
                page.keyboard.press("Enter")
                logger.info("Login submitted via Enter key, waiting...")
            time.sleep(5)

            # ── Step 4: Handle post-login captcha if needed ──
            for attempt in range(3):
                if "/login" not in page.url:
                    logger.info("Login succeeded!")
                    break

                has_captcha = page.query_selector(
                    'iframe[src*="recaptcha"], iframe[title*="reCAPTCHA"]'
                )
                if has_captcha:
                    logger.info(f"Post-login captcha detected (attempt {attempt + 1}/3)...")
                    try:
                        solved = _solve_recaptcha(page)
                        if solved:
                            time.sleep(2)
                            submit_btn = page.query_selector('button[type="submit"]')
                            if submit_btn:
                                submit_btn.click()
                            time.sleep(5)
                    except Exception as e:
                        logger.warning(f"Post-login captcha attempt {attempt + 1} failed: {e}")
                        time.sleep(2)
                else:
                    time.sleep(3)

            # ── Step 5: Verify login ──
            time.sleep(3)
            cookies = _extract_cookies(context)
            if cookies:
                session = _get_session(cookies)
                if _is_logged_in(session):
                    logger.info("Stealth browser login successful!")
                    return cookies

            if "/login" not in page.url:
                cookies = _extract_cookies(context)
                if cookies:
                    logger.info("Login appears successful (redirected)")
                    return cookies

            logger.warning("Stealth login failed — could not verify session")
            page.screenshot(path="/tmp/reddit_login_debug.png")
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
    # Gallery URLs: /gallery/xxx
    match = re.search(r'/gallery/([a-z0-9]+)', url)
    if match:
        return f"t3_{match.group(1)}"
    match = re.search(r'/r/\w+/(\w+)', url)
    if match:
        return f"t3_{match.group(1)}"
    return ""


# ── Public API: Upvote ───────────────────────────────────────────────

def run_upvote(username: str, password: str, post_url: str, post_id_override: str = "", **kwargs) -> bool:
    """Upvote a Reddit post"""
    post_id = ""
    if post_id_override:
        if post_id_override.startswith(("t1_", "t3_")):
            post_id = post_id_override
        else:
            post_id = f"t3_{post_id_override}"
    else:
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

def _post_comment_request(session, post_id: str, text: str, post_url: str) -> dict:
    """Actually send the comment request. Returns {'ok': bool, 'retry': bool, 'error': str}"""
    modhash = _get_modhash(session)
    if not modhash:
        return {"ok": False, "retry": True, "error": "Could not get modhash"}

    resp = session.post("https://old.reddit.com/api/comment", data={
        "thing_id": post_id, "text": text, "uh": modhash,
    }, headers={
        "X-Modhash": modhash, "Referer": post_url,
    }, timeout=15)

    if resp.status_code == 200:
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        errors = data.get("json", {}).get("errors", [])
        if errors:
            error_codes = [e[0] for e in errors]
            logger.error(f"Comment errors: {errors}")
            if "BAD_CAPTCHA" in error_codes:
                return {"ok": False, "retry": False, "error": "Reddit verlangt ein Captcha zum Kommentieren. Account hat evtl. zu wenig Karma."}
            return {"ok": False, "retry": False, "error": f"Reddit errors: {errors}"}
        logger.info(f"Comment posted on {post_id}")
        return {"ok": True, "retry": False, "error": ""}
    elif resp.status_code in (403, 401):
        return {"ok": False, "retry": True, "error": f"HTTP {resp.status_code}"}
    else:
        logger.error(f"Comment failed: HTTP {resp.status_code} — {resp.text[:200]}")
        return {"ok": False, "retry": False, "error": f"HTTP {resp.status_code}"}


def run_comment(username: str, password: str, post_url: str, text: str, thing_id: str = "", **kwargs) -> bool:
    """Post a comment on a Reddit post or reply to a comment.
    If thing_id is set (e.g. t1_xxx), use it directly instead of parsing the URL."""
    if thing_id:
        post_id = thing_id
    else:
        post_id = _url_to_fullname(post_url)
    if not post_id:
        logger.error(f"Could not extract post ID from URL: {post_url}")
        return False

    try:
        # Attempt 1: just use saved cookies directly — no validation, no login
        cookies = _load_cookies()
        if cookies:
            session = _get_session(cookies)
            logger.info(f"Comment attempt 1: using saved cookies for {post_id}")
            result = _post_comment_request(session, post_id, text, post_url)
            if result["ok"]:
                return True
            if not result["retry"]:
                raise Exception(result["error"]) if result["error"] else None
                return False
            logger.warning(f"Comment attempt 1 failed ({result['error']}), will retry with fresh session")

        # Attempt 2: full session validation + possible re-login
        logger.info("Comment attempt 2: using _ensure_session")
        session = _ensure_session(username, password)
        result = _post_comment_request(session, post_id, text, post_url)
        if result["ok"]:
            return True
        if result["error"]:
            raise Exception(result["error"])
        return False

    except Exception as e:
        logger.error(f"Comment error: {e}")
        raise


# ── Test Auth ────────────────────────────────────────────────────────

def check_inbox_replies() -> list:
    """Check Reddit inbox for unread comment replies.
    Uses saved cookies (no username/password needed).
    Returns list of reply dicts and marks them as read."""
    cookies = _load_cookies()
    if not cookies:
        logger.warning("No saved cookies — cannot check inbox replies")
        return []

    session = _get_session(cookies)
    if not _is_logged_in(session):
        logger.warning("Saved cookies expired — cannot check inbox replies")
        return []

    try:
        resp = session.get(
            "https://old.reddit.com/message/unread.json?limit=25",
            timeout=15,
        )
        if resp.status_code != 200:
            logger.error(f"Inbox fetch failed: HTTP {resp.status_code}")
            return []

        data = resp.json()
        children = data.get("data", {}).get("children", [])

        replies = []
        read_ids = []
        for item in children:
            item_data = item.get("data", {})
            if item_data.get("type") != "comment_reply":
                continue

            context_path = item_data.get("context", "")
            context_url = f"https://www.reddit.com{context_path}" if context_path else ""

            replies.append({
                "author": item_data.get("author", "[deleted]"),
                "body": item_data.get("body", ""),
                "link_title": item_data.get("link_title", ""),
                "subreddit": item_data.get("subreddit", ""),
                "context": context_url,
                "name": item_data.get("name", ""),
                "parent_id": item_data.get("parent_id", ""),
            })
            read_ids.append(item_data.get("name", ""))

        # Mark replies as read so they don't come up again
        if read_ids:
            modhash = _get_modhash(session)
            session.post(
                "https://old.reddit.com/api/read_message",
                data={"id": ",".join(read_ids), "uh": modhash},
                headers={"X-Modhash": modhash},
                timeout=15,
            )
            logger.info(f"Marked {len(read_ids)} messages as read")

        logger.info(f"Found {len(replies)} new comment replies")
        return replies

    except Exception as e:
        logger.error(f"Error checking inbox replies: {e}")
        return []


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
