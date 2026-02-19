"""
Flask web application for reddit-monitor
Complete rewrite with persistent JSON storage
"""

import os
import sys
import json
import hashlib
import secrets
import threading
import logging
from datetime import datetime, time as dtime
from pathlib import Path
from functools import wraps

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_wtf.csrf import CSRFProtect

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.config import setup_logging, DATA_DIR

# Setup logging
setup_logging()

# Paths
CONFIG_FILE = DATA_DIR / "config.json"
USERS_FILE = DATA_DIR / "users.json"

# Initialize Flask app
app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF temporarily
csrf = CSRFProtect(app)


def load_json(filepath: Path, default: dict = None) -> dict:
    """Load JSON file or return default"""
    if filepath.exists():
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except:
            pass
    return default or {}


def save_json(filepath: Path, data: dict):
    """Save data to JSON file"""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2, default=str)


def hash_password(password: str) -> str:
    """Hash password with salt"""
    salt = "reddit_monitor_salt_2024"
    return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()


_CONFIG_DEFAULTS = {
    'reddit_username': '',
    'reddit_password': '',
    'subreddits': '',
    'scan_interval': 15,
    'active_start': '09:00',
    'active_end': '17:00',
    'slack_bot_token': '',
    'slack_channel_id': '',
    'slack_webhook': '',
    'slack_channel': '#general',
    'bot_username': 'Reddit Monitor',
    'bot_emoji': ':robot_face:',
    'notify_new_posts': True,
    'notify_keywords': True,
    'notify_errors': False,
    'keywords': '',
    'exclude_keywords': '',
    'required_flairs': '',
    'exclude_flairs': '',
    'min_upvotes': 5,
    'min_comments': 0,
    'max_age_hours': 24,
    'last_scan': None,
    'monitor_running': False,
    'slack_app_token': '',
    'openrouter_api_key': '',
    'openrouter_model': 'meta-llama/llama-3.1-70b-instruct',
    'openrouter_persona': '',
    'groq_api_key': '',
    'groq_language': 'en',
    'captcha_api_key': '',
}


def get_config() -> dict:
    """Get current configuration, merging defaults for missing keys"""
    saved = load_json(CONFIG_FILE, {})
    merged = dict(_CONFIG_DEFAULTS)
    merged.update(saved)
    return merged


def save_config(data: dict):
    """Save configuration"""
    config = get_config()
    config.update(data)
    save_json(CONFIG_FILE, config)


def get_users() -> dict:
    """Get all users"""
    return load_json(USERS_FILE, {})


def save_users(users: dict):
    """Save users"""
    save_json(USERS_FILE, users)


def login_required(f):
    """Login required decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            # For API requests, return JSON
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Nicht eingeloggt'}), 401
            flash('Bitte einloggen', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Inject current_user into all templates
@app.context_processor
def inject_user():
    class CurrentUser:
        @property
        def is_authenticated(self):
            return 'user_id' in session

        @property
        def username(self):
            return session.get('username', '')

    return dict(current_user=CurrentUser())


# Routes
@app.route('/')
@login_required
def index():
    """Dashboard"""
    config = get_config()
    return render_template('index.html', config=config)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        users = get_users()

        # Auto-create first user
        if not users:
            users[username] = {
                'password': hash_password(password),
                'created': datetime.now().isoformat()
            }
            save_users(users)
            flash(f'Account "{username}" erstellt!', 'success')

        # Check credentials
        if username in users and users[username]['password'] == hash_password(password):
            session['user_id'] = username
            session['username'] = username
            flash(f'Willkommen, {username}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Falsche Anmeldedaten', 'danger')

    return render_template('login.html', form=None)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Register page"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        password2 = request.form.get('password2', '')

        if not username or not password:
            flash('Alle Felder ausfuellen', 'danger')
        elif password != password2:
            flash('Passwoerter stimmen nicht ueberein', 'danger')
        else:
            users = get_users()
            if username in users:
                flash('Username existiert bereits', 'danger')
            else:
                users[username] = {
                    'password': hash_password(password),
                    'created': datetime.now().isoformat()
                }
                save_users(users)
                flash('Account erstellt! Bitte einloggen.', 'success')
                return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/logout')
def logout():
    """Logout"""
    session.clear()
    flash('Abgemeldet', 'info')
    return redirect(url_for('login'))


@app.route('/settings/reddit', methods=['GET', 'POST'])
@login_required
def reddit_settings():
    """Reddit configuration"""
    config = get_config()

    if request.method == 'POST':
        new_config = {
            'reddit_username': request.form.get('reddit_username', '').strip(),
            'subreddits': request.form.get('subreddits', '').strip(),
            'scan_interval': int(request.form.get('scan_interval', 15)),
            'active_start': request.form.get('active_start', '09:00'),
            'active_end': request.form.get('active_end', '17:00'),
        }

        # Only update password if provided
        if request.form.get('reddit_password'):
            new_config['reddit_password'] = request.form.get('reddit_password')

        save_config(new_config)
        flash('Reddit-Einstellungen gespeichert!', 'success')
        return redirect(url_for('reddit_settings'))

    return render_template('reddit_settings.html', config=config)


@app.route('/settings/slack', methods=['GET', 'POST'])
@login_required
def slack_settings():
    """Slack configuration"""
    config = get_config()

    if request.method == 'POST':
        new_config = {
            'slack_bot_token': request.form.get('slack_bot_token', '').strip(),
            'slack_app_token': request.form.get('slack_app_token', '').strip(),
            'slack_channel_id': request.form.get('slack_channel_id', '').strip(),
            'slack_webhook': request.form.get('webhook_url', '').strip(),
            'slack_channel': request.form.get('slack_channel', '#general').strip(),
            'bot_username': request.form.get('bot_username', 'Reddit Monitor').strip(),
            'bot_emoji': request.form.get('bot_emoji', ':robot_face:').strip(),
            'notify_new_posts': 'notify_new_posts' in request.form,
            'notify_keywords': 'notify_keywords' in request.form,
            'notify_errors': 'notify_errors' in request.form,
        }

        save_config(new_config)
        flash('Slack-Einstellungen gespeichert!', 'success')
        return redirect(url_for('slack_settings'))

    return render_template('slack_settings.html', config=config)


@app.route('/settings/ai', methods=['GET', 'POST'])
@login_required
def ai_settings():
    """AI/LLM configuration"""
    config = get_config()

    if request.method == 'POST':
        model = request.form.get('openrouter_model', '').strip()
        custom_model = request.form.get('openrouter_model_custom', '').strip()
        if model == 'custom' and custom_model:
            model = custom_model

        new_config = {
            'openrouter_api_key': request.form.get('openrouter_api_key', '').strip(),
            'openrouter_model': model,
            'openrouter_persona': request.form.get('openrouter_persona', '').strip(),
            'groq_api_key': request.form.get('groq_api_key', '').strip(),
            'groq_language': request.form.get('groq_language', 'en').strip(),
            'captcha_api_key': request.form.get('captcha_api_key', '').strip(),
        }

        save_config(new_config)
        flash('AI-Einstellungen gespeichert!', 'success')
        return redirect(url_for('ai_settings'))

    return render_template('ai_settings.html', config=config)


@app.route('/settings/guardrails', methods=['GET', 'POST'])
@login_required
def guardrails():
    """Guardrails configuration"""
    config = get_config()

    if request.method == 'POST':
        new_config = {
            'keywords': request.form.get('keywords', '').strip(),
            'exclude_keywords': request.form.get('exclude_keywords', '').strip(),
            'required_flairs': request.form.get('required_flairs', '').strip(),
            'exclude_flairs': request.form.get('exclude_flairs', '').strip(),
            'min_upvotes': int(request.form.get('min_upvotes', 5)),
            'min_comments': int(request.form.get('min_comments', 0)),
            'max_age_hours': int(request.form.get('max_age_hours', 24)),
        }

        save_config(new_config)
        flash('Guardrails gespeichert!', 'success')
        return redirect(url_for('guardrails'))

    return render_template('guardrails.html', config=config)


# API Routes
@app.route('/api/status')
@login_required
def api_status():
    """API endpoint for status"""
    config = get_config()
    subreddits = [s.strip() for s in config.get('subreddits', '').split('\n') if s.strip()]

    return jsonify({
        'status': 'running' if scheduler.running else 'stopped',
        'reddit': {
            'username': config.get('reddit_username', ''),
            'configured': bool(config.get('reddit_username')),
            'subreddits': subreddits,
            'subreddit_count': len(subreddits),
        },
        'slack': {
            'configured': bool(config.get('slack_webhook')),
            'channel': config.get('slack_channel', '#general'),
        },
        'last_scan': config.get('last_scan'),
        'scan_interval': config.get('scan_interval', 15),
    })


# Store for scan results
SCAN_RESULTS_FILE = DATA_DIR / "scan_results.json"
SCAN_STATUS_FILE = DATA_DIR / "scan_status.json"
SEEN_POSTS_FILE = DATA_DIR / "seen_posts.json"


def get_seen_posts() -> dict:
    """Get set of already-notified post IDs with timestamps"""
    return load_json(SEEN_POSTS_FILE, {})


def mark_posts_seen(post_ids: list):
    """Mark post IDs as seen so they won't be notified again"""
    seen = get_seen_posts()
    now = datetime.now().isoformat()
    for pid in post_ids:
        seen[pid] = now
    # Prune entries older than 7 days to prevent unbounded growth
    cutoff = datetime.now().timestamp() - 7 * 86400
    seen = {
        pid: ts for pid, ts in seen.items()
        if datetime.fromisoformat(ts).timestamp() > cutoff
    }
    save_json(SEEN_POSTS_FILE, seen)

def run_scan_background(cfg_copy):
    """Run scan in background thread"""
    import asyncio
    from app.reddit_monitor import RedditMonitor
    from app.config import config as app_config

    # Update status
    save_json(SCAN_STATUS_FILE, {'status': 'running', 'started': datetime.now().isoformat()})

    try:
        # Update app config
        app_config.reddit.username = ''
        app_config.reddit.password = ''
        app_config.reddit.subreddits = cfg_copy['subreddits']
        app_config.reddit.min_upvotes = cfg_copy['min_upvotes']
        app_config.reddit.keywords = cfg_copy['keywords']
        app_config.reddit.exclude_keywords = cfg_copy['exclude_keywords']
        app_config.reddit.required_flairs = cfg_copy['required_flairs']
        app_config.reddit.exclude_flairs = cfg_copy['exclude_flairs']

        async def do_scan():
            monitor = RedditMonitor()
            await monitor.start()
            try:
                return await monitor.scan_all()
            finally:
                await monitor.stop()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        posts = loop.run_until_complete(do_scan())
        loop.close()

        # Filter out already-seen posts
        seen = get_seen_posts()
        new_posts = [p for p in posts if p.id not in seen]

        # Save results (show all matched posts, but mark which are new)
        results = {
            'success': True,
            'posts_found': len(posts),
            'new_posts': len(new_posts),
            'posts': [p.to_dict() for p in posts],
            'completed': datetime.now().isoformat()
        }
        save_json(SCAN_RESULTS_FILE, results)
        save_json(SCAN_STATUS_FILE, {'status': 'completed', 'completed': datetime.now().isoformat()})

        # Update last scan time
        save_json(CONFIG_FILE, {**load_json(CONFIG_FILE, {}), 'last_scan': datetime.now().isoformat()})

        # Mark all found posts as seen
        mark_posts_seen([p.id for p in posts])

        # Notify via Slack only for NEW posts
        if new_posts and (cfg_copy.get('slack_bot_token') or cfg_copy.get('slack_webhook')):
            from app.slack_integration import SlackNotifier
            notifier = SlackNotifier(
                bot_token=cfg_copy.get('slack_bot_token'),
                channel_id=cfg_copy.get('slack_channel_id'),
                webhook_url=cfg_copy.get('slack_webhook'),
            )
            notifier.notify_new_posts(new_posts)

    except Exception as e:
        import traceback
        traceback.print_exc()
        save_json(SCAN_STATUS_FILE, {'status': 'error', 'error': str(e)})
        save_json(SCAN_RESULTS_FILE, {'success': False, 'error': str(e)})


@app.route('/api/scan', methods=['POST'])
def api_scan():
    """API endpoint to trigger manual scan (runs in background)"""
    import threading

    config = get_config()

    subreddits = [s.strip() for s in config.get('subreddits', '').replace('\r', '').split('\n') if s.strip()]
    if not subreddits:
        return jsonify({'success': False, 'error': 'Keine Subreddits konfiguriert'}), 400

    # Check if scan already running
    status = load_json(SCAN_STATUS_FILE, {})
    if status.get('status') == 'running':
        return jsonify({'success': False, 'error': 'Scan läuft bereits'}), 400

    # Prepare config copy for background thread
    cfg_copy = {
        'subreddits': subreddits,
        'min_upvotes': config.get('min_upvotes', 0),
        'keywords': [k.strip() for k in config.get('keywords', '').replace('\r', '').split('\n') if k.strip()],
        'exclude_keywords': [k.strip() for k in config.get('exclude_keywords', '').replace('\r', '').split('\n') if k.strip()],
        'required_flairs': [f.strip() for f in config.get('required_flairs', '').replace('\r', '').split('\n') if f.strip()],
        'exclude_flairs': [f.strip() for f in config.get('exclude_flairs', '').replace('\r', '').split('\n') if f.strip()],
        'slack_webhook': config.get('slack_webhook', ''),
        'slack_bot_token': config.get('slack_bot_token', ''),
        'slack_channel_id': config.get('slack_channel_id', ''),
    }

    # Start background scan
    thread = threading.Thread(target=run_scan_background, args=(cfg_copy,))
    thread.daemon = True
    thread.start()

    return jsonify({'success': True, 'message': 'Scan gestartet...', 'status': 'running'})


@app.route('/api/scan/status')
def api_scan_status():
    """Get current scan status and results"""
    status = load_json(SCAN_STATUS_FILE, {'status': 'idle'})
    results = load_json(SCAN_RESULTS_FILE, {})

    return jsonify({
        'status': status.get('status', 'idle'),
        'results': results if status.get('status') == 'completed' else None
    })


@app.route('/api/slack/test', methods=['POST'])
@login_required
def api_slack_test():
    """Test Slack webhook"""
    config = get_config()

    if not config.get('slack_bot_token') and not config.get('slack_webhook'):
        return jsonify({'success': False, 'error': 'Kein Bot Token oder Webhook konfiguriert'}), 400

    try:
        from app.slack_integration import SlackNotifier
        notifier = SlackNotifier(
            bot_token=config.get('slack_bot_token'),
            channel_id=config.get('slack_channel_id'),
            webhook_url=config.get('slack_webhook'),
        )
        success = notifier.post_to_slack("Test-Nachricht vom Reddit Monitor! Das Setup funktioniert. ✅")

        if success:
            return jsonify({'success': True, 'message': 'Test erfolgreich!'})
        else:
            return jsonify({'success': False, 'error': 'Slack Nachricht konnte nicht gesendet werden'}), 400

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ai/test', methods=['POST'])
@login_required
def api_ai_test():
    """Test LLM comment generation"""
    config = get_config()

    if not config.get('openrouter_api_key'):
        return jsonify({'success': False, 'error': 'OpenRouter API Key nicht konfiguriert'}), 400

    try:
        from app.llm_generator import LLMGenerator
        gen = LLMGenerator(
            api_key=config.get('openrouter_api_key'),
            model=config.get('openrouter_model', 'meta-llama/llama-3.1-70b-instruct'),
            persona=config.get('openrouter_persona', ''),
        )
        comment = gen.generate_comment(
            post_title="Meine Wohnung hat Schimmel - was tun?",
            post_content="Habe gerade Schimmel in meiner Mietwohnung entdeckt. Der Vermieter reagiert nicht.",
            subreddit="wohnen",
            user_instruction="write a helpful and supportive comment",
        )
        return jsonify({'success': True, 'comment': comment})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/reddit/test', methods=['POST'])
@login_required
def api_reddit_test():
    """Test Reddit stealth browser login"""
    config = get_config()

    try:
        from app.reddit_actions import test_reddit_auth
        result = test_reddit_auth(
            username=config.get('reddit_username', ''),
            password=config.get('reddit_password', ''),
        )
        if result["success"]:
            return jsonify({
                'success': True,
                'message': f"Verbunden als u/{result['username']} (Karma: {result['karma']})"
            })
        return jsonify({'success': False, 'error': result['error']}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/monitor/start', methods=['POST'])
@login_required
def api_monitor_start():
    """Start the monitor - begins scheduled scanning"""
    save_config({'monitor_running': True})
    scheduler.start()
    return jsonify({'success': True, 'status': 'running'})


@app.route('/api/monitor/stop', methods=['POST'])
@login_required
def api_monitor_stop():
    """Stop the monitor - stops scheduled scanning"""
    save_config({'monitor_running': False})
    scheduler.stop()
    return jsonify({'success': True, 'status': 'stopped'})


class MonitorScheduler:
    """Background scheduler that runs scans at configured intervals"""

    def __init__(self):
        self._thread: threading.Thread = None
        self._stop_event = threading.Event()
        self._logger = logging.getLogger(__name__)

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self):
        if self.running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        self._logger.info("Monitor scheduler started")

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._thread = None
        self._logger.info("Monitor scheduler stopped")

    def _in_active_hours(self, cfg: dict) -> bool:
        now = datetime.now().time()
        try:
            start = dtime.fromisoformat(cfg.get('active_start', '09:00'))
            end = dtime.fromisoformat(cfg.get('active_end', '22:00'))
        except (ValueError, TypeError):
            return True
        if start <= end:
            return start <= now <= end
        # Overnight range (e.g. 22:00 - 06:00)
        return now >= start or now <= end

    def _run_loop(self):
        while not self._stop_event.is_set():
            cfg = get_config()
            interval_minutes = cfg.get('scan_interval', 15)

            if self._in_active_hours(cfg):
                subreddits = [s.strip() for s in cfg.get('subreddits', '').replace('\r', '').split('\n') if s.strip()]
                if subreddits:
                    self._logger.info(f"Scheduled scan starting ({len(subreddits)} subreddits)")
                    cfg_copy = {
                        'subreddits': subreddits,
                        'min_upvotes': cfg.get('min_upvotes', 0),
                        'keywords': [k.strip() for k in cfg.get('keywords', '').replace('\r', '').split('\n') if k.strip()],
                        'exclude_keywords': [k.strip() for k in cfg.get('exclude_keywords', '').replace('\r', '').split('\n') if k.strip()],
                        'required_flairs': [f.strip() for f in cfg.get('required_flairs', '').replace('\r', '').split('\n') if f.strip()],
                        'exclude_flairs': [f.strip() for f in cfg.get('exclude_flairs', '').replace('\r', '').split('\n') if f.strip()],
                        'slack_webhook': cfg.get('slack_webhook', ''),
                        'slack_bot_token': cfg.get('slack_bot_token', ''),
                        'slack_channel_id': cfg.get('slack_channel_id', ''),
                    }
                    try:
                        run_scan_background(cfg_copy)
                    except Exception as e:
                        self._logger.error(f"Scheduled scan error: {e}")
            else:
                self._logger.debug("Outside active hours, skipping scan")

            # Wait for the interval, but check stop_event frequently
            self._stop_event.wait(timeout=interval_minutes * 60)


scheduler = MonitorScheduler()


def create_app():
    """Application factory"""
    # Resume scheduler if monitor was running before restart
    cfg = get_config()
    if cfg.get('monitor_running'):
        scheduler.start()
    return app


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
