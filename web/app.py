"""
Flask web application for reddit-monitor
Complete rewrite with persistent JSON storage
"""

import os
import sys
import json
import hashlib
import secrets
from datetime import datetime
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


def get_config() -> dict:
    """Get current configuration"""
    return load_json(CONFIG_FILE, {
        'reddit_username': '',
        'reddit_password': '',
        'subreddits': '',
        'scan_interval': 15,
        'active_start': '09:00',
        'active_end': '17:00',
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
        'monitor_running': False
    })


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
        'status': 'running' if config.get('monitor_running') else 'stopped',
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


@app.route('/api/scan', methods=['POST'])
@login_required
def api_scan():
    """API endpoint to trigger manual scan"""
    config = get_config()

    if not config.get('reddit_username'):
        return jsonify({'success': False, 'error': 'Reddit nicht konfiguriert'}), 400

    try:
        from app.reddit_monitor import monitor
        from app.config import config as app_config
        import asyncio

        # Update app config from stored config
        app_config.reddit.username = config.get('reddit_username', '')
        app_config.reddit.password = config.get('reddit_password', '')
        app_config.reddit.subreddits = [s.strip() for s in config.get('subreddits', '').split('\n') if s.strip()]
        app_config.reddit.min_upvotes = config.get('min_upvotes', 5)
        app_config.reddit.keywords = [k.strip() for k in config.get('keywords', '').split('\n') if k.strip()]
        app_config.reddit.exclude_keywords = [k.strip() for k in config.get('exclude_keywords', '').split('\n') if k.strip()]
        app_config.reddit.required_flairs = [f.strip() for f in config.get('required_flairs', '').split('\n') if f.strip()]
        app_config.reddit.exclude_flairs = [f.strip() for f in config.get('exclude_flairs', '').split('\n') if f.strip()]
        app_config.slack.webhook_url = config.get('slack_webhook', '')

        # Run scan
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        if not monitor.browser:
            loop.run_until_complete(monitor.start())

        posts = loop.run_until_complete(monitor.scan_all())

        # Update last scan time
        save_config({'last_scan': datetime.now().isoformat()})

        # Notify via Slack
        if posts and config.get('slack_webhook'):
            from app.slack_integration import SlackNotifier
            notifier = SlackNotifier()
            notifier.webhook = None  # Reset
            from slack_sdk.webhook import WebhookClient
            notifier.webhook = WebhookClient(config.get('slack_webhook'))
            notifier.notify_new_posts(posts)

        return jsonify({
            'success': True,
            'posts_found': len(posts),
            'posts': [p.to_dict() for p in posts]
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/slack/test', methods=['POST'])
@login_required
def api_slack_test():
    """Test Slack webhook"""
    config = get_config()

    if not config.get('slack_webhook'):
        return jsonify({'success': False, 'error': 'Webhook nicht konfiguriert'}), 400

    try:
        from slack_sdk.webhook import WebhookClient

        webhook = WebhookClient(config.get('slack_webhook'))
        response = webhook.send(
            text="Test-Nachricht vom Reddit Monitor!",
            username=config.get('bot_username', 'Reddit Monitor'),
            icon_emoji=config.get('bot_emoji', ':robot_face:')
        )

        if response.status_code == 200:
            return jsonify({'success': True, 'message': 'Test erfolgreich!'})
        else:
            return jsonify({'success': False, 'error': f'Slack Fehler: {response.body}'}), 400

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/monitor/start', methods=['POST'])
@login_required
def api_monitor_start():
    """Start the monitor"""
    save_config({'monitor_running': True})
    return jsonify({'success': True, 'status': 'running'})


@app.route('/api/monitor/stop', methods=['POST'])
@login_required
def api_monitor_stop():
    """Stop the monitor"""
    save_config({'monitor_running': False})
    return jsonify({'success': True, 'status': 'stopped'})


def create_app():
    """Application factory"""
    return app


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
