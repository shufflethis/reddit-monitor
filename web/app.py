"""
Flask web application for reddit-monitor
"""

import os
import sys
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, IntegerField, SelectMultipleField
from wtforms.validators import DataRequired, Length, Optional
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap

from app.config import config, setup_logging

# Setup logging
setup_logging()

# Initialize Flask app
app = Flask(__name__, template_folder='../web/templates', static_folder='../web/static')
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{config.db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class RedditAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Encrypted in production
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class SubredditConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class SlackConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    webhook_url = db.Column(db.String(500), nullable=False)
    channel = db.Column(db.String(100), default='#general')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[DataRequired()])

class RedditConfigForm(FlaskForm):
    username = StringField('Reddit Username', validators=[DataRequired()])
    password = PasswordField('Reddit Password', validators=[DataRequired()])
    subreddits = TextAreaField('Subreddits (one per line)', validators=[DataRequired()])
    scan_interval = IntegerField('Scan Interval (seconds)', default=900)
    min_upvotes = IntegerField('Minimum Upvotes', default=5)
    keywords = TextAreaField('Keywords (one per line)')
    exclude_keywords = TextAreaField('Exclude Keywords (one per line)')
    required_flairs = TextAreaField('Required Flairs (one per line)')
    exclude_flairs = TextAreaField('Exclude Flairs (one per line)')

class SlackConfigForm(FlaskForm):
    webhook_url = StringField('Slack Webhook URL', validators=[DataRequired()])
    channel = StringField('Channel', default='#general')
    username = StringField('Bot Username', default='Reddit Monitor')
    icon_emoji = StringField('Icon Emoji', default=':robot_face:')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_app():
    """Application factory"""
    # Ensure database exists
    with app.app_context():
        db.create_all()
    
    # Register blueprints and routes
    register_routes()
    
    return app

def register_routes():
    """Register all routes"""
    
    @app.route('/')
    @login_required
    def index():
        """Dashboard"""
        return render_template('index.html')
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """Login page"""
        form = LoginForm()
        
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user:  # In production, check password
                login_user(user)
                return redirect(url_for('index'))
            flash('Invalid username or password', 'danger')
        
        return render_template('login.html', form=form)
    
    @app.route('/logout')
    @login_required
    def logout():
        """Logout"""
        logout_user()
        return redirect(url_for('login'))
    
    @app.route('/settings/reddit', methods=['GET', 'POST'])
    @login_required
    def reddit_settings():
        """Reddit configuration"""
        form = RedditConfigForm()
        
        if form.validate_on_submit():
            # Save configuration
            # In production, encrypt password
            config.reddit.username = form.username.data
            config.reddit.password = form.password.data
            config.reddit.subreddits = [s.strip() for s in form.subreddits.data.split('\n') if s.strip()]
            config.reddit.scan_interval = form.scan_interval.data
            config.reddit.min_upvotes = form.min_upvotes.data
            config.reddit.keywords = [k.strip() for k in form.keywords.data.split('\n') if k.strip()]
            config.reddit.exclude_keywords = [k.strip() for k in form.exclude_keywords.data.split('\n') if k.strip()]
            config.reddit.required_flairs = [f.strip() for f in form.required_flairs.data.split('\n') if f.strip()]
            config.reddit.exclude_flairs = [f.strip() for f in form.exclude_flairs.data.split('\n') if f.strip()]
            
            flash('Reddit configuration saved!', 'success')
            return redirect(url_for('index'))
        
        return render_template('reddit_settings.html', form=form)
    
    @app.route('/settings/slack', methods=['GET', 'POST'])
    @login_required
    def slack_settings():
        """Slack configuration"""
        form = SlackConfigForm()
        
        if form.validate_on_submit():
            config.slack.webhook_url = form.webhook_url.data
            config.slack.channel = form.channel.data
            config.slack.username = form.username.data
            config.slack.icon_emoji = form.icon_emoji.data
            
            flash('Slack configuration saved!', 'success')
            return redirect(url_for('index'))
        
        return render_template('slack_settings.html', form=form)
    
    @app.route('/api/status')
    @login_required
    def api_status():
        """API endpoint for status"""
        return jsonify({
            'status': 'running',
            'logged_in': True,
            'config': {
                'reddit': {
                    'username': config.reddit.username,
                    'subreddits': config.reddit.subreddits,
                    'scan_interval': config.reddit.scan_interval,
                    'active_hours': f"{config.reddit.active_hours_start} - {config.reddit.active_hours_end}"
                },
                'slack': {
                    'webhook_configured': bool(config.slack.webhook_url)
                }
            }
        })
    
    @app.route('/api/scan', methods=['POST'])
    @login_required
    def api_scan():
        """API endpoint to trigger manual scan"""
        # Import here to avoid circular imports
        from app.reddit_monitor import monitor
        
        try:
            # In production, this would be async
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # Start monitor if not running
            if not monitor.browser:
                loop.run_until_complete(monitor.start())
            
            # Perform scan
            posts = loop.run_until_complete(monitor.scan_all())
            
            # Notify via Slack
            if posts and config.slack.webhook_url:
                from app.slack_integration import slack_notifier
                slack_notifier.notify_new_posts(posts)
            
            return jsonify({
                'success': True,
                'posts_found': len(posts),
                'posts': [p.to_dict() for p in posts]
            })
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/voice/transcribe', methods=['POST'])
    @login_required
    def api_transcribe_voice():
        """API endpoint to transcribe voice message"""
        # In production, handle audio upload and transcribe with Whisper
        # For now, return mock response
        
        data = request.json
        audio_url = data.get('audio_url')
        post_id = data.get('post_id')
        
        if not audio_url or not post_id:
            return jsonify({'error': 'Missing audio_url or post_id'}), 400
        
        # Mock transcription
        transcript = "This is a mock transcription of the voice message. In production, this would use Whisper CLI."
        
        return jsonify({
            'success': True,
            'transcript': transcript,
            'post_id': post_id
        })

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)