#!/usr/bin/env python3
"""
reddit-monitor - Entry point for the Reddit Monitoring Tool
"""

import sys
import os
import threading
import logging

# Add project root to path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

from app.config import setup_logging

logger = logging.getLogger(__name__)


def start_slack_bolt():
    """Start Slack Bolt Socket Mode in a daemon thread if configured"""
    try:
        from web.app import get_config
        cfg = get_config()

        bot_token = cfg.get('slack_bot_token', '')
        app_token = cfg.get('slack_app_token', '')

        if bot_token and app_token:
            from app.slack_bolt_app import start_bolt_socket_mode
            thread = threading.Thread(
                target=start_bolt_socket_mode,
                args=(bot_token, app_token),
                daemon=True,
            )
            thread.start()
            logger.info("Slack Bolt Socket Mode thread started")
        else:
            logger.info("Slack Bolt not started (missing bot_token or app_token)")
    except Exception as e:
        logger.error(f"Failed to start Slack Bolt: {e}")


def main():
    """Main entry point"""
    # Setup logging
    setup_logging()

    # Run the app
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'true').lower() == 'true'

    # Import after path setup
    from web.app import create_app
    app = create_app()

    # Start Slack Bolt Socket Mode (only in reloader child or non-debug)
    if os.environ.get('WERKZEUG_RUN_MAIN') == 'true' or not debug:
        start_slack_bolt()

    print(f"""
    ╔══════════════════════════════════════════════╗
    ║           Reddit Monitor v1.0                ║
    ║──────────────────────────────────────────────║
    ║  Server: http://localhost:{port}               ║
    ║  Debug:  {debug}                               ║
    ╚══════════════════════════════════════════════╝

    Press Ctrl+C to stop
    """)

    app.run(host='0.0.0.0', port=port, debug=debug)

if __name__ == '__main__':
    main()
