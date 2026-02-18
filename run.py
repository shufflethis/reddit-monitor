#!/usr/bin/env python3
"""
reddit-monitor - Entry point for the Reddit Monitoring Tool
"""

import sys
import os

# Add project root to path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

from app.config import setup_logging

def main():
    """Main entry point"""
    # Setup logging
    setup_logging()

    # Import after path setup
    from web.app import app

    # Run the app
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'true').lower() == 'true'

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
