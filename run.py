#!/usr/bin/env python3
"""
reddit-monitor - Entry point for the Reddit Monitoring Tool
"""

import sys
import os

# Add app directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from app.config import setup_logging
from web.app import create_app

def main():
    """Main entry point"""
    # Setup logging
    setup_logging()
    
    # Create Flask app
    app = create_app()
    
    # Run the app
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    print(f"Starting Reddit Monitor on http://localhost:{port}")
    print("Press Ctrl+C to stop")
    
    app.run(host='0.0.0.0', port=port, debug=debug)

if __name__ == '__main__':
    main()