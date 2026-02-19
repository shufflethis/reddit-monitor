"""
Configuration and logging setup for reddit-monitor
"""

import os
import sys
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import time

# Base paths
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = DATA_DIR / "logs"
DB_DIR = DATA_DIR / "db"

# Create directories
for dir_path in [DATA_DIR, LOGS_DIR, DB_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)

@dataclass
class RedditConfig:
    """Reddit account and scraping configuration"""
    username: str = ""
    password: str = ""
    subreddits: List[str] = field(default_factory=lambda: ["python", "programming"])
    scan_interval: int = 900  # seconds (15 minutes)
    active_hours_start: time = field(default_factory=lambda: time(9, 0))  # 9:00
    active_hours_end: time = field(default_factory=lambda: time(17, 0))   # 17:00
    headless: bool = True
    
    # Guardrails
    keywords: List[str] = field(default_factory=list)
    exclude_keywords: List[str] = field(default_factory=list)
    min_upvotes: int = 5
    required_flairs: List[str] = field(default_factory=list)
    exclude_flairs: List[str] = field(default_factory=list)

@dataclass
class SlackConfig:
    """Slack integration configuration"""
    webhook_url: str = ""
    channel: str = "#general"
    username: str = "Reddit Monitor"
    icon_emoji: str = ":robot_face:"
    
@dataclass
class VoiceConfig:
    """Voice transcription configuration"""
    whisper_model: str = "base"  # base, small, medium, large
    language: str = "en"
    max_duration: int = 30  # seconds
    temp_dir: str = str(DATA_DIR / "temp")

@dataclass
class AppConfig:
    """Main application configuration"""
    reddit: RedditConfig = field(default_factory=RedditConfig)
    slack: SlackConfig = field(default_factory=SlackConfig)
    voice: VoiceConfig = field(default_factory=VoiceConfig)
    debug: bool = True
    db_path: str = str(DB_DIR / "reddit_monitor.db")
    log_level: str = "INFO"

_logging_initialized = False

def setup_logging():
    """Setup application logging (idempotent - safe to call multiple times)"""
    global _logging_initialized
    if _logging_initialized:
        return
    _logging_initialized = True

    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    # File handler
    file_handler = logging.FileHandler(LOGS_DIR / "app.log")
    file_handler.setFormatter(logging.Formatter(log_format))

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(log_format))

    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    # Third-party loggers
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('playwright').setLevel(logging.WARNING)

# Initialize config
config = AppConfig()

# Expose for easy import
__all__ = ['config', 'setup_logging', 'BASE_DIR', 'DATA_DIR', 'LOGS_DIR', 'DB_DIR']