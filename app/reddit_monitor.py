"""
Reddit monitor core functionality
"""

import asyncio
import logging
from datetime import datetime, time
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum
import json

from playwright.async_api import async_playwright, Browser, Page

from .config import config

logger = logging.getLogger(__name__)

class PostStatus(Enum):
    """Status of a monitored post"""
    NEW = "new"
    SEEN = "seen"
    REPLIED = "replied"
    IGNORED = "ignored"

@dataclass
class RedditPost:
    """Represents a Reddit post"""
    id: str
    title: str
    content: str
    url: str
    subreddit: str
    author: str
    upvotes: int
    created_utc: float
    flair: Optional[str] = None
    comments_count: int = 0
    status: PostStatus = PostStatus.NEW
    matched_keywords: List[str] = None
    
    def __post_init__(self):
        if self.matched_keywords is None:
            self.matched_keywords = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'id': self.id,
            'title': self.title,
            'content': self.content[:500] + '...' if len(self.content) > 500 else self.content,
            'url': self.url,
            'subreddit': self.subreddit,
            'author': self.author,
            'upvotes': self.upvotes,
            'created_utc': self.created_utc,
            'flair': self.flair,
            'comments_count': self.comments_count,
            'status': self.status.value,
            'matched_keywords': self.matched_keywords
        }

class RedditMonitor:
    """Main Reddit monitoring class"""
    
    def __init__(self):
        self.browser: Optional[Browser] = None
        self.page: Optional[Page] = None
        self.logged_in = False
        self.last_scan_time: Optional[datetime] = None
        self.seen_posts: Dict[str, datetime] = {}
        self.replied_posts: Dict[str, datetime] = {}
        
    async def start(self):
        """Start the monitor"""
        playwright = await async_playwright().start()
        self.browser = await playwright.chromium.launch(headless=config.reddit.headless)
        self.page = await self.browser.new_page()
        
        # Set user agent to avoid detection
        await self.page.set_extra_http_headers({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        logger.info("Reddit monitor started")
        
    async def stop(self):
        """Stop the monitor"""
        if self.browser:
            await self.browser.close()
        logger.info("Reddit monitor stopped")
        
    async def login(self, username: str, password: str):
        """Login to Reddit"""
        logger.info(f"Attempting login for user: {username}")
        
        try:
            # Navigate to login page
            await self.page.goto("https://www.reddit.com/login")
            await self.page.wait_for_load_state('networkidle')
            
            # Fill login form
            await self.page.fill('input[name="username"]', username)
            await self.page.fill('input[name="password"]', password)
            await self.page.click('button[type="submit"]')
            
            # Wait for login to complete
            await self.page.wait_for_timeout(3000)
            
            # Check if login was successful
            try:
                await self.page.wait_for_selector('header', timeout=5000)
                self.logged_in = True
                logger.info("Login successful")
                return True
            except:
                logger.error("Login failed - check credentials")
                return False
                
        except Exception as e:
            logger.error(f"Login error: {e}")
            return False
    
    def check_guardrails(self, post: RedditPost) -> bool:
        """Check if post passes all guardrails"""
        cfg = config.reddit
        
        # Minimum upvotes
        if post.upvotes < cfg.min_upvotes:
            logger.debug(f"Post {post.id} failed min_upvotes: {post.upvotes} < {cfg.min_upvotes}")
            return False
        
        # Required flairs
        if cfg.required_flairs and (not post.flair or post.flair not in cfg.required_flairs):
            logger.debug(f"Post {post.id} failed required_flairs: {post.flair} not in {cfg.required_flairs}")
            return False
        
        # Excluded flairs
        if cfg.exclude_flairs and post.flair in cfg.exclude_flairs:
            logger.debug(f"Post {post.id} failed exclude_flairs: {post.flair} in {cfg.exclude_flairs}")
            return False
        
        # Keywords check
        text_to_check = f"{post.title} {post.content}".lower()
        
        # Exclude keywords (fail fast)
        for keyword in cfg.exclude_keywords:
            if keyword.lower() in text_to_check:
                logger.debug(f"Post {post.id} contains excluded keyword: {keyword}")
                return False
        
        # Required keywords
        matched_keywords = []
        for keyword in cfg.keywords:
            if keyword.lower() in text_to_check:
                matched_keywords.append(keyword)
        
        if cfg.keywords and not matched_keywords:
            logger.debug(f"Post {post.id} has no required keywords")
            return False
        
        post.matched_keywords = matched_keywords
        return True
    
    async def scan_subreddit(self, subreddit: str) -> List[RedditPost]:
        """Scan a subreddit for new posts"""
        logger.info(f"Scanning subreddit: {subreddit}")
        
        try:
            # Navigate to subreddit
            url = f"https://www.reddit.com/r/{subreddit}/new/"
            await self.page.goto(url)
            await self.page.wait_for_load_state('networkidle')
            
            # Wait for posts to load
            await self.page.wait_for_selector('div[data-testid="post-container"]', timeout=10000)
            
            # Extract posts
            posts = []
            
            # Get post elements
            post_elements = await self.page.query_selector_all('div[data-testid="post-container"]')
            
            for element in post_elements[:20]:  # Limit to first 20 posts
                try:
                    # Extract post data
                    post_id = await element.get_attribute('id') or ''
                    if not post_id.startswith('t3_'):
                        continue
                    
                    # Get title
                    title_elem = await element.query_selector('h3')
                    title = await title_elem.text_content() if title_elem else "No title"
                    
                    # Get content (first paragraph)
                    content_elem = await element.query_selector('div[data-testid="post-content"] p')
                    content = await content_elem.text_content() if content_elem else ""
                    
                    # Get URL
                    link_elem = await element.query_selector('a[data-testid="post-title"]')
                    href = await link_elem.get_attribute('href') if link_elem else ""
                    url = f"https://www.reddit.com{href}" if href and href.startswith('/') else href or ""
                    
                    # Get author
                    author_elem = await element.query_selector('a[data-testid="post_author_link"]')
                    author = await author_elem.text_content() if author_elem else "[deleted]"
                    
                    # Get upvotes
                    vote_elem = await element.query_selector('div[data-testid="vote-arrows"] + div')
                    upvotes_text = await vote_elem.text_content() if vote_elem else "0"
                    upvotes = 0
                    try:
                        if 'k' in upvotes_text:
                            upvotes = int(float(upvotes_text.replace('k', '').replace(',', '')) * 1000)
                        else:
                            upvotes = int(upvotes_text.replace(',', ''))
                    except:
                        upvotes = 0
                    
                    # Get flair
                    flair_elem = await element.query_selector('span[data-testid="flair"]')
                    flair = await flair_elem.text_content() if flair_elem else None
                    
                    # Get comment count
                    comments_elem = await element.query_selector('a[data-testid="comments"]')
                    comments_text = await comments_elem.text_content() if comments_elem else "0 comments"
                    comments_count = 0
                    try:
                        comments_count = int(''.join(filter(str.isdigit, comments_text)))
                    except:
                        comments_count = 0
                    
                    post = RedditPost(
                        id=post_id.replace('t3_', ''),
                        title=title,
                        content=content,
                        url=url,
                        subreddit=subreddit,
                        author=author,
                        upvotes=upvotes,
                        created_utc=datetime.now().timestamp(),
                        flair=flair,
                        comments_count=comments_count
                    )
                    
                    posts.append(post)
                    
                except Exception as e:
                    logger.debug(f"Error extracting post: {e}")
                    continue
            
            logger.info(f"Found {len(posts)} posts in r/{subreddit}")
            return posts
            
        except Exception as e:
            logger.error(f"Error scanning subreddit r/{subreddit}: {e}")
            return []
    
    async def scan_all(self) -> List[RedditPost]:
        """Scan all configured subreddits"""
        if not self.logged_in and config.reddit.username and config.reddit.password:
            success = await self.login(config.reddit.username, config.reddit.password)
            if not success:
                logger.error("Cannot scan without login")
                return []
        
        all_posts = []
        for subreddit in config.reddit.subreddits:
            posts = await self.scan_subreddit(subreddit)
            
            # Filter by guardrails
            filtered_posts = []
            for post in posts:
                if self.check_guardrails(post):
                    filtered_posts.append(post)
            
            logger.info(f"r/{subreddit}: {len(posts)} total, {len(filtered_posts)} passed guardrails")
            all_posts.extend(filtered_posts)
        
        self.last_scan_time = datetime.now()
        return all_posts
    
    async def reply_to_post(self, post: RedditPost, reply_text: str) -> bool:
        """Reply to a Reddit post"""
        if not self.logged_in:
            logger.error("Cannot reply without login")
            return False
        
        try:
            # Navigate to post
            await self.page.goto(post.url)
            await self.page.wait_for_load_state('networkidle')
            
            # Find reply box
            reply_box = await self.page.wait_for_selector('div[data-testid="comment"] textarea', timeout=5000)
            await reply_box.click()
            await reply_box.fill(reply_text)
            
            # Submit reply
            submit_button = await self.page.wait_for_selector('button[type="submit"]', timeout=5000)
            await submit_button.click()
            
            # Wait for reply to be posted
            await self.page.wait_for_timeout(3000)
            
            logger.info(f"Replied to post: {post.id}")
            self.replied_posts[post.id] = datetime.now()
            return True
            
        except Exception as e:
            logger.error(f"Error replying to post {post.id}: {e}")
            return False

# Singleton instance
monitor = RedditMonitor()