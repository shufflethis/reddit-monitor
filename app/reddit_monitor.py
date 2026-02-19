"""
Reddit monitor core functionality
"""

import asyncio
import logging
import random
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
    thumbnail: Optional[str] = None

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
            'matched_keywords': self.matched_keywords,
            'thumbnail': self.thumbnail,
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
        
        # Set realistic user agent to avoid detection
        await self.page.set_extra_http_headers({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Accept-Language': 'en-US,en;q=0.9,de;q=0.8',
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
    
    async def scan_subreddit(self, subreddit: str, retry: int = 0) -> List[RedditPost]:
        """Scan a subreddit for new posts using old.reddit.com (more stable)"""
        logger.info(f"Scanning subreddit: {subreddit}")

        try:
            # Use old.reddit.com - much more stable for scraping
            url = f"https://old.reddit.com/r/{subreddit}/new/"
            response = await self.page.goto(url, timeout=20000)

            # Check for errors - retry on 403 (rate limit)
            if response and response.status == 403 and retry < 2:
                wait = (retry + 1) * 15 + random.randint(5, 15)
                logger.warning(f"r/{subreddit} returned 403 - waiting {wait}s before retry {retry + 1}/2")
                await asyncio.sleep(wait)
                return await self.scan_subreddit(subreddit, retry=retry + 1)

            if response and response.status >= 400:
                logger.warning(f"Subreddit r/{subreddit} returned HTTP {response.status} - skipping")
                return []

            await self.page.wait_for_load_state('domcontentloaded')

            # Quick check for error page or private subreddit
            page_content = await self.page.content()
            if 'private' in page_content.lower() or 'banned' in page_content.lower() or 'error' in page_content[:500].lower():
                logger.warning(f"Subreddit r/{subreddit} appears private/banned - skipping")
                return []

            # Wait for posts to load (shorter timeout)
            try:
                await self.page.wait_for_selector('div.thing', timeout=8000)
            except:
                logger.warning(f"No posts found in r/{subreddit} - may be empty or restricted")
                return []

            # Extract posts
            posts = []

            # Get post elements from old reddit
            post_elements = await self.page.query_selector_all('div.thing.link')

            for element in post_elements[:20]:  # Limit to first 20 posts
                try:
                    # Extract post ID
                    post_id = await element.get_attribute('data-fullname') or ''
                    if not post_id.startswith('t3_'):
                        continue

                    # Get title
                    title_elem = await element.query_selector('a.title')
                    title = await title_elem.text_content() if title_elem else "No title"

                    # Get URL
                    href = await title_elem.get_attribute('href') if title_elem else ""
                    post_url = href if href and href.startswith('http') else f"https://old.reddit.com{href}" if href else ""

                    # Get author
                    author_elem = await element.query_selector('a.author')
                    author = await author_elem.text_content() if author_elem else "[deleted]"

                    # Get upvotes (score)
                    score_elem = await element.query_selector('div.score.unvoted')
                    upvotes_text = await score_elem.get_attribute('title') if score_elem else "0"
                    upvotes = 0
                    try:
                        upvotes = int(upvotes_text) if upvotes_text else 0
                    except:
                        # Try alternate score location
                        score_elem2 = await element.query_selector('div.score.likes')
                        if score_elem2:
                            upvotes_text = await score_elem2.text_content() or "0"
                            try:
                                upvotes = int(upvotes_text.replace(',', ''))
                            except:
                                upvotes = 0

                    # Get flair
                    flair_elem = await element.query_selector('span.linkflairlabel')
                    flair = await flair_elem.text_content() if flair_elem else None

                    # Get comment count
                    comments_elem = await element.query_selector('a.comments')
                    comments_text = await comments_elem.text_content() if comments_elem else "0 comments"
                    comments_count = 0
                    try:
                        # Extract number from "XX comments"
                        num_str = ''.join(filter(str.isdigit, comments_text.split()[0]))
                        comments_count = int(num_str) if num_str else 0
                    except:
                        comments_count = 0

                    # Get timestamp
                    time_elem = await element.query_selector('time')
                    created_utc = datetime.now().timestamp()
                    if time_elem:
                        datetime_attr = await time_elem.get_attribute('datetime')
                        if datetime_attr:
                            try:
                                created_utc = datetime.fromisoformat(datetime_attr.replace('Z', '+00:00')).timestamp()
                            except:
                                pass

                    # Get thumbnail/image URL
                    thumbnail = None
                    thumb_elem = await element.query_selector('a.thumbnail img')
                    if thumb_elem:
                        thumb_src = await thumb_elem.get_attribute('src')
                        if thumb_src and ('redditmedia' in thumb_src or 'redd.it' in thumb_src):
                            thumbnail = thumb_src
                    # Also check data-url for direct image links
                    data_url = await element.get_attribute('data-url')
                    if data_url and any(data_url.endswith(ext) for ext in ('.jpg', '.jpeg', '.png', '.gif', '.webp')):
                        thumbnail = data_url
                    elif data_url and 'i.redd.it' in (data_url or ''):
                        thumbnail = data_url

                    # Fix protocol-relative URLs
                    if thumbnail and thumbnail.startswith('//'):
                        thumbnail = f'https:{thumbnail}'

                    post = RedditPost(
                        id=post_id.replace('t3_', ''),
                        title=title.strip(),
                        content="",  # Old reddit doesn't show content in list view
                        url=post_url,
                        subreddit=subreddit,
                        author=author,
                        upvotes=upvotes,
                        created_utc=created_utc,
                        flair=flair,
                        comments_count=comments_count,
                        thumbnail=thumbnail,
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
    
    async def fetch_post_content(self, post: 'RedditPost') -> str:
        """Navigate to individual post page and extract selftext + image"""
        try:
            # Try JSON API first for content + images (faster, more reliable)
            import requests as http_req
            json_url = f"https://old.reddit.com/by_id/t3_{post.id}.json"
            headers = {"User-Agent": "Mozilla/5.0 (compatible; RedditMonitor/1.0)"}
            resp = http_req.get(json_url, headers=headers, timeout=10)
            content = ""

            if resp.status_code == 200:
                data = resp.json()
                children = data.get("data", {}).get("children", [])
                if children:
                    post_data = children[0].get("data", {})
                    content = post_data.get("selftext", "").strip()

                    # Get preview image (high quality)
                    if not post.thumbnail or 'thumbs.redditmedia' in (post.thumbnail or ''):
                        preview = post_data.get("preview", {})
                        images = preview.get("images", [])
                        if images:
                            # Get source (full resolution) image
                            source = images[0].get("source", {})
                            img_url = source.get("url", "").replace("&amp;", "&")
                            if img_url:
                                post.thumbnail = img_url

                    # For gallery posts, get first gallery image
                    if not post.thumbnail and post_data.get("is_gallery"):
                        gallery_data = post_data.get("gallery_data", {})
                        media_metadata = post_data.get("media_metadata", {})
                        items = gallery_data.get("items", [])
                        if items and media_metadata:
                            first_id = items[0].get("media_id")
                            if first_id and first_id in media_metadata:
                                media = media_metadata[first_id]
                                # Get the largest preview
                                previews = media.get("p", [])
                                if previews:
                                    img_url = previews[-1].get("u", "").replace("&amp;", "&")
                                    if img_url:
                                        post.thumbnail = img_url
                                # Or source image
                                if not post.thumbnail:
                                    source = media.get("s", {})
                                    img_url = source.get("u", "").replace("&amp;", "&")
                                    if img_url:
                                        post.thumbnail = img_url

                    # Direct image URL (i.redd.it)
                    if not post.thumbnail:
                        url_str = post_data.get("url", "")
                        if 'i.redd.it' in url_str or 'i.imgur.com' in url_str:
                            post.thumbnail = url_str

            # Fallback: scrape the page
            if not content:
                post_url = post.url
                if 'old.reddit.com' not in post_url:
                    post_url = post_url.replace('www.reddit.com', 'old.reddit.com')
                    if 'old.reddit.com' not in post_url:
                        post_url = post_url.replace('reddit.com', 'old.reddit.com')

                await self.page.goto(post_url, timeout=15000)
                await self.page.wait_for_load_state('domcontentloaded')

                content_elem = await self.page.query_selector('div.thing.link div.usertext-body div.md')
                if content_elem:
                    text = await content_elem.text_content()
                    content = text.strip() if text else ""

            # Fix protocol-relative URLs
            if post.thumbnail and post.thumbnail.startswith('//'):
                post.thumbnail = f'https:{post.thumbnail}'

            return content
        except Exception as e:
            logger.debug(f"Could not fetch content for post {post.id}: {e}")
            return ""

    async def scan_all(self) -> List[RedditPost]:
        """Scan all configured subreddits"""
        # Login is optional - public subreddits can be scraped without login
        if not self.logged_in and config.reddit.username and config.reddit.password:
            success = await self.login(config.reddit.username, config.reddit.password)
            if not success:
                logger.warning("Login failed - continuing without login (public subreddits only)")
                # Don't return empty - try to scan public subreddits anyway

        all_posts = []
        for i, subreddit in enumerate(config.reddit.subreddits):
            # Random delay between subreddits to avoid rate limiting
            if i > 0:
                delay = random.uniform(3, 8)
                logger.debug(f"Waiting {delay:.1f}s before next subreddit")
                await asyncio.sleep(delay)

            posts = await self.scan_subreddit(subreddit)

            # Filter by guardrails
            filtered_posts = []
            for post in posts:
                if self.check_guardrails(post):
                    filtered_posts.append(post)

            logger.info(f"r/{subreddit}: {len(posts)} total, {len(filtered_posts)} passed guardrails")

            # Fetch full content for posts that passed guardrails
            for post in filtered_posts:
                if not post.content:
                    delay = random.uniform(1, 3)
                    await asyncio.sleep(delay)
                    post.content = await self.fetch_post_content(post)

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