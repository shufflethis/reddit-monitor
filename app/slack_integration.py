"""
Slack integration for reddit-monitor
Supports both Bot Token (preferred) and Webhook fallback.
Rich Block Kit messages with images and action buttons.
"""

import json
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from slack_sdk import WebClient
from slack_sdk.webhook import WebhookClient

from .config import config, DATA_DIR
from .reddit_monitor import RedditPost

logger = logging.getLogger(__name__)

THREAD_POSTS_FILE = DATA_DIR / "thread_posts.json"
_thread_posts_lock = threading.Lock()


def load_thread_posts() -> dict:
    """Load thread-to-post mapping (thread-safe)"""
    with _thread_posts_lock:
        if THREAD_POSTS_FILE.exists():
            try:
                with open(THREAD_POSTS_FILE, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return {}


def save_thread_posts(data: dict):
    """Save thread-to-post mapping, pruning entries older than 7 days (thread-safe)"""
    with _thread_posts_lock:
        cutoff = datetime.now().timestamp() - 7 * 86400
        pruned = {}
        for ts, entry in data.items():
            try:
                if datetime.fromisoformat(entry.get("stored_at", "")).timestamp() > cutoff:
                    pruned[ts] = entry
            except Exception:
                pruned[ts] = entry
        THREAD_POSTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(THREAD_POSTS_FILE, 'w') as f:
            json.dump(pruned, f, indent=2, default=str)


class SlackNotifier:
    """Handle Slack notifications and interactions"""

    def __init__(self, bot_token: str = None, channel_id: str = None, webhook_url: str = None):
        self.client: Optional[WebClient] = None
        self.webhook: Optional[WebhookClient] = None
        self.channel_id = channel_id

        if bot_token:
            self.client = WebClient(token=bot_token)
            logger.info(f"Slack bot token configured (channel: {channel_id})")
        elif webhook_url:
            self.webhook = WebhookClient(webhook_url)
            logger.info("Slack webhook configured (fallback)")

    def post_to_slack(self, message: str, blocks: list = None, attachments: list = None) -> Optional[str]:
        """Post message to Slack. Returns message ts on success, None on failure."""
        try:
            if self.client and self.channel_id:
                kwargs = {
                    "channel": self.channel_id,
                    "text": message,
                    "unfurl_links": False,
                    "unfurl_media": True,
                }
                if blocks:
                    kwargs["blocks"] = blocks
                if attachments:
                    kwargs["attachments"] = attachments

                response = self.client.chat_postMessage(**kwargs)
                if response["ok"]:
                    logger.info(f"Posted to Slack (bot): {message[:50]}...")
                    return response["ts"]
                else:
                    logger.error(f"Slack API error: {response.get('error')}")
                    return None
            elif self.webhook:
                response = self.webhook.send(text=message)
                if response.status_code == 200:
                    logger.info(f"Posted to Slack (webhook): {message[:50]}...")
                    return "webhook"
                else:
                    logger.error(f"Slack webhook error: {response.body}")
                    return None
            else:
                logger.warning("No Slack credentials configured")
                return None

        except Exception as e:
            logger.error(f"Error posting to Slack: {e}")
            return None

    def _build_post_blocks(self, post: RedditPost) -> tuple:
        """Build Slack Block Kit blocks for a Reddit post. Returns (blocks, fallback_text)."""
        flair_str = f" | Flair: {post.flair}" if post.flair else ""
        keywords_str = f" | Keywords: {', '.join(post.matched_keywords)}" if post.matched_keywords else ""
        content_str = post.content[:500] + '...' if len(post.content) > 500 else post.content if post.content else ''

        # Post data for button values
        post_value = json.dumps({
            "id": post.id,
            "url": post.url,
            "title": post.title,
            "content": post.content[:1000] if post.content else "",
            "subreddit": post.subreddit,
        })

        blocks = []

        # Header
        blocks.append({
            "type": "header",
            "text": {"type": "plain_text", "text": post.title[:150], "emoji": True}
        })

        # Post meta info
        meta = f"*r/{post.subreddit}* | u/{post.author} | {post.upvotes} upvotes | {post.comments_count} comments{flair_str}{keywords_str}"
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": meta}]
        })

        # Content
        if content_str:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": content_str}
            })

        # Image
        img_url = post.thumbnail or ""
        if img_url.startswith('//'):
            img_url = f'https:{img_url}'
        if img_url.startswith('http'):
            blocks.append({
                "type": "image",
                "image_url": img_url,
                "alt_text": post.title[:75],
            })

        # Link
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"<{post.url}|View on Reddit>"}
        })

        blocks.append({"type": "divider"})

        # Action buttons
        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Upvote", "emoji": True},
                    "value": post_value,
                    "action_id": "upvote_post",
                    "style": "primary",
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Comment", "emoji": True},
                    "value": post_value,
                    "action_id": "reply_with_voice",
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Ignore", "emoji": True},
                    "value": post_value,
                    "action_id": "ignore_post",
                    "style": "danger",
                },
            ]
        })

        fallback = f"New post in r/{post.subreddit}: {post.title}"
        return blocks, fallback

    def notify_new_posts(self, posts: List[RedditPost]):
        """Notify about new posts that passed guardrails, storing thread mapping"""
        if not posts:
            return

        thread_posts = load_thread_posts()

        for post in posts:
            blocks, fallback = self._build_post_blocks(post)
            msg_ts = self.post_to_slack(fallback, blocks=blocks)

            if msg_ts and msg_ts != "webhook":
                thread_posts[msg_ts] = {
                    "post_id": post.id,
                    "post_url": post.url,
                    "post_title": post.title,
                    "post_content": post.content[:1000] if post.content else "",
                    "subreddit": post.subreddit,
                    "author": post.author,
                    "stored_at": datetime.now().isoformat(),
                }

        save_thread_posts(thread_posts)

    def notify_replies(self, replies: List[Dict[str, Any]]):
        """Send Slack notifications for Reddit comment replies"""
        if not replies:
            return

        for reply in replies:
            body = reply.get("body", "")
            if len(body) > 500:
                body = body[:500] + "..."

            blocks = [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "Reply auf deinen Kommentar",
                        "emoji": True,
                    },
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": (
                                f"*r/{reply.get('subreddit', '?')}* | "
                                f"Post: {reply.get('link_title', '?')} | "
                                f"von u/{reply.get('author', '?')}"
                            ),
                        }
                    ],
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": body or "(empty)"},
                },
            ]

            context_url = reply.get("context", "")
            if context_url:
                blocks.append({
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "text": "Auf Reddit ansehen",
                                "emoji": True,
                            },
                            "url": context_url,
                            "action_id": "view_reply_on_reddit",
                        }
                    ],
                })

            blocks.append({"type": "divider"})

            fallback = f"Reply von u/{reply.get('author', '?')} in r/{reply.get('subreddit', '?')}"
            self.post_to_slack(fallback, blocks=blocks)

    def handle_voice_reply(self, post_id: str, voice_audio_url: str, transcript: str) -> bool:
        """Handle voice reply from Slack"""
        logger.info(f"Handling voice reply for post {post_id}")
        confirmation = f"*Voice Reply Processed*\n*Post ID:* {post_id}\n*Transcript:* {transcript[:100]}..."
        return self.post_to_slack(confirmation) is not None

    def send_status_update(self, status: str):
        """Send status update to Slack"""
        self.post_to_slack(f"*Reddit Monitor Status Update*\n{status}")


# Singleton instance
slack_notifier = SlackNotifier()
