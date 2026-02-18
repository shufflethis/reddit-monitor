"""
Slack integration for reddit-monitor
"""

import logging
from typing import List, Dict, Any
from slack_sdk import WebClient
from slack_sdk.webhook import WebhookClient

from .config import config
from .reddit_monitor import RedditPost

logger = logging.getLogger(__name__)

class SlackNotifier:
    """Handle Slack notifications and interactions"""
    
    def __init__(self):
        self.webhook = None
        self.client = None
        
        if config.slack.webhook_url:
            self.webhook = WebhookClient(config.slack.webhook_url)
            logger.info("Slack webhook configured")
        
    def post_to_slack(self, message: str, attachments: List[Dict[str, Any]] = None) -> bool:
        """Post message to Slack channel"""
        if not self.webhook:
            logger.warning("No Slack webhook configured")
            return False
        
        try:
            response = self.webhook.send(
                text=message,
                attachments=attachments or []
            )
            
            if response.status_code == 200:
                logger.info(f"Posted to Slack: {message[:50]}...")
                return True
            else:
                logger.error(f"Slack API error: {response.body}")
                return False
                
        except Exception as e:
            logger.error(f"Error posting to Slack: {e}")
            return False
    
    def format_post_message(self, post: RedditPost) -> str:
        """Format Reddit post for Slack message"""
        flair_str = f" • Flair: {post.flair}" if post.flair else ""
        keywords_str = f" • Keywords: {', '.join(post.matched_keywords)}" if post.matched_keywords else ""
        
        message = f"""
🚨 *New Reddit Post Found!*

*Title:* {post.title}
*Subreddit:* r/{post.subreddit}
*Author:* u/{post.author}
*Upvotes:* {post.upvotes} • Comments: {post.comments_count}{flair_str}{keywords_str}

*Content:* {post.content[:200]}...

<{post.url}|View on Reddit>
"""
        return message.strip()
    
    def format_attachments(self, post: RedditPost) -> List[Dict[str, Any]]:
        """Format Slack attachments for post"""
        attachments = [
            {
                "color": "#36a64f",  # Green
                "blocks": [
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "text": "Reply with Voice",
                                    "emoji": True
                                },
                                "value": f"reply_{post.id}",
                                "action_id": "reply_with_voice"
                            },
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "text": "Ignore Post",
                                    "emoji": True
                                },
                                "value": f"ignore_{post.id}",
                                "action_id": "ignore_post"
                            }
                        ]
                    }
                ]
            }
        ]
        return attachments
    
    def notify_new_posts(self, posts: List[RedditPost]):
        """Notify about new posts that passed guardrails"""
        if not posts:
            return
        
        for post in posts:
            message = self.format_post_message(post)
            attachments = self.format_attachments(post)
            self.post_to_slack(message, attachments)
    
    def handle_voice_reply(self, post_id: str, voice_audio_url: str, transcript: str) -> bool:
        """Handle voice reply from Slack"""
        logger.info(f"Handling voice reply for post {post_id}")
        
        # Here you would:
        # 1. Use the transcript to generate a reply
        # 2. Post to Reddit
        # 3. Send confirmation to Slack
        
        confirmation = f"""
🎤 *Voice Reply Processed*

*Post ID:* {post_id}
*Transcript:* {transcript[:100]}...

Reply will be posted to Reddit shortly.
"""
        
        return self.post_to_slack(confirmation)
    
    def send_status_update(self, status: str):
        """Send status update to Slack"""
        message = f"""
📊 *Reddit Monitor Status Update*

{status}
"""
        self.post_to_slack(message)

# Singleton instance
slack_notifier = SlackNotifier()