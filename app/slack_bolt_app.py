"""
Slack Bolt Socket Mode app — handles button clicks, voice clips, and text messages
for interactive Reddit engagement from Slack.
"""

import json
import logging
import threading

import requests
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

from .slack_integration import load_thread_posts, save_thread_posts

logger = logging.getLogger(__name__)

# Module-level reference so run.py can start it
_bolt_handler: SocketModeHandler = None


def _get_config():
    """Import lazily to avoid circular imports"""
    from web.app import get_config
    return get_config()


def _get_post_data(body):
    """Extract post data from button action value"""
    actions = body.get("actions", [])
    if not actions:
        return None
    value = actions[0].get("value", "{}")
    try:
        return json.loads(value)
    except Exception:
        return None


def _get_thread_ts(body):
    """Get the thread timestamp from the action message"""
    msg = body.get("message", {})
    return msg.get("ts")


def _get_channel(body):
    """Get channel ID from body"""
    ch = body.get("channel", {})
    if isinstance(ch, dict):
        return ch.get("id")
    return ch


def create_bolt_app(bot_token: str) -> App:
    """Create and configure the Slack Bolt app with all handlers"""
    bolt_app = App(token=bot_token)

    # Global middleware to log ALL incoming actions/events
    @bolt_app.middleware
    def log_all_requests(body, next, logger):
        req_type = body.get("type", "unknown")
        action_ids = [a.get("action_id", "?") for a in body.get("actions", [])]
        event_type = body.get("event", {}).get("type", "")
        logger.info(f"[BOLT MIDDLEWARE] type={req_type} actions={action_ids} event={event_type}")
        next()

    # ── Button: Upvote ──────────────────────────────────────────────
    @bolt_app.action("upvote_post")
    def handle_upvote(ack, body, say, client):
        ack()
        post_data = _get_post_data(body)
        if not post_data:
            return

        thread_ts = _get_thread_ts(body)
        channel = _get_channel(body)

        client.chat_postMessage(
            channel=channel,
            thread_ts=thread_ts,
            text="Upvoting post on Reddit...",
        )

        def _do_upvote():
            try:
                cfg = _get_config()
                from .reddit_actions import run_upvote
                success = run_upvote(
                    cfg.get("reddit_username", ""),
                    cfg.get("reddit_password", ""),
                    post_data.get("url", ""),
                    post_id_override=post_data.get("id", ""),
                )
                msg = "Upvote successful!" if success else "Upvote failed — check logs."
                client.chat_postMessage(channel=channel, thread_ts=thread_ts, text=msg)
            except Exception as e:
                logger.error(f"Upvote error: {e}")
                client.chat_postMessage(channel=channel, thread_ts=thread_ts, text=f"Upvote error: {e}")

        threading.Thread(target=_do_upvote, daemon=True).start()

    # ── Button: Comment (opens thread) ──────────────────────────────
    @bolt_app.action("reply_with_voice")
    def handle_comment_start(ack, body, client):
        ack()
        post_data = _get_post_data(body)
        if not post_data:
            return

        thread_ts = _get_thread_ts(body)
        channel = _get_channel(body)

        # Store post data in thread mapping
        thread_posts = load_thread_posts()
        if thread_ts:
            from datetime import datetime
            thread_posts[thread_ts] = {
                "post_id": post_data.get("id"),
                "post_url": post_data.get("url"),
                "post_title": post_data.get("title"),
                "post_content": post_data.get("content", ""),
                "subreddit": post_data.get("subreddit"),
                "stored_at": datetime.now().isoformat(),
            }
            save_thread_posts(thread_posts)

        client.chat_postMessage(
            channel=channel,
            thread_ts=thread_ts,
            text="Send a voice clip or text message in this thread with your comment instructions.\nExample: _\"write something supportive about their situation\"_",
        )

    # ── Button: Ignore ──────────────────────────────────────────────
    @bolt_app.action("ignore_post")
    def handle_ignore(ack, body, client):
        ack()
        post_data = _get_post_data(body)
        thread_ts = _get_thread_ts(body)
        channel = _get_channel(body)

        title = post_data.get("title", "Unknown") if post_data else "Unknown"
        client.chat_postMessage(
            channel=channel,
            thread_ts=thread_ts,
            text=f"Post ignored: _{title}_",
        )

    # ── Button: Post comment to Reddit ──────────────────────────────
    @bolt_app.action("confirm_post")
    def handle_confirm_post(ack, body, client):
        ack()
        logger.info("=== CONFIRM_POST button clicked ===")
        actions = body.get("actions", [])
        if not actions:
            logger.warning("confirm_post: no actions in body")
            return

        value = actions[0].get("value", "{}")
        try:
            data = json.loads(value)
        except Exception as e:
            logger.error(f"confirm_post: JSON parse error: {e}, value={value[:200]}")
            return

        logger.info(f"confirm_post: post_url={data.get('post_url', 'MISSING')}, comment_len={len(data.get('comment_text', ''))}")

        thread_ts = _get_thread_ts(body)
        channel = _get_channel(body)

        client.chat_postMessage(
            channel=channel,
            thread_ts=thread_ts,
            text="Posting comment to Reddit...",
        )

        def _do_comment():
            try:
                cfg = _get_config()
                username = cfg.get("reddit_username", "")
                password = cfg.get("reddit_password", "")
                logger.info(f"confirm_post: username={'SET' if username else 'EMPTY'}, password={'SET' if password else 'EMPTY'}")
                from .reddit_actions import run_comment
                success = run_comment(
                    username,
                    password,
                    data["post_url"],
                    data["comment_text"],
                )
                msg = "Comment posted successfully!" if success else "Failed to post comment — check logs."
                client.chat_postMessage(channel=channel, thread_ts=thread_ts, text=msg)
            except Exception as e:
                import traceback
                logger.error(f"Comment post error: {e}\n{traceback.format_exc()}")
                client.chat_postMessage(channel=channel, thread_ts=thread_ts, text=f"Comment error: {e}")

        threading.Thread(target=_do_comment, daemon=True).start()

    # ── Button: Regenerate comment ──────────────────────────────────
    @bolt_app.action("regenerate_comment")
    def handle_regenerate(ack, body, client):
        ack()
        actions = body.get("actions", [])
        if not actions:
            return

        value = actions[0].get("value", "{}")
        try:
            data = json.loads(value)
        except Exception:
            return

        thread_ts = _get_thread_ts(body)
        channel = _get_channel(body)

        def _do_regenerate():
            try:
                cfg = _get_config()
                from .llm_generator import LLMGenerator

                gen = LLMGenerator(
                    api_key=cfg.get("openrouter_api_key", ""),
                    model=cfg.get("openrouter_model", "meta-llama/llama-3.1-70b-instruct"),
                    persona=cfg.get("openrouter_persona", ""),
                )
                comment = gen.generate_comment(
                    post_title=data.get("post_title", ""),
                    post_content=data.get("post_content", ""),
                    subreddit=data.get("subreddit", ""),
                    user_instruction=data.get("instruction", "write a helpful comment"),
                )
                _post_comment_preview(client, channel, thread_ts, comment, data)
            except Exception as e:
                logger.error(f"Regenerate error: {e}")
                client.chat_postMessage(channel=channel, thread_ts=thread_ts, text=f"Regeneration error: {e}")

        threading.Thread(target=_do_regenerate, daemon=True).start()

    # ── Event: file_shared (voice clip) ─────────────────────────────
    @bolt_app.event("file_shared")
    def handle_file_shared(event, client):
        file_id = event.get("file_id")
        if not file_id:
            return

        # Get file info
        file_info = client.files_info(file=file_id)
        file_data = file_info.get("file", {})

        mimetype = file_data.get("mimetype", "")
        if not mimetype.startswith("audio/"):
            return  # Not an audio file, skip

        # Check if this is in a thread with a post mapping
        shares = file_data.get("shares", {})
        channel_id = None
        thread_ts = None

        # Find the thread this file was shared in
        for share_type in ("public", "private"):
            for ch_id, share_list in shares.get(share_type, {}).items():
                for share in share_list:
                    if share.get("thread_ts"):
                        channel_id = ch_id
                        thread_ts = share["thread_ts"]
                        break

        if not thread_ts:
            return

        thread_posts = load_thread_posts()
        post_info = thread_posts.get(thread_ts)
        if not post_info:
            return

        # Capture URL for background download
        download_url = file_data.get("url_private_download") or file_data.get("url_private")

        def _process_voice():
            try:
                cfg = _get_config()

                client.chat_postMessage(channel=channel_id, thread_ts=thread_ts, text="Transcribing voice clip...")

                # Try Slack's built-in transcription first (wait up to 15s)
                instruction = None
                import time
                for _ in range(5):
                    updated = client.files_info(file=file_data.get("id"))
                    transcript = updated.get("file", {}).get("transcription", {})
                    if transcript.get("status") == "complete":
                        instruction = transcript.get("preview", {}).get("content", "")
                        if instruction:
                            logger.info(f"Using Slack transcription: {instruction[:80]}...")
                            break
                    time.sleep(3)

                # Fallback to Groq Whisper if Slack transcript not available
                if not instruction:
                    headers = {"Authorization": f"Bearer {cfg.get('slack_bot_token', '')}"}
                    audio_response = requests.get(download_url, headers=headers, timeout=30)
                    audio_response.raise_for_status()
                    audio_bytes = audio_response.content

                    from .groq_transcriber import GroqTranscriber
                    transcriber = GroqTranscriber(
                        api_key=cfg.get("groq_api_key", ""),
                        language=cfg.get("groq_language", "de"),
                    )
                    filename = file_data.get("name", "audio.ogg")
                    instruction = transcriber.transcribe(audio_bytes, filename)

                client.chat_postMessage(
                    channel=channel_id,
                    thread_ts=thread_ts,
                    text=f"*Transcription:* _{instruction}_\n\nGenerating comment...",
                )

                # Generate comment
                from .llm_generator import LLMGenerator
                gen = LLMGenerator(
                    api_key=cfg.get("openrouter_api_key", ""),
                    model=cfg.get("openrouter_model", "meta-llama/llama-3.1-70b-instruct"),
                    persona=cfg.get("openrouter_persona", ""),
                )
                comment = gen.generate_comment(
                    post_title=post_info.get("post_title", ""),
                    post_content=post_info.get("post_content", ""),
                    subreddit=post_info.get("subreddit", ""),
                    user_instruction=instruction,
                )

                regen_data = {
                    "post_url": post_info.get("post_url"),
                    "post_title": post_info.get("post_title"),
                    "post_content": post_info.get("post_content"),
                    "subreddit": post_info.get("subreddit"),
                    "instruction": instruction,
                }
                _post_comment_preview(client, channel_id, thread_ts, comment, regen_data)

            except Exception as e:
                logger.error(f"Voice processing error: {e}")
                client.chat_postMessage(channel=channel_id, thread_ts=thread_ts, text=f"Error: {e}")

        threading.Thread(target=_process_voice, daemon=True).start()

    # ── Event: message (text instruction in thread) ─────────────────
    @bolt_app.event("message")
    def handle_message(event, client):
        # Only handle threaded messages
        thread_ts = event.get("thread_ts")
        if not thread_ts:
            return

        # Ignore bot messages
        if event.get("bot_id") or event.get("subtype"):
            return

        text = event.get("text", "").strip()
        if not text:
            return

        channel = event.get("channel")

        thread_posts = load_thread_posts()
        post_info = thread_posts.get(thread_ts)
        if not post_info:
            return  # Not a thread we're tracking

        cfg = _get_config()

        client.chat_postMessage(
            channel=channel,
            thread_ts=thread_ts,
            text="Generating comment...",
        )

        def _process_text():
            try:
                from .llm_generator import LLMGenerator
                gen = LLMGenerator(
                    api_key=cfg.get("openrouter_api_key", ""),
                    model=cfg.get("openrouter_model", "meta-llama/llama-3.1-70b-instruct"),
                    persona=cfg.get("openrouter_persona", ""),
                )
                comment = gen.generate_comment(
                    post_title=post_info.get("post_title", ""),
                    post_content=post_info.get("post_content", ""),
                    subreddit=post_info.get("subreddit", ""),
                    user_instruction=text,
                )

                regen_data = {
                    "post_url": post_info.get("post_url"),
                    "post_title": post_info.get("post_title"),
                    "post_content": post_info.get("post_content"),
                    "subreddit": post_info.get("subreddit"),
                    "instruction": text,
                }
                _post_comment_preview(client, channel, thread_ts, comment, regen_data)

            except Exception as e:
                logger.error(f"Text processing error: {e}")
                client.chat_postMessage(channel=channel, thread_ts=thread_ts, text=f"Error: {e}")

        threading.Thread(target=_process_text, daemon=True).start()

    return bolt_app


def _post_comment_preview(client, channel, thread_ts, comment_text, regen_data):
    """Post a comment preview with [Post to Reddit] and [Regenerate] buttons"""
    confirm_value = json.dumps({
        "post_url": regen_data.get("post_url"),
        "comment_text": comment_text,
    })
    regen_value = json.dumps(regen_data)

    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Generated Comment Preview:*\n\n{comment_text}",
            },
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Post to Reddit"},
                    "style": "primary",
                    "value": confirm_value,
                    "action_id": "confirm_post",
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Regenerate"},
                    "value": regen_value,
                    "action_id": "regenerate_comment",
                },
            ],
        },
    ]

    client.chat_postMessage(
        channel=channel,
        thread_ts=thread_ts,
        text=f"Generated comment: {comment_text[:100]}...",
        blocks=blocks,
    )


def start_bolt_socket_mode(bot_token: str, app_token: str):
    """Start Slack Bolt in Socket Mode (blocking — run in daemon thread)"""
    global _bolt_handler
    try:
        bolt_app = create_bolt_app(bot_token)
        _bolt_handler = SocketModeHandler(bolt_app, app_token)
        logger.info("Slack Bolt Socket Mode started")
        _bolt_handler.start()  # blocking
    except Exception as e:
        logger.error(f"Slack Bolt Socket Mode error: {e}")
