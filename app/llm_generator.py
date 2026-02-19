"""
OpenRouter LLM comment generation
"""

import logging
import requests

logger = logging.getLogger(__name__)


class LLMGenerator:
    """Generate Reddit comments using OpenRouter API"""

    def __init__(self, api_key: str, model: str = "meta-llama/llama-3.1-70b-instruct", persona: str = ""):
        self.api_key = api_key
        self.model = model
        self.persona = persona

    def generate_comment(self, post_title: str, post_content: str, subreddit: str, user_instruction: str) -> str:
        """Generate a Reddit comment using OpenRouter chat completions"""
        system_prompt = (
            "You are a Reddit user writing a comment on a post. "
            "Write naturally and conversationally, matching the tone of the subreddit. "
            "Keep your response concise and relevant. Do NOT use markdown formatting. "
            "Do NOT include any meta-commentary about being an AI."
        )
        if self.persona:
            system_prompt += f"\n\nYour persona/writing style: {self.persona}"

        user_prompt = (
            f"Subreddit: r/{subreddit}\n"
            f"Post Title: {post_title}\n"
        )
        if post_content:
            user_prompt += f"Post Content: {post_content[:1000]}\n"
        user_prompt += f"\nInstruction: {user_instruction}\n\nWrite the comment:"

        try:
            response = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "max_tokens": 500,
                    "temperature": 0.8,
                },
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()
            comment = data["choices"][0]["message"]["content"].strip()
            logger.info(f"Generated comment ({len(comment)} chars) for r/{subreddit}: {comment[:80]}...")
            return comment
        except Exception as e:
            logger.error(f"OpenRouter LLM error: {e}")
            raise
