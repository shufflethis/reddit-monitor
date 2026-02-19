"""
Groq Whisper API transcription for voice clips
"""

import logging
from groq import Groq

logger = logging.getLogger(__name__)


class GroqTranscriber:
    """Transcribe audio using Groq's Whisper API"""

    def __init__(self, api_key: str, language: str = "en"):
        self.client = Groq(api_key=api_key)
        self.language = language

    def transcribe(self, audio_bytes: bytes, filename: str = "audio.ogg") -> str:
        """Transcribe audio bytes to text via Groq whisper-large-v3"""
        try:
            transcription = self.client.audio.transcriptions.create(
                file=(filename, audio_bytes),
                model="whisper-large-v3",
                language=self.language,
                response_format="text",
            )
            text = transcription.strip() if isinstance(transcription, str) else str(transcription).strip()
            logger.info(f"Transcribed audio ({len(audio_bytes)} bytes): {text[:80]}...")
            return text
        except Exception as e:
            logger.error(f"Groq transcription error: {e}")
            raise
