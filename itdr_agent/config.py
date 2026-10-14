"""Configuration — loaded from .env with sensible defaults."""

import os

from dotenv import load_dotenv

# Load .env if present; silently skip if missing.
load_dotenv()

TIMEOUT_SECONDS: int = int(os.getenv("TIMEOUT_SECONDS", "120"))
OPENROUTER_API_KEY: str | None = os.getenv("OPENROUTER_API_KEY")

# Output cap on every model call. Without it OpenRouter reserves the model's
# whole context window per request, and a key with a spending limit gets 402.
MAX_OUTPUT_TOKENS: int = 8192
