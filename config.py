import os
from pathlib import Path

DB_PATH = os.environ.get("SENT_DB", str(Path(__file__).parent / "sent.db"))
SCORE_THRESHOLD = float(os.environ.get("SENT_THRESHOLD", "8.0"))
SCORE_ALPHA = float(os.environ.get("SENT_ALPHA", "0.5"))
POLL_INTERVAL = int(os.environ.get("SENT_POLL_INTERVAL", "60"))
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
# AI backend: "claude-code", "api", "auto" (tries claude-code first, then api, then rules)
AI_BACKEND = os.environ.get("SENT_AI_BACKEND", "auto")
PACKAGE_CACHE_DIR = Path(os.environ.get("SENT_CACHE", str(Path(__file__).parent / ".cache")))
PACKAGE_CACHE_DIR.mkdir(exist_ok=True)
