from __future__ import annotations

"""
Suspicious pattern detection engine.

Operates ONLY on newly introduced lines (added/modified).
Each pattern has a category, regex, and risk score.
"""

import re
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Pattern definitions — each pattern carries a risk weight
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PatternRule:
    category: str
    name: str
    regex: re.Pattern
    score: int
    description: str


PATTERNS: list[PatternRule] = [
    # ---- Code execution ----
    PatternRule("execution", "eval_call",
                re.compile(r'\beval\s*\('), 20,
                "eval() call — arbitrary code execution"),
    PatternRule("execution", "exec_call",
                re.compile(r'\bexec\s*\('), 20,
                "exec() call — arbitrary code execution"),
    PatternRule("execution", "compile_call",
                re.compile(r'\bcompile\s*\('), 10,
                "compile() call — dynamic code compilation"),
    PatternRule("execution", "dynamic_import",
                re.compile(r'__import__\s*\(|importlib\.import_module\s*\('), 15,
                "Dynamic import — runtime module loading"),
    PatternRule("execution", "subprocess",
                re.compile(r'subprocess\.(run|call|Popen|check_output)\s*\(|os\.system\s*\(|os\.popen\s*\('), 15,
                "Subprocess/system execution"),

    # ---- Obfuscation ----
    PatternRule("obfuscation", "base64_decode",
                re.compile(r'base64\.(b64decode|decodebytes|urlsafe_b64decode)\s*\(|atob\s*\('), 15,
                "Base64 decoding — possible obfuscated payload"),
    PatternRule("obfuscation", "zlib_decompress",
                re.compile(r'zlib\.decompress\s*\(|gzip\.decompress\s*\('), 10,
                "Compression decompression — possible obfuscated data"),
    PatternRule("obfuscation", "long_string",
                re.compile(r'["\'][A-Za-z0-9+/=]{100,}["\']'), 15,
                "Long encoded string literal"),
    PatternRule("obfuscation", "hex_decode",
                re.compile(r'bytes\.fromhex\s*\(|codecs\.decode\s*\([^)]*hex'), 10,
                "Hex decoding"),
    PatternRule("obfuscation", "char_join",
                re.compile(r'""\.join\s*\(\s*\[?\s*chr\s*\(|String\.fromCharCode'), 15,
                "Character-by-character string construction"),

    # ---- Network activity ----
    PatternRule("network", "requests_lib",
                re.compile(r'\brequests\.(get|post|put|delete|head|patch|session)\s*\('), 10,
                "HTTP request via requests library"),
    PatternRule("network", "urllib_call",
                re.compile(r'urllib\.(request\.urlopen|request\.Request)\s*\(|urlopen\s*\('), 10,
                "HTTP request via urllib"),
    PatternRule("network", "http_client",
                re.compile(r'http\.client\.HTTP'), 10,
                "HTTP request via http.client"),
    PatternRule("network", "socket_create",
                re.compile(r'socket\.socket\s*\(|socket\.create_connection\s*\('), 10,
                "Raw socket creation"),
    PatternRule("network", "external_url",
                re.compile(r'https?://(?!localhost|127\.0\.0\.1|example\.com)[^\s\'">,]+'), 8,
                "External URL reference"),
    PatternRule("network", "dns_lookup",
                re.compile(r'socket\.getaddrinfo\s*\(|socket\.gethostbyname\s*\('), 8,
                "DNS resolution"),
    PatternRule("network", "fetch_call",
                re.compile(r'\bfetch\s*\('), 10,
                "fetch() call (JS network request)"),
    PatternRule("network", "xmlhttp",
                re.compile(r'XMLHttpRequest|\.open\s*\(\s*["\'](?:GET|POST)'), 10,
                "XMLHttpRequest usage"),

    # ---- Sensitive access ----
    PatternRule("sensitive", "env_access",
                re.compile(r'os\.environ|process\.env|getenv\s*\('), 25,
                "Environment variable access — possible credential theft"),
    PatternRule("sensitive", "ssh_access",
                re.compile(r'[~/]\.ssh|id_rsa|id_ed25519|authorized_keys'), 25,
                "SSH key/config access"),
    PatternRule("sensitive", "aws_creds",
                re.compile(r'[~/]\.aws|AWS_SECRET|AWS_ACCESS_KEY|aws_session_token', re.IGNORECASE), 25,
                "AWS credential access"),
    PatternRule("sensitive", "token_pattern",
                re.compile(r'(?:api[_-]?key|token|secret|password|credential)\s*[=:]', re.IGNORECASE), 15,
                "Possible hardcoded credential/token"),
    PatternRule("sensitive", "file_read_sensitive",
                re.compile(r'open\s*\(\s*["\'][/~](?:etc/passwd|etc/shadow|\.env)'), 25,
                "Reading sensitive system file"),
    PatternRule("sensitive", "crypto_wallet",
                re.compile(r'(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})'), 20,
                "Possible cryptocurrency wallet address"),
    PatternRule("sensitive", "keychain_access",
                re.compile(r'keyring\.|keychain|libsecret|SecKeychainFind'), 20,
                "System keychain access"),

    # ---- Supply chain specific ----
    PatternRule("supply_chain", "setup_py_install",
                re.compile(r'cmdclass\s*=|class\s+\w*[Ii]nstall\w*\s*\('), 20,
                "Custom install command in setup.py"),
    PatternRule("supply_chain", "postinstall_script",
                re.compile(r'"(?:pre|post)install"\s*:'), 20,
                "npm pre/post install script"),
    PatternRule("supply_chain", "pip_install_runtime",
                re.compile(r'pip\s+install|pip3\s+install|subprocess.*pip'), 15,
                "Runtime pip install — injecting dependencies"),
    PatternRule("supply_chain", "setup_cfg_change",
                re.compile(r'entry_points|console_scripts'), 10,
                "Entry point modification"),
    PatternRule("supply_chain", "npm_lifecycle",
                re.compile(r'"(prepare|prepublish|preinstall|install|postinstall)"\s*:'), 20,
                "npm lifecycle script hook"),
]


# Files that are high-risk by nature — new appearance is noteworthy
HIGH_RISK_FILES = {
    "setup.py", "setup.cfg", "pyproject.toml",
    "package.json", ".npmrc",
    "Makefile", "configure", "configure.ac",
    "pre-commit", "post-commit",
    "Dockerfile", "docker-compose.yml",
}

# File extensions worth scanning
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".sh", ".bash", ".zsh", ".bat", ".cmd", ".ps1",
    ".cfg", ".ini", ".toml", ".yaml", ".yml", ".json",
}


def is_scannable(filepath: str) -> bool:
    from pathlib import PurePosixPath
    p = PurePosixPath(filepath)
    return p.suffix.lower() in SCANNABLE_EXTENSIONS or p.name in HIGH_RISK_FILES


def scan_line(line: str) -> list[tuple[PatternRule, str]]:
    """Scan a single line against all patterns. Returns list of (rule, matched_text)."""
    hits = []
    for rule in PATTERNS:
        m = rule.regex.search(line)
        if m:
            hits.append((rule, m.group()))
    return hits


def is_high_risk_new_file(filepath: str) -> bool:
    from pathlib import PurePosixPath
    return PurePosixPath(filepath).name in HIGH_RISK_FILES
