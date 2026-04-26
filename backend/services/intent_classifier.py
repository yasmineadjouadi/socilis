"""permet de classer chaque message dans l’une des trois catégories suivantes :
IOC (Indicator of Compromise) : indicateurs techniques comme une adresse IP, un hash ou une URL
Question : question liée à la cybersécurité
Off-topic : message non pertinent"""

import json
import re
from pathlib import Path
from services.ioc_scan_service import detect_type

# Chargement des mots-clés
_KW_PATH = Path(__file__).parent.parent / "cybersec_keywords.json"
with open(_KW_PATH, encoding="utf-8") as f:
    _RAW = json.load(f)

# Flatten + normalisation
_ALL_KEYWORDS = [
    kw.lower().strip()
    for category in _RAW.get("cybersecurity_keywords", {}).values()
    for kw in category
]

# Regex pour mots complets (évite "patch" dans "dispatch")
_KEYWORD_PATTERNS = [
    re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE)
    for kw in _ALL_KEYWORDS
]

# Détection de question
QUESTION_PATTERNS = [
    r"\?$",
    r"^(qu['e]st|c['e]st|comment|pourquoi|explique|définition)",
]

QUESTION_REGEX = re.compile("|".join(QUESTION_PATTERNS), re.IGNORECASE)

# Noms cyber pour fallback
CYBER_NOUNS = [
    "ransomware", "malware", "virus", "phishing", "attaque",
    "vulnérabilité", "chiffrement", "firewall", "botnet",
    "exploit", "patch", "ddos", "zero day", "backdoor", "trojan"
]


def contains_cyber_keyword(text: str) -> bool:
    return any(pattern.search(text) for pattern in _KEYWORD_PATTERNS)


def contains_cyber_noun(text: str) -> bool:
    return any(n in text for n in CYBER_NOUNS)


def classify_message(message: str) -> str:
    msg = message.strip().lower()

    # 1. Détection IOC (prioritaire)
    if detect_type(msg) != "unknown":
        return "ioc"

    # 2. Détection question explicite + cyber
    if QUESTION_REGEX.search(msg) and contains_cyber_noun(msg):
        return "question"

    # 3. Détection mot-clé cyber
    if contains_cyber_keyword(msg):
        return "question"

    # 4. Sinon
    return "off_topic"