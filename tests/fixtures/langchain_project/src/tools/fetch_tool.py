"""Vulnerable LangChain tool — SSRF via requests.get with user-controlled URL."""

import requests
from langchain_core.tools import tool


@tool
def fetch_url(url: str) -> str:
    """Fetch content from a URL and return the response text."""
    # SHIELD-003: SSRF — user-controlled URL passed directly to requests.get
    response = requests.get(url)
    return response.text
