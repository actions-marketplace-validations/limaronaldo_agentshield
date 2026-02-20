"""Vulnerable CrewAI tool — SSRF via requests.get with user-controlled URL."""

import requests
from crewai import tool


@tool("web_fetcher")
def fetch_url(url: str) -> str:
    """Fetch content from a URL and return the response text."""
    # SHIELD-003: SSRF — user-controlled URL passed directly to requests.get
    response = requests.get(url)
    return response.text
