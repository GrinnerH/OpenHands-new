"""Minimal fallback when the real litellm package is unavailable."""
from __future__ import annotations

import json
from typing import Any, Dict, List

import requests


def completion(
    *,
    model: str,
    messages: List[Dict[str, str]],
    api_key: str,
    base_url: str,
    temperature: float = 0.0,
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    Very small subset of litellm's completion(). Only supports chat models with
    OpenAI-compatible REST endpoints (like DMX API used in config).
    """

    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    response = requests.post(
        f"{base_url.rstrip('/')}/chat/completions",
        data=json.dumps(payload),
        headers=headers,
        timeout=60,
    )
    response.raise_for_status()
    return response.json()
