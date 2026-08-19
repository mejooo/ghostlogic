"""Ollama is optional at run time, so this test skips when it is absent.

It exists so that a machine which *should* have a model gets told when the
model has gone missing, rather than silently demoing the fallback text.
"""

import json
import urllib.error
import urllib.request

import pytest

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.2:3b"


def _ollama_available() -> bool:
    try:
        urllib.request.urlopen("http://localhost:11434/api/tags", timeout=2)
        return True
    except (urllib.error.URLError, OSError):
        return False


@pytest.mark.skipif(not _ollama_available(), reason="Ollama not running")
def test_model_answers_over_http():
    payload = json.dumps(
        {"model": MODEL, "prompt": "Reply with the single word OK.", "stream": False}
    ).encode()
    req = urllib.request.Request(
        OLLAMA_URL, data=payload, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        body = json.loads(resp.read())

    assert "response" in body
    assert body["response"].strip()
