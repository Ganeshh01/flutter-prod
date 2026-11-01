"""Gemini cloud client for optional AI incident analysis."""

import os

from google import genai
from google.genai import types

from .ollama_client import SCHEMA


DEFAULT_MODEL = "gemini-2.5-flash"


class GeminiError(Exception):
    """Gemini is unavailable or returned an unusable response."""


class GeminiClient:

    def __init__(self, api_key=None, model=None):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        self.model = model or os.environ.get("GEMINI_MODEL") or DEFAULT_MODEL

        if not self.api_key:
            raise GeminiError(
                "GEMINI_API_KEY is missing. Configure it as an environment variable."
            )

        try:
            self.client = genai.Client(api_key=self.api_key)
        except Exception as exc:
            raise GeminiError("Could not initialize Gemini client: %s" % exc) from None

    def generate_json(self, system, user):
        """Generate structured JSON. Caller must validate the response."""

        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=user,
                config=types.GenerateContentConfig(
                    system_instruction=system,
                    response_mime_type="application/json",
                    response_schema=SCHEMA,
                    temperature=0,
                    max_output_tokens=600,
                ),
            )

            content = response.text

            if not isinstance(content, str) or not content.strip():
                raise GeminiError("Gemini returned an empty answer")

            return content

        except GeminiError:
            raise
        except Exception:
            raise GeminiError(
                "Gemini request failed. Check API access, model availability and network."
            ) from None