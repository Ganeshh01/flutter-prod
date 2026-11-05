
"""Gemini client for incident analysis and AI-powered tool calling."""

import json
import os
import time

from google import genai
from google.genai import types

from .ollama_client import SCHEMA


DEFAULT_MODEL = "gemini-3.8-flash"
MAX_TOOL_CALLS = 5
MAX_RETRIES = 3


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
            raise GeminiError(
                "Could not initialize Gemini client: %s" % str(exc)
            ) from None

    def _generate_with_retry(self, **kwargs):
        """Call Gemini with retries for temporary service failures."""

        retryable_errors = (
            "429",
            "500",
            "502",
            "503",
            "504",
            "UNAVAILABLE",
            "RESOURCE_EXHAUSTED",
            "INTERNAL",
        )

        for attempt in range(MAX_RETRIES):
            try:
                return self.client.models.generate_content(**kwargs)

            except Exception as exc:
                error = str(exc)

                should_retry = any(
                    marker in error.upper()
                    for marker in retryable_errors
                )

                if not should_retry or attempt == MAX_RETRIES - 1:
                    raise GeminiError(
                        "Gemini request failed: %s" % error
                    ) from None

                delay = 2 ** (attempt + 1)

                print(
                    "Gemini temporarily unavailable. "
                    "Retrying in %s seconds (attempt %s/%s)."
                    % (delay, attempt + 1, MAX_RETRIES)
                )

                time.sleep(delay)

        raise GeminiError("Gemini request failed after retries.")

    def generate_json(self, system, user):
        """Generate structured JSON for incident analysis."""

        response = self._generate_with_retry(
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
            raise GeminiError("Gemini returned an empty answer.")

        return content

    def generate_with_tools(
        self,
        system,
        user,
        tool_declarations,
        tool_registry,
        max_tool_calls=MAX_TOOL_CALLS,
    ):
        """
        Understand a user question, select registered Python tools,
        execute them and generate a natural-language answer.
        """

        if not tool_declarations:
            raise GeminiError("No AI tools were provided.")

        if not tool_registry:
            raise GeminiError("The tool registry is empty.")

        if max_tool_calls < 1:
            raise GeminiError("Maximum tool calls must be at least one.")

        allowed_names = set(tool_registry)

        for declaration in tool_declarations:
            if declaration["name"] not in allowed_names:
                raise GeminiError(
                    "Tool declaration is not registered: "
                    + declaration["name"]
                )

        try:
            functions = [
                types.FunctionDeclaration(
                    name=item["name"],
                    description=item["description"],
                    parameters=item["parameters"],
                )
                for item in tool_declarations
            ]

            tool = types.Tool(function_declarations=functions)

            contents = [user]
            executed_tools = []

            for _ in range(max_tool_calls + 1):

                response = self._generate_with_retry(
                    model=self.model,
                    contents=contents,
                    config=types.GenerateContentConfig(
                        system_instruction=system,
                        tools=[tool],
                        automatic_function_calling=(
                            types.AutomaticFunctionCallingConfig(
                                disable=True
                            )
                        ),
                        temperature=0,
                        max_output_tokens=1200,
                    ),
                )

                if not response.candidates:
                    raise GeminiError(
                        "Gemini returned no response candidates."
                    )

                model_content = response.candidates[0].content

                if not model_content or not model_content.parts:
                    raise GeminiError(
                        "Gemini returned an empty response."
                    )

                function_calls = [
                    part.function_call
                    for part in model_content.parts
                    if part.function_call
                ]

                # Gemini has completed its answer.
                if not function_calls:
                    answer = response.text

                    if not answer or not answer.strip():
                        raise GeminiError(
                            "Gemini returned an empty conversational response."
                        )

                    return {
                        "answer": answer,
                        "tool_calls": executed_tools,
                    }

                # Preserve the model's function-call message.
                contents.append(model_content)

                function_responses = []

                for function_call in function_calls:

                    name = function_call.name
                    arguments = dict(function_call.args or {})

                    # Never execute an unregistered function.
                    if name not in tool_registry:
                        raise GeminiError(
                            "Gemini requested an unavailable tool: " + name
                        )

                    if len(executed_tools) >= max_tool_calls:
                        raise GeminiError(
                            "Maximum AI tool execution limit reached."
                        )

                    function = tool_registry[name]

                    # Execute only the registered Python function.
                    try:
                        result = function(**arguments)

                        if isinstance(
                            result,
                            (str, int, float, bool, type(None), list, dict),
                        ):
                            tool_result = result
                        else:
                            tool_result = str(result)

                    except Exception as exc:
                        tool_result = {
                            "error": "Tool execution failed: %s" % str(exc)
                        }

                    executed_tools.append({
                        "tool": name,
                        "arguments": arguments,
                        "result": tool_result,
                    })

                    # Return the actual tool result to Gemini.
                    function_responses.append(
                        types.Part.from_function_response(
                            name=name,
                            response={
                                "result": tool_result
                            },
                        )
                    )

                contents.append(
                    types.Content(
                        role="user",
                        parts=function_responses,
                    )
                )

            raise GeminiError(
                "Gemini exceeded the maximum number of tool-calling rounds."
            )

        except GeminiError:
            raise

        except Exception as exc:
            raise GeminiError(
                "Gemini tool-calling request failed: %s" % str(exc)
            ) from None
