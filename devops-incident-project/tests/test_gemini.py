import unittest
from unittest.mock import MagicMock, patch

from incident_agent.llm.gemini_client import (
    GeminiClient,
    GeminiError,
)


class GeminiClientTests(unittest.TestCase):

    def test_missing_api_key(self):
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaisesRegex(GeminiError, "GEMINI_API_KEY"):
                GeminiClient(api_key="")

    def test_default_model(self):
        with patch("incident_agent.llm.gemini_client.genai.Client"):
            client = GeminiClient(api_key="dummy-key")

        self.assertEqual(client.model, "gemini-2.5-flash")

    @patch("incident_agent.llm.gemini_client.genai.Client")
    def test_generate_json(self, mock_client_class):
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        mock_client.models.generate_content.return_value.text = (
            '{"root_causes":[],"suggested_fixes":[],"verification_commands":[]}'
        )

        client = GeminiClient(api_key="dummy-key")

        result = client.generate_json("system prompt", "user prompt")

        self.assertIn("root_causes", result)

        kwargs = mock_client.models.generate_content.call_args.kwargs

        self.assertEqual(kwargs["model"], "gemini-2.5-flash")
        self.assertEqual(kwargs["contents"], "user prompt")
        self.assertEqual(
            kwargs["config"].system_instruction,
            "system prompt",
        )
        self.assertEqual(
            kwargs["config"].response_mime_type,
            "application/json",
        )

    @patch("incident_agent.llm.gemini_client.genai.Client")
    def test_empty_response(self, mock_client_class):
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        mock_client.models.generate_content.return_value.text = ""

        client = GeminiClient(api_key="dummy-key")

        with self.assertRaisesRegex(GeminiError, "empty answer"):
            client.generate_json("system", "user")

    @patch("incident_agent.llm.gemini_client.genai.Client")
    def test_api_failure(self, mock_client_class):
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        mock_client.models.generate_content.side_effect = Exception(
            "simulated API failure"
        )

        client = GeminiClient(api_key="dummy-key")

        with self.assertRaisesRegex(GeminiError, "Gemini request failed"):
            client.generate_json("system", "user")


if __name__ == "__main__":
    unittest.main()