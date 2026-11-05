
import requests

API_URL = "http://127.0.0.1:8000/ask"

print("=" * 45)
print("       DEVOPS AI INCIDENT ASSISTANT")
print("=" * 45)
print("Ask questions about your application.")
print("Type 'exit' to quit.\n")

while True:
    question = input("You: ").strip()

    if question.lower() in ("exit", "quit"):
        print("Agent: Goodbye!")
        break

    if not question:
        continue

    try:
        response = requests.post(
            API_URL,
            json={"question": question},
            timeout=120,
        )
        response.raise_for_status()

        result = response.json()

        print("\nAgent:")
        print(result["answer"])
        print("\nEvidence:")
        for item in result["evidence"]:
            print(f'{item["id"]}: {item["summary"]}')

        print("\nData mode:", result["data_mode"])
        print("-" * 45)

    except requests.RequestException as exc:
        print(f"\nAgent API error: {exc}\n")
