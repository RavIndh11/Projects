import os
import json
from openai import OpenAI
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class AIEngine:
    def __init__(self, provider="openai", model="gpt-3.5-turbo"):
        self.provider = provider.lower()
        self.model = model

        # System prompt instructing the AI to act as a realistic Linux shell
        self.system_prompt = """You are a realistic Ubuntu Linux terminal.
The user is interacting with you via SSH.
When the user types a command, you must output exactly what the terminal would show.
Do not provide any explanations, apologies, or conversational filler.
Only output the raw text that a real bash shell would return.
If a command is not found, output: bash: <command>: command not found
If a command requires root, output: Permission denied
Simulate standard directories like /home, /etc, /var, etc.
Current user: root
Current hostname: server
Current directory: /root"""

        # Maintain a history to keep context of the session (e.g., changing directories)
        self.history = [{"role": "system", "content": self.system_prompt}]

        if self.provider == "openai":
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                print("WARNING: OPENAI_API_KEY not found in environment. AI responses will fail.")
            self.client = OpenAI(api_key=api_key)
        elif self.provider == "ollama":
            # For local models using Ollama, assuming default local endpoint
            self.client = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
        else:
            raise ValueError(f"Unsupported provider: {provider}")

    def get_response(self, command: str) -> str:
        """
        Sends the attacker's command to the LLM and returns the simulated terminal output.
        """
        # Append the user's command to the history
        self.history.append({"role": "user", "content": command})

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=self.history,
                temperature=0.2, # Low temperature for more deterministic/realistic output
                max_tokens=500
            )

            output = response.choices[0].message.content

            # Append the AI's response to the history so it remembers state
            self.history.append({"role": "assistant", "content": output})

            # Prevent history from growing indefinitely to avoid context window limits
            # Keep system prompt + last 20 interaction turns (approx)
            if len(self.history) > 41:
                self.history = [self.history[0]] + self.history[-40:]

            return output

        except Exception as e:
            # Fallback if API fails
            error_msg = f"bash: {command.split()[0] if command else ''}: command not found\r\n" if command else ""
            return error_msg
