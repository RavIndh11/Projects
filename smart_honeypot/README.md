# Smart AI-Powered SSH Honeypot

This project is a dynamic, intelligent SSH honeypot that uses Large Language Models (LLMs) to simulate a realistic Ubuntu Linux environment.

Traditional honeypots often rely on static responses or limited simulated filesystems, which experienced attackers can quickly identify as fake. This honeypot intercepts an attacker's bash commands and feeds them to an AI model instructed to act exactly like a real terminal, generating dynamic, highly realistic responses on the fly. This keeps attackers engaged longer and allows for better threat intelligence gathering.

## Features
- **Dynamic Interaction:** Commands are processed by an LLM (OpenAI or local via Ollama), meaning the system can realistically "fake" almost any command, file read, or script execution.
- **Universal Access:** Accepts any username and password combination to lure attackers in.
- **Threat Logging:** Logs all IP addresses, attempted credentials, and executed commands to `honeypot_activity.log`.
- **Configurable Models:** Can be backed by OpenAI's GPT models or locally hosted models (e.g., Llama 3) via Ollama.

## Setup

1. **Install Dependencies:**
   Ensure you have Python 3.8+ installed.
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure API Keys (If using OpenAI):**
   Create a `.env` file in the same directory as the scripts and add your OpenAI API key:
   ```env
   OPENAI_API_KEY=your_api_key_here
   ```

## Usage

You can start the honeypot by running the `honeypot.py` script. By default, it listens on port `2222` to avoid conflicting with your actual SSH server (which usually runs on port 22).

```bash
python honeypot.py
```

### Command Line Arguments
- `-p`, `--port`: Port to listen on (Default: `2222`)
- `--provider`: AI provider to use. Choices are `openai` or `ollama`. (Default: `openai`)
- `--model`: The specific model to use (e.g., `gpt-3.5-turbo`, `gpt-4`, `llama3`). (Default: `gpt-3.5-turbo`)

### Examples

**Run with default settings (OpenAI gpt-3.5-turbo on port 2222):**
```bash
python honeypot.py
```

**Run on port 22 with GPT-4 (Requires root privileges for port 22):**
```bash
sudo python honeypot.py -p 22 --model gpt-4
```

**Run using a local model via Ollama (No API key required):**
*Note: Ensure Ollama is running locally on `http://localhost:11434`.*
```bash
python honeypot.py --provider ollama --model llama3
```

## Testing the Honeypot

From another terminal (or another machine), SSH into your honeypot:

```bash
ssh root@localhost -p 2222
```
Enter *any* password when prompted. Once inside, try running standard Linux commands like `ls`, `cat /etc/passwd`, `uname -a`, or `whoami`.

## Disclaimer
This tool is for educational and research purposes only. Do not deploy this in a production environment without fully understanding the risks of running honeypots on your network.
