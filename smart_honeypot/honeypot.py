import os
import sys
import socket
import paramiko
import threading
import logging
from datetime import datetime
from ai_engine import AIEngine

# Configure logging for threat intelligence
logging.basicConfig(
    filename='honeypot_activity.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

# RSA key for the SSH server (generate one if it doesn't exist)
HOST_KEY_FILE = 'server_rsa.key'

def generate_host_key():
    if not os.path.exists(HOST_KEY_FILE):
        print(f"Generating RSA key for SSH server...")
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(HOST_KEY_FILE)
    return paramiko.RSAKey(filename=HOST_KEY_FILE)

class SSHServerInterface(paramiko.ServerInterface):
    """
    Paramiko interface that allows any username and password.
    """
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        # Log the credentials the attacker tried
        logging.info(f"[{self.client_ip}] Login attempt - Username: {username}, Password: {password}")
        print(f"[{self.client_ip}] Login attempt - Username: {username}, Password: {password}")

        # Accept ANY credentials to let them in
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


def handle_connection(client_socket, client_address, host_key, ai_provider="openai", ai_model="gpt-3.5-turbo"):
    """
    Handles a single SSH connection, simulating a shell using the AI engine.
    """
    client_ip = client_address[0]
    print(f"New connection from {client_ip}:{client_address[1]}")
    logging.info(f"New connection from {client_ip}")

    try:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(host_key)

        server = SSHServerInterface(client_ip)
        try:
            transport.start_server(server=server)
        except paramiko.SSHException:
            print(f"[{client_ip}] SSH negotiation failed.")
            return

        # Wait for auth
        channel = transport.accept(20)
        if channel is None:
            print(f"[{client_ip}] No channel created.")
            return

        server.event.wait(10)
        if not server.event.is_set():
            print(f"[{client_ip}] Client never asked for a shell.")
            channel.close()
            return

        # Welcome banner
        channel.send("\r\nWelcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-72-generic x86_64)\r\n\r\n")
        channel.send(" * Documentation:  https://help.ubuntu.com\r\n")
        channel.send(" * Management:     https://landscape.canonical.com\r\n")
        channel.send(" * Support:        https://ubuntu.com/advantage\r\n\r\n")

        # Initialize AI Engine for this specific session
        try:
            ai = AIEngine(provider=ai_provider, model=ai_model)
        except Exception as e:
            print(f"Failed to initialize AI Engine: {e}")
            channel.send("System maintenance. Disconnecting...\r\n")
            channel.close()
            return

        prompt = "root@server:~# "
        channel.send(prompt)

        command_buffer = ""
        while True:
            try:
                # Read raw bytes and handle potential decoding errors
                raw_bytes = channel.recv(1024)
                if not raw_bytes:
                    break

                try:
                    chars = raw_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    # Ignore non-utf8 characters gracefully
                    continue

                for char in chars:
                    # Handle Enter key
                    if char == '\r' or char == '\n':
                        channel.send("\r\n")
                        command = command_buffer.strip()
                        command_buffer = ""

                        if command:
                            if command in ['exit', 'logout']:
                                channel.send("logout\r\n")
                                break

                            # Log the command
                            logging.info(f"[{client_ip}] Command: {command}")
                            print(f"[{client_ip}] Executed: {command}")

                            # Get AI response
                            response = ai.get_response(command)

                            # Send response (ensure proper line endings for SSH)
                            if response:
                                formatted_response = response.replace('\n', '\r\n')
                                if not formatted_response.endswith('\r\n'):
                                    formatted_response += '\r\n'
                                channel.send(formatted_response)

                        channel.send(prompt)

                    # Handle Backspace
                    elif char == '\x08' or char == '\x7f':
                        if len(command_buffer) > 0:
                            command_buffer = command_buffer[:-1]
                            channel.send('\x08 \x08')

                    # Handle Ctrl+C
                    elif char == '\x03':
                        channel.send("^C\r\n" + prompt)
                        command_buffer = ""

                    # Handle normal typing
                    else:
                        command_buffer += char
                        channel.send(char)

            except Exception as e:
                print(f"[{client_ip}] Error in session: {e}")
                break

    except Exception as e:
        print(f"[{client_ip}] Connection error: {e}")
    finally:
        print(f"[{client_ip}] Connection closed.")
        try:
            transport.close()
        except:
            pass


def start_honeypot(port=2222, ai_provider="openai", ai_model="gpt-3.5-turbo"):
    """
    Starts the SSH honeypot server.
    """
    host_key = generate_host_key()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        sock.listen(100)

        print(f"Starting Smart AI Honeypot on port {port}...")
        print(f"Using AI Provider: {ai_provider}, Model: {ai_model}")
        print(f"Waiting for connections...")

        while True:
            client_socket, client_address = sock.accept()
            # Handle each connection in a new thread
            t = threading.Thread(
                target=handle_connection,
                args=(client_socket, client_address, host_key, ai_provider, ai_model)
            )
            t.daemon = True
            t.start()

    except Exception as e:
        print(f"Error starting server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Smart AI-Powered SSH Honeypot")
    parser.add_argument("-p", "--port", type=int, default=2222, help="Port to listen on (default 2222)")
    parser.add_argument("--provider", type=str, default="openai", choices=["openai", "ollama"], help="AI provider to use")
    parser.add_argument("--model", type=str, default="gpt-3.5-turbo", help="Model name (e.g., gpt-3.5-turbo, gpt-4, llama3)")

    args = parser.parse_args()

    start_honeypot(port=args.port, ai_provider=args.provider, ai_model=args.model)
