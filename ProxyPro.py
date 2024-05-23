import http.server
import socketserver
import urllib.request
import socket
import select
import ssl
import logging
import time
from collections import defaultdict

logging.basicConfig(level=logging.DEBUG)

class Proxy(http.server.SimpleHTTPRequestHandler):

    ERROR_PAGES = {
        400: b"<html><body><h1>400 Bad Request</h1></body></html>",
        401: b"<html><body><h1>401 Unauthorized</h1></body></html>",
        403: b"<html><body><h1>403 Forbidden</h1></body></html>",
        404: b"<html><body><h1>404 Not Found</h1></body></html>",
        429: b"<html><body><h1>429 Too Many Requests</h1></body></html>",
        500: b"<html><body><h1>500 Internal Server Error</h1></body></html>"
    }

    RATE_LIMIT = 10  # requests
    RATE_LIMIT_WINDOW = 60  # seconds

    ip_access_log = defaultdict(list)
    blocked_ips = set()

    # Preload and cache SSL contexts
    client_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    client_context.load_cert_chain(certfile='C:/Users/saro_/48a30643e73509b6.crt', keyfile='C:/Users/saro_/saro.life.key')
    client_context.load_verify_locations(cafile='C:/Users/saro_/gd_bundle-g2-g1.crt')
    client_context.minimum_version = ssl.TLSVersion.TLSv1_2
    client_context.options |= ssl.OP_NO_TICKET
    client_context.set_ciphers('HIGH+ECDSA:HIGH+RSA:!aNULL:!eNULL:!MD5:!RC4')

    server_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    server_context.check_hostname = False
    server_context.verify_mode = ssl.CERT_NONE
    server_context.minimum_version = ssl.TLSVersion.TLSv1_2
    server_context.options |= ssl.OP_NO_TICKET
    server_context.set_ciphers('HIGH:!aNULL:!MD5:!RC4:!DHE')

    def is_rate_limited(self, client_ip):
        current_time = time.time()
        access_times = self.ip_access_log[client_ip]
        
        # Remove outdated access times
        while access_times and current_time - access_times[0] > self.RATE_LIMIT_WINDOW:
            access_times.pop(0)
        
        # Check if the current request exceeds the rate limit
        if len(access_times) >= self.RATE_LIMIT:
            return True
        
        access_times.append(current_time)
        return False

    def send_error_page(self, code):
        try:
            self.send_response(code)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", len(self.ERROR_PAGES[code]))
            self.end_headers()
            self.wfile.write(self.ERROR_PAGES[code])
        except Exception as e:
            logging.error("Error sending error page: %s", e)

    def do_CONNECT(self):
        client_ip = self.client_address[0]
        
        if client_ip in self.blocked_ips:
            self.send_error_page(403)
            return
        
        if self.is_rate_limited(client_ip):
            logging.warning(f"Rate limit exceeded for IP: {client_ip}")
            self.send_error_page(429)
            return

        try:
            self.send_response(200, "Connection established")
            self.end_headers()

            dest_host, dest_port = self.path.split(':')
            dest_port = int(dest_port) if dest_port else 443

            logging.debug(f"SSL context setup with options: {self.client_context.options}")
            logging.debug(f"Cipher suites: {self.client_context.get_ciphers()}")

            client_socket = self.client_context.wrap_socket(self.connection, server_side=True)
            with socket.create_connection((dest_host, dest_port)) as dest_sock:
                dest_socket = self.server_context.wrap_socket(dest_sock, server_hostname=dest_host)
                while True:
                    readers, _, _ = select.select([client_socket, dest_socket], [], [])
                    if client_socket in readers:
                        data = client_socket.recv(4096)
                        if not data:
                            break
                        dest_socket.sendall(data)
                    if dest_socket in readers:
                        data = dest_socket.recv(4096)
                        if not data:
                            break
                        client_socket.sendall(data)

        except ssl.SSLError as e:
            logging.error("SSL error occurred: %s", e)
            self.send_error_page(400)
        except Exception as e:
            logging.error("An error occurred: %s", e)
            self.send_error_page(500)
        finally:
            if 'client_socket' in locals() and client_socket:
                try:
                    client_socket.close()
                except Exception as e:
                    logging.error("Error closing client socket: %s", e)
            if 'dest_socket' in locals() and dest_socket:
                try:
                    dest_socket.close()
                except Exception as e:
                    logging.error("Error closing destination socket: %s", e)

    def do_GET(self):
        client_ip = self.client_address[0]
        
        if client_ip in self.blocked_ips:
            self.send_error_page(403)
            return
        
        if self.is_rate_limited(client_ip):
            logging.warning(f"Rate limit exceeded for IP: {client_ip}")
            self.send_error_page(429)
            return
        
        try:
            self.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'
            self.headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            req = urllib.request.Request(self.path, headers=dict(self.headers))
            with urllib.request.urlopen(req) as resp:
                self.send_response(resp.getcode())
                self.send_header('Content-type', resp.info().get_content_type())
                self.end_headers()
                self.copyfile(resp, self.wfile)
        except urllib.error.HTTPError as e:
            logging.error("HTTP error occurred: %s", e)
            self.send_error_page(e.code)
        except Exception as e:
            logging.error("An error occurred: %s", e)
            self.send_error_page(500)

    def do_POST(self):
        client_ip = self.client_address[0]
        
        if client_ip in self.blocked_ips:
            self.send_error_page(403)
            return
        
        if self.is_rate_limited(client_ip):
            logging.warning(f"Rate limit exceeded for IP: {client_ip}")
            self.send_error_page(429)
            return
        
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            req = urllib.request.Request(self.path, data=post_data, headers=dict(self.headers), method='POST')
            with urllib.request.urlopen(req) as resp:
                self.send_response(resp.getcode())
                self.send_header('Content-type', resp.info().get_content_type())
                for key, value in resp.info().items():
                    self.send_header(key, value)
                self.end_headers()
                self.copyfile(resp, self.wfile)
        except urllib.error.HTTPError as e:
            logging.error("HTTP error occurred: %s", e)
            self.send_error_page(e.code)
        except Exception as e:
            logging.error("An error occurred: %s", e)
            self.send_error_page(500)

PORT = 8080
with socketserver.ThreadingTCPServer(('127.0.0.1', PORT), Proxy) as httpd:
    print(f"Serving at port {PORT}")
    httpd.serve_forever()