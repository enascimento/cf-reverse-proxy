import socket
import urllib
import urlparse
from BaseHTTPServer import BaseHTTPRequestHandler
from BaseHTTPServer import HTTPServer

# Global whitelist of hostnames that can requested from the reverse proxy
g_whitelist_target_hostnames = ["google.com"]


class MyHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        target_hostname = self.headers["Host"]

        # Verify if the target_hostname is allowed:
        # - do not allow proxy requests for the proxy hostname, thus avoiding the request loop issue;
        # - and only allow proxy requests to hostnames specified in the whitelist
        if not ((target_hostname != socket.gethostname()) and (target_hostname in g_whitelist_target_hostnames)):
            self.send_error(500)
            self.end_headers()
            self.wfile.close()
            return

        req_url_parsed = urlparse.urlparse(self.path)
        url_target = urlparse.urlunsplit(("http",
                                          target_hostname,
                                          req_url_parsed.path,
                                          req_url_parsed.query,
                                          req_url_parsed.fragment))
        try:
            conn = urllib.urlopen(url_target)
            data = conn.read()
        except Exception as e:
            self.send_error(404)
            self.end_headers()
            self.wfile.close()
            return

        conn.close()
        # send response code received from target_host reply into the response to the client
        self.send_response(conn.getcode())

        # send headers received from target_host reply into the response to the client
        for (hdr, val) in conn.headers.items():
            self.send_header(hdr, val)

        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()

        # write body of the reply received from target_host to the client
        self.wfile.write(data)
        self.wfile.close()
        return


def run_server():
    server_address = ('localhost', 9090)
    httpd = HTTPServer(server_address, MyHandler)
    httpd.serve_forever()


if __name__ == "__main__":
    run_server()
