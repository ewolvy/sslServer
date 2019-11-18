""" SSL Web server to control home automation """
#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import base64
import ssl
import sys
import os
import json
import re
import time
from http.server import SimpleHTTPRequestHandler, HTTPServer

class AuthHandler(SimpleHTTPRequestHandler):
    """ Main class to present web pages and authentication. """

    def execute(self, command):
        """ Execute the given command and return the result """
        print(command)
        result = os.system(command)
        self.wfile.write(json.dumps({'Response': [{"Command": command},
                                                  {"Result": result}]}).encode())

    def add_to_db(self):
        """ Add the sensor data to the database """
        #TODO: manage database
        if re.match('01/', self.path[7:]) is not None:
            print("01")
        else:
            print("Not valid")

    def do_HEAD(self):
        """ Send the header """
        print("Send header")
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_authhead(self):
        """ Send the authentication header """
        print("Send header")
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm=\"Test\"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        """ Present front page with user authentication. """
        key = self.server.get_auth_key()
        config = self.server.get_config()
        if self.headers.get('Authorization') is None:
            self.do_authhead()
            self.wfile.write('No auth header received'.encode())
        elif self.headers.get('Authorization') == 'Basic ' + key:
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            for path in config["paths"]:
                if re.match("/" + path["path"] + "/", self.path) is not None:
                    if path["type"] == "ir":
                        command = config["devices"][path["type"]]["command"]
                        command = command + path["code"]
                        command = command + " "
                        start = len(path["path"]) + 2
                        command = command + self.path[start:]
                        self.execute(command)
                    elif path["type"] == "rf":
                        command = config["devices"][path["type"]]["command"]
                        command = command + path["code"]
                        self.execute(command)
                    elif path["type"] == "sensor":
                        print("sensor")
                    else:
                        print("desconocido")

            if re.match('/exitprogram/', self.path) is not None:
                self.wfile.write(json.dumps({"Exit": 0}).encode())
                time.sleep(1)
                print("Exiting")
                sys.exit(0)
        else:
            self.do_authhead()
            self.wfile.write(self.headers.get('Authorization').encode())
            self.wfile.write('Not authenticated'.encode())

class CustomHTTPServer(HTTPServer):
    """ Custom class to create the HTTPS Server. """
    key = ''
    config = None

    def __init__(self, address, handlerClass=AuthHandler):
        super().__init__(address, handlerClass)

    def set_auth(self, password):
        """ Set the username and password key for basic authentication. """
        self.key = base64.b64encode(bytes('%s' % (password), 'utf-8')).decode('ascii')

    def get_auth_key(self):
        """ Get the username and password key for basic authentication. """
        return self.key

    def set_config(self, json_config):
        """ Set the JSON configuration. """
        self.config = json_config

    def get_config(self):
        """ Get the JSON configuration."""
        return self.config


def get_preferences():
    """ Check if exists a preferences file and returns the JSON object,
        otherwise prints error message and exits program. """
    if os.path.isfile("ssl_server.json"):
        with open("ssl_server.json", 'r') as config_file:
            return json.loads(config_file.read())
    if os.path.isfile("/etc/ssl_server.json"):
        with open("ssl_server.json", 'r') as config_file:
            return json.loads(config_file.read())
    sys.exit("No configuration file found. Terminating program.")


def create_server(port, password):
    """ Function to create the SSL server at the given port with username and password. """
    httpd = CustomHTTPServer(('', port), AuthHandler)
    httpd.set_auth(password)
    httpd.set_config(get_preferences())
    httpd.socket = ssl.wrap_socket(httpd.socket, server_side=True,
                                   certfile="fullchain.pem",
                                   keyfile="privkey.pem",
                                   ssl_version=ssl.PROTOCOL_TLSv1)
    httpd.serve_forever()


if __name__ == '__main__':
    # if len(sys.argv) < 3:
    #     print("use sslRaspRemote.py [port] [username:password]")
    #     sys.exit()
    create_server(int(sys.argv[1]), sys.argv[2])
    # create_server(7012, "juanjo:m4ndr4k3")
