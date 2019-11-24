""" SSL Web server to control home automation """
#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import base64
import ssl
import sys
import os
import json
import re
import sqlite3
import time
from http.server import SimpleHTTPRequestHandler, HTTPServer

class AuthHandler(SimpleHTTPRequestHandler):
    """ Main class to present web pages and authentication. """

    def execute(self, command):
        """ Execute the given command and return the result """
        print(command)
        result = os.system(command)
        self.wfile.write(json.dumps(
            {'Response': [{"Command": command},
                          {"Result": result}]}).encode())

    def add_to_db(self, data, room):
        """ Add the sensor data to the database """
        connection = sqlite3.connect('sensor_data.db')
        cursor = connection.cursor()
        to_insert = str(time.time()) + data
        splitted = re.split("[TH]", to_insert)
        splitted.append(room)
        sql_insert = "INSERT INTO tempAndHumidity VALUES (?, ?, ?, ?)"
        cursor.execute(sql_insert, splitted)
        connection.commit()
        connection.close()
        print(sql_insert)
        self.wfile.write(json.dumps(
            {'Response': [{"Command": sql_insert}]}).encode())

    def select_from_db(self, room):
        """ Get the sensor data from the database """
        connection = sqlite3.connect('sensor_data.db')
        cursor = connection.cursor()
        sql_select = "SELECT time, temp, humidity FROM tempAndHumidity WHERE room=? ORDER BY time"
        cursor.execute(sql_select, (room,))
        data = cursor.fetchall()
        connection.close()
        keys = ["time", "temp", "humidity"]
        response = []
        for row in data:
            zip_obj = zip(keys, row)
            response.append(dict(zip_obj))
        print(response)
        self.wfile.write(json.dumps(response).encode())

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

            print("Buscando acción a realizar para:")
            print(self.path)
            for path in config["paths"]:
                if re.match("/" + path["path"] + "/", self.path) is not None:
                    if config["devices"][path["type"]]["type"] == "command":
                        # When the device type is command, execute it
                        print("Acción de tipo comando")
                        command = config["devices"][path["type"]]["command"]
                        command = command + path["code"]
                        if config["devices"][path["type"]]["hasExtra"] == "true":
                            command = command + " "
                            start = len(path["path"]) + 2
                            command = command + self.path[start:]
                        self.execute(command)
                    elif config["devices"][path["type"]]["type"] == "database":
                        # When the device type is database, check if it's for select or insert
                        print("Acción de tipo base de datos")
                        if config["devices"][path["type"]]["operation"] == "insert":
                            start = len(path["path"]) + 2
                            self.add_to_db(data=self.path[start:], room=path["code"])
                        elif config["devices"][path["type"]]["operation"] == "select":
                            start = len(path["path"]) + 2
                            self.select_from_db(room=self.path[start:])
                    else:
                        print("desconocido")
                        print(config["devices"][path["type"]]["type"])

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
    certfile = None
    keyfile = None
    if httpd.config["certs"]["source"] == "local":
        print("Local certs files")
        if os.path.isfile(httpd.config["certs"]["certfile"]):
            certfile = httpd.config["certs"]["certfile"]
        else:
            sys.exit("Local certfile not found. Please review your ssl_server.json.")
        if os.path.isfile(httpd.config["certs"]["keyfile"]):
            keyfile = httpd.config["certs"]["keyfile"]
        else:
            sys.exit("Local keyfile not found. Please review your ssl_server.json.")
    if httpd.config["certs"]["source"] == "remote":
        while True:
            command = "mount " + httpd.config["certs"]["mount_point"]
            os.system(command)
            if not os.path.ismount(httpd.config["certs"]["mount_point"]):
                print("Mount failed. Waiting 1 minute for mount retry.")
                time.sleep(60)
            else:
                print("Certification location mounted.")
                break
        if os.path.isfile(httpd.config["certs"]["certfile"]):
            certfile = httpd.config["certs"]["certfile"]
        else:
            sys.exit("Remote certfile not found. Please review your ssl_server.json.")
        if os.path.isfile(httpd.config["certs"]["keyfile"]):
            keyfile = httpd.config["certs"]["keyfile"]
        else:
            sys.exit("Remote keyfile not found. Please review your ssl_server.json.")
    if certfile is not None and keyfile is not None:
        httpd.socket = ssl.wrap_socket(httpd.socket, server_side=True,
                                       certfile=certfile,
                                       keyfile=keyfile,
                                       ssl_version=ssl.PROTOCOL_TLSv1)
    httpd.serve_forever()


def check_database():
    """ Check if database file exists with the table tempAndHumidity. If not, create it """
    connection = sqlite3.connect('sensor_data.db')
    cursor = connection.cursor()

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='tempAndHumidity'")

    if cursor.fetchone() is None:
        cursor.execute(
            "CREATE TABLE tempAndHumidity (time real, temp real, humidity real, room text)")
        connection.commit()

    connection.close()


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("use sslRaspRemote.py [port] [username:password]")
        sys.exit()
    check_database()
    create_server(int(sys.argv[1]), sys.argv[2])
