import BaseHTTPServer

from http_parser.http import HttpStream
from http_parser.reader import SocketReader
from SimpleHTTPServer import SimpleHTTPRequestHandler

WEBSERVER_PORT = 8080

HandlerClass = SimpleHTTPRequestHandler
ServerClass  = BaseHTTPServer.HTTPServer
Protocol     = "HTTP/1.0"

def main():
    #server = redis.Redis("localhost")
    myip = '192.168.122.21'
    webserver_address = (myip, WEBSERVER_PORT)
    HandlerClass.protocol_version = Protocol
    httpd = ServerClass(webserver_address, HandlerClass)
    sa = httpd.socket.getsockname()
    print "Serving HTTP on", sa[0], "port", sa[1], "..."
    httpd.serve_forever()

if __name__ == '__main__':
    main()

