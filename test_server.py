import socket
import signal
import time
import sys
import logging

# reference http://blog.wachowicz.eu/?p=256

class TestServer:

    def __init__(self,port=8001):

        self.host='0.0.0.0'
        self.port=port

        self.logger = logging.getLogger(__name__)


    def start(self):
        """Open a listening socket"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host,self.port))
        self.logger.info("Launching server")
        self._accept_connections()


    def stop(self):
        """Shut down the server"""
        self.logger.info("Stopping server")
        try:
            self.socket.close()
        except:
            pass


    def _generate_headers(self,code):
        """Generate HTTP response header"""

        # determine response code
        h = ''
        if (code == 200):
            h = 'HTTP/1.1 200 OK\n'
        elif (code == 404):
            h = 'HTTP/1.1 404 Not Found\n'

        current_date = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
        h+= 'Date: ' + current_date + '\n'
        h+= 'Server: RewriteProxyTestServer\n'
        h+= 'Connection: close\n\n'

        return h

    def _accept_connections(self):
        """Respond to incomming connections"""

        while True:
            self.logger.info("waiting for connection")
            self.socket.listen(5)

            conn,addr = self.socket.accept()

            self.logger.info("accepted connection from %s".format(addr))

            data = conn.recv(1024)
            string = bytes.decode(data)

            # determine request method
            request_method = string.split(' ')[0]
            self.logger.info("Method: ", request_method)
            self.logger.info("Request body: ", string)

            if (request_method == 'GET') or (request_method == 'HEAD'):
                # we could read the file info here,
                # but i dont care about files right now

                response_headers = self._generate_headers(200)
                current_date = time.strftime(
                    "%a, %d %b %Y %H:%M:%S", time.localtime())
                response_content = b"Success\n{}\n{}".format(current_date,string)

                server_response =  response_headers.encode()
                if (request_method == 'GET'):
                    server_response +=  response_content

                conn.send(server_response)
                conn.close()
            else:
                self.logger.info("ignoring request:\n{}".format(string))


if __name__ == "__main__":

    def graceful_shutdown(sig,dummy):
        s.stop()
        sys.exit(1)

    signal.signal(signal.SIGINT, graceful_shutdown)

    s = TestServer(8001)
    s.start()
