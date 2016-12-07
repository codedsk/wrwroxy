#!/usr/bin/env python

import os
import socket
import sys
import re
import select
import time
import glob
import urlparse
import logging
import logging.config
import argparse
import signal


# might need to setup a SocketHandler style logger
# https://docs.python.org/3/howto/logging-cookbook.html#sending-and-receiving-logging-events-across-a-network

def create_log_config(logfile,loglevel,logstream=None):

    handlers = ["fileHandler"]

    if logstream is None:
        stream = sys.stdout
    else:
        stream = logstream
        handlers.append("consoleHandler")

    dictLogConfig = {
        "version" : 1,
        "handlers" : {
            "fileHandler" : {
                "class" : "logging.FileHandler",
                "formatter" : "time_msg",
                "filename" : logfile,
            },
            "consoleHandler" : {
                "class" : "logging.StreamHandler",
                "formatter" : "time_msg",
                "stream" : stream,
            }
        },
        "loggers" : {
            '' : {
                "handlers" : handlers,
                "level" : loglevel,
            }
        },
        "formatters" : {
            "time_msg" : {
                "format" : "%(asctime)s: %(message)s"
            },
            "full" : {
                "format" : "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            }
        }
    }

    return dictLogConfig


def parseoptions():
    usage = "usage: %prog [options]"
    parser = argparse.ArgumentParser(usage=usage)

    parser.add_argument('--listenHost',
                    help='Interface the proxy should listen on.',
                    action='store',
                    dest='listenHost',
                    default='0.0.0.0',
                    type=str)

    parser.add_argument('--listenPort',
                    help='Port this proxy should listen on.',
                    action='store',
                    dest='listenPort',
                    default=8000,
                    type=int)

    parser.add_argument('--forwardHost',
                    help='Host/Interface the proxy should forward packets to.',
                    action='store',
                    dest='forwardHost',
                    default='127.0.0.1',
                    type=str)

    parser.add_argument('--forwardPort',
                    help='Port the proxy should forward packets to.',
                    action='store',
                    dest='forwardPort',
                    default=8001,
                    type=int)

    parser.add_argument('--loglevel',
                    help='Level of detailed messages to put in the logs',
                    action='store',
                    dest='loglevel',
                    default='INFO',
                    type=str)

    parser.add_argument('--logfile',
                    help='Name of the log file',
                    action='store',
                    dest='logfile',
                    default='wrwroxy.log',
                    type=str)

    parser.add_argument('--stream-log',
                    help='Write logging messages to stdout',
                    action='store_true',
                    dest='stream_log')

    parser.add_argument('--no-auth',
                    help='Disable authentication for testing purposes',
                    action='store_false',
                    dest='authenticate')

    parser.add_argument('remainder', nargs=argparse.REMAINDER)

    options = parser.parse_args()

    return options,options.remainder



def check_auth_cookie(hdr):

    logger = logging.getLogger(__name__)
    logger.debug('checking authentication cookie')

    # return True if authentication passes.
    # return False if authentication fails.
    result = False

    # get the session from the environment
    # get the vncpassword from /var/run/Xvnc/passwd-*
    # get the hostname from ${SESSIONDIR}/resources
    # remove http(s):// from hostname, convert '.' to '-'
    # generate the cookie_name from 'weber-auth-' + modified_hostname
    session = os.environ['SESSION']

    pwfile = glob.glob('/var/run/Xvnc/passwd-*')[0]
    with open(pwfile, 'r') as f:
        pw = f.read()
        vncpass = ''.join([('%02x' % ord(c)) for c in pw])

    fn = os.path.join(os.environ['SESSIONDIR'], 'resources')
    with open(fn, 'r') as f:
        res = f.read()
    for line in res.split('\n'):
        if line.startswith('hub_url'):
            url = line.split()[1]
            host = url[url.find('//')+2:]
            cookie_name = 'weber-auth-' + host.replace('.','-')
            break

    # our weber-auth cookie could be anywhere in the list
    # of cookies sent with the request.
    r = re.compile('^Cookie: .*{0}'.format(cookie_name))
    cookies = filter(r.match,hdr)

    # there should only be one weber-auth cookie sent
    ncookies = len(cookies)
    if ncookies == 0:
        # header does not have a weber-auth cookie, exit
        logger.error('header missing weber-auth cookie.')
        logger.error("header:\n{0}".format(hdr))
        return False
    elif ncookies > 1:
        # cookie names should be unique, right?
        msg = 'header has multiple matching weber-auth cookies: '
        cookie_str = '\n'.join(cookies)
        logger.error(msg + cookie_str)
        return False

    # grab the header line with our weber-auth cookie
    cookie = cookies[0]

    # find the value for the weber-auth cookie
    # cookies are separated by a semicolon and a space
    # there is no trailing semicolon for the last cookie
    cvalm = re.search('{0}=([^ \t\n\r\f\v;,]+);?'.format(cookie_name),cookie)

    if cvalm is None:
        # no value for the cookie?
        logger.error('weber-auth cookie missing value: {0}'.format(cookie))
        return False

    # isolate the cookie value and convert special characters
    cval = urlparse.unquote(cvalm.group(1))
    logger.debug("cookie value = :" + cval + ":")
    logger.debug("session: " + session)
    logger.debug("vncpass: " + vncpass)

    # cookie value should match
    # <session>:<password>,<session>:<password>,....
    for item in cval.split(','):
        csession, cpasswd = item.split(':')
        if csession == session and cpasswd == vncpass:
            result = True
            break

    return result


class ProxyHandler(object):

    def __init__(self, listenHost='0.0.0.0', listenPort=8000,
        forwardHost='127.0.0.1', forwardPort=8001, authenticate=True):

        self.listenHost = listenHost
        self.listenPort = listenPort
        self.forwardHost = forwardHost
        self.forwardPort = forwardPort
        self.authenticate = authenticate

        self.logger = logging.getLogger(__name__)


    def _read_header(self,ns):
        chunk=''
        while chunk.rfind('\r\n\r\n') == -1:
            try:
                chunk += ns.recv(10000)
            except:
                break
            if len(chunk) > 100000:
                self.logger.error('Header is too long')
                sys.exit(1)
        arr = chunk.split('\r\n\r\n', 1)
        hdr = arr[0].split('\n')
        for n in range(0,len(hdr)):
            hdr[n] = hdr[n].strip()
        if len(hdr) < 1:
            self.logger.error('Malformed header1: ' + str(hdr))
            sys.exit(1)
        if len(arr) == 2:
            body = arr[1]
        else:
            body = ''
        return hdr,body


    def start(self):

        self.logger.info("ProxyHandler started")

        self.ls = socket.socket()
        self.ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ls.bind((self.listenHost,self.listenPort))
        self.ls.listen(55)

        self.logger.info("ProxyHandler listening on {}:{}".format(
            self.listenHost,self.listenPort))

        while True:

            try:
                ns,sockaddr = self.ls.accept()
            except OSError: # Could be interrupted by a signal
                continue

            header,body = self._read_header(ns)

            if len(header) < 1:
                ns.close()

            # request header path should match:
            # /weber/<SESSION>/<TOKEN>/<CONTAINER>/
            header[0] = re.sub('/weber/[0-9]+/[^/]+/[0-9]+', '', header[0], 1)


            # fork twice so a separate process, managed by init, handles
            # forwarding packets to the proxied application, while this
            # process handles setting up more incoming connections.
            if os.fork() == 0:
                self.ls.close()
                if os.fork() == 0:
                    # inside the grandchild process
                    self.logger.debug("forking ProxyConnect")

                    # run this process in a new session
                    os.setsid()

                    # create a ProxyConnect object to send
                    # packets to the proxied application
                    # register the check_auth_cookie plugin
                    # run the socket connector and packet forwarder
                    p = ProxyConnect(ns,self.forwardHost,self.forwardPort)
                    if self.authenticate is True:
                        p.register_plugin(check_auth_cookie)
                    p.run(header,body)

                    self.logger.debug("ProxyConnect process exiting")
                    os._exit(0)
                else:
                    os._exit(0)
            else:
                try:
                    os.wait()
                    os.wait()
                except:
                    pass


    def stop(self):
        self.logger.info("ProxyHandler shutting down")
        try:
            self.logger.debug("shutting down the listening socket")
            self.ls.close()
        except:
            pass


class ProxyConnect(object):
    """Forward packets between two sockets, a client and a proxied application"""

    def __init__(self, ns1, forwardHost='127.0.0.1', forwardPort=8001):
        self.ns1 = ns1
        self.ns2 = None
        self.forwardHost = forwardHost
        self.forwardPort = forwardPort
        self.plugins = []

        self.logger = logging.getLogger(__name__)


    def register_plugin(self,fxn):
        self.logger.debug("registering new plugin: {}".format(fxn.__name__))
        self.plugins.append(fxn)


    def _forward_packets(self):
        """copy traffic between two sockets"""

        self.logger.debug("forwarding packets")

        af = self.ns1.fileno()
        bf = self.ns2.fileno()
        abuf = ''
        bbuf = ''

        rfds = [af,bf]
        while True:
            try:
                rd,_,_ = select.select(rfds,[],[])
            except select.error:
                continue
            if af in rd:
                chunk = self.ns1.recv(4096)
                if chunk == '':
                    break
                abuf += chunk
                while abuf != '':
                    sent = self.ns2.send(abuf)
                    abuf = abuf[sent:]
            if bf in rd:
                chunk = self.ns2.recv(4096)
                if chunk == '':
                    break
                bbuf += chunk
                while bbuf != '':
                    sent = self.ns1.send(bbuf)
                    bbuf = bbuf[sent:]

        # one socket closed, close the other
        self.logger.debug("closing all sockets")
        try:
            self.ns1.close()
        except:
            pass
        try:
            self.ns2.close()
        except:
            pass


    def run(self,header,body):

        self.logger.debug("ProxyConnect starting")

        # run the plugins
        for fxn in self.plugins:
            self.logger.debug("executing plugin: {}".format(fxn.__name__))
            if fxn(header) is False:
                msg = "ProxyConnect exiting due to plugin failure: {}"
                self.logger.info(msg.format(fxn.__name__))
                try:
                    self.ns1.close()
                except:
                    pass
                os._exit(1)

        # create a new socket that talks to the proxied application
        self.ns2 = socket.socket()

        # The target may not be running yet.  Try several times to connect.
        # Once connected, break out of the checking loop
        # Otherwise, wait a while before trying again.
        for cnt in xrange(1,80):
            try:
                self.ns2.connect((self.forwardHost, self.forwardPort))
                break
            except:
                time.sleep(0.1)

        msg = "ProxyConnect connected to {}:{}"
        self.logger.info(msg.format(self.forwardHost,self.forwardPort))

        # Send the modified initial packet from
        # the client to the proxied application
        chunk = '\r\n'.join(header) + '\r\n\r\n' + body
        while len(chunk) > 0:
            sent = self.ns2.send(chunk)
            chunk = chunk[sent:]

        # Forward all packets from the client to the proxied application
        self._forward_packets()

        self.logger.info("ProxyConnect sockets closed, exiting")


if __name__ == "__main__":

    # parse command line options
    options,remainder = parseoptions()


    # setup a log file
    options.logfile = os.path.abspath(os.path.expanduser(
                        os.path.expandvars(options.logfile)))

    if options.stream_log is True:
        logstream = sys.stdout
    else:
        logstream = None

    dictLogConfig = create_log_config(
        options.logfile, options.loglevel, logstream)
    logging.config.dictConfig(dictLogConfig)

    logger = logging.getLogger(__name__)


    # start a ProxyHandler to recieve packets
    # and forward them to a proxied application
    handler = ProxyHandler(
                options.listenHost,
                options.listenPort,
                options.forwardHost,
                options.forwardPort,
                options.authenticate)

    def sigint_handler(sig,dummy):
        handler.stop()
        sys.exit(1)

    signal.signal(signal.SIGINT, sigint_handler)

    handler.start()

    sys.exit(0)
