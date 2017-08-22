import socket
import json
import traceback
import logging
from copy import copy


def request(addr, method, data, timeout=None):
    '''Simple single function interface
    for JSON-RPC request that
    creates and destroys a socket for every request.
    '''
    host, port = addr.split(':')
    jsrpc = JSONRPCProxy(host, port, connect_timeout=timeout)
    r = jsrpc.request(method, data, timeout=timeout)
    jsrpc.close()
    return r


def notify(addr, method, data):
    '''Simple single function interface
    for JSON-RPC notify that
    creates and destroys a socket for every request.
    '''
    host, port = addr.split(':')
    jsrpc = JSONRPCProxy(host, port)
    r = jsrpc.notify(method, data)
    jsrpc.close()
    return r


class JSONRPCError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class JSONRPCBadResponse(JSONRPCError):
    pass


class JSONRPCRequestFailure(JSONRPCError):
    pass


class JSONRPCResponseError(JSONRPCError):
    '''
    JSONRPCResponseError contains a dictionary with a code and a message
    '''
    pass


class JSONRPCProxy:

    def __init__(self, host, port, version='2.0', connect_timeout=2):
        self.host = host
        self.port = int(port)
        self.version = version
        self._id = 1
        self.timeout = connect_timeout
        self.connect()

    @property
    def _rpcid(self):
        if self._id >= 1000000:
            self._id = 0
        self._id += 1
        return self._id

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(self.timeout)
        self.socket.connect((self.host, self.port))

    def close(self):
        self.socket.close()

    def _msg(self, method, params={}, notify=False):
        jsonrpc = {
            'jsonrpc': self.version,
            'method': method,
            'params': params
        }

        if notify is not True:
            rpcid = copy(self._rpcid)
            jsonrpc['id'] = rpcid

        string = json.dumps(jsonrpc)
	print "request msg :%s" %(string)
        #netstring = str(len(string)) + ':' + string + ','
        netstring =  string 

        if notify:
            return netstring
        else:
            return (rpcid, netstring)

    def request(self, method, params={}, retry=1, timeout=2):

        def do_retry(retry):
            retry -= 1
            if retry < 0:
                raise JSONRPCRequestFailure('Retries exceeded.')

            self.close()
            try:
                self.connect()
            except:
                traceback_string = traceback.format_exc()
                logging.error(traceback_string)
            return self.request(method, params, retry-1)

        try:
            rpcid, netstring = self._msg(method, params)

            self.socket.sendall(netstring)
        except:
            # Get the traceback
            tb_s = traceback.format_exc()
            logging.error(tb_s)
            return do_retry(retry)
        
        
        response_string = str(self.socket.recv(1514))
        
	if response_string == "\n" :
	    response_string = str(self.socket.recv(1514))
 
        try:
            response = json.loads(response_string)
        except:
            raise JSONRPCBadResponse(
                'Failed to parse response: {}'.format(response_string))
 
        if 'jsonrpc' not in response:
                raise JSONRPCBadResponse("Missing 'jsonrpc' version")
 
        if response['jsonrpc'] != self.version:
                raise JSONRPCBadResponse(
                 'Bad jsonrpc version. Got {actual}, expects {expected}'
                 .format(
                     actual=response['jsonrpc'],
                     expected=self.version))
 
        if 'id' not in response:
            raise JSONRPCBadResponse("Missing 'id'")
 
        if response['id'] != rpcid:
            logging.error(
                'Wrong response id. Got {actual}, expects {expected}.'
                ' Retrying...'.format(
                    actual=response['id'],
                    expected=rpcid))
            return do_retry(retry)
 
        if 'result' in response:
            return response['result']
        elif 'error' in response:
            error = response['error']
            if 'code' not in error:
                raise JSONRPCBadResponse(
                    'error response missing code. Response: {}'
                    .format(response))
            elif 'message' not in error:
                raise JSONRPCBadResponse(
                    'error response missing message. Response: {}'
                    .format(response))
            raise JSONRPCResponseError(response['error'])
        else:
            raise JSONRPCBadResponse(
                'Invalid response: {}'.format(response))

    def notify(self, method, params={}):
        netstring = self._msg(method, params, notify=True)
        try:
            self.socket.sendall(netstring)
        except Exception:
            self.close()
            try:
                # Retry once
                self.connect()
                self.socket.sendall(netstring)
            except Exception:
                raise JSONRPCRequestFailure('Failed to send.')
