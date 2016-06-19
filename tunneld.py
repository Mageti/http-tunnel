#!/usr/bin/env python
import sys
import socket
import select
import ssl
import argparse

from cgi import parse_qs
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

class ProxyRequestHandler(BaseHTTPRequestHandler):

	sockets = {}
	BUFFER = 1024*50
	SOCKET_TIMEOUT = 50

	def _get_connection_id(self):
		return self.path.split('/')[-1]

	def _get_socket(self):
		"""get the socket which connects to the target address for this connection"""
		id = self._get_connection_id()
		return self.sockets.get(id, None)

	def _close_socket(self):
		""" close the current socket"""
		id = self._get_connection_id()
		if id in self.sockets:
			s = self.sockets[id]
			if s:
				s.close()
				del self.sockets[id]

	def _send_response(self, code, data=None):
		self.server_version = 'Apache'
		self.sys_version = ''
		self.send_response(code)
		self.end_headers()
		if data:
			self.wfile.write(data)


	def do_GET(self):
		"""GET: Read data from TargetAddress and return to client through http response"""
		s = self._get_socket()
		if s:
			try:
				# check if the socket is ready to be read
				rlist, wlist, xlist = select.select([s], [], [], 1)
				if len(rlist) > 0: 
					to_read_socket = rlist[0]
					try:
						data = to_read_socket.recv(self.BUFFER)
						self._send_response(200, data)
					except socket.error as ex:
						self._send_response(503)
				else: 
					self._send_response(204) # no content had be retrieved
			except KeyboardInterrupt:
				pass
		else:
			self._send_response(400)


	def do_POST(self):
		"""POST: Create TCP Connection to the TargetAddress"""
		id = self._get_connection_id() 
		print 'Initializing connection with ID %s' % id
		length = int(self.headers.getheader('content-length'))
		req_data = self.rfile.read(length)
		params = parse_qs(req_data, keep_blank_values=1) 
		target_host = params['host'][0]
		target_port = int(params['port'][0])

		print 'Connecting to target address: %s % s' % (target_host, target_port)
		# open socket connection to remote server
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		# use non-blocking socket
		s.setblocking(0)
		s.connect_ex((target_host, target_port))

		#save socket reference
		self.sockets[id] = s
		try: 
			self._send_response(200)
		except socket.error, e:
			print e

	def do_PUT(self):
		"""Read data from HTTP Request and send to TargetAddress"""
		id = self._get_connection_id()

		if id not in self.sockets:
			self._send_response(400)
			return

		s = self.sockets[id]
		if not s:
			self._send_response(400)
			return

		length = int(self.headers.getheader('content-length'))
		data = parse_qs(self.rfile.read(length), keep_blank_values=1)['data'][0] 

		# check if the socket is ready to write
		rlist, wlist, xlist = select.select([], [s], [], 1)
		if len(wlist) > 0: 
			to_write_socket = wlist[0]
			try: 
				to_write_socket.sendall(data)
				self._send_response(200)
			except socket.error as ex:
				self._send_response(503)
		else:
			self._send_response(504)

	def do_DELETE(self): 
		self._close_socket()
		self._send_response(200)

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Start Tunnel Server")
	parser.add_argument("-p", default=9999, dest='port', help='Specify port number server will listen to (default: 9999)', type=int)
	parser.add_argument("-s", default=False, dest='ssl', action='store_true', help='Enable SSL (default: disabled)')
	args = parser.parse_args()

	httpd = HTTPServer(('', args.port), ProxyRequestHandler)

	if args.ssl:
		httpd.socket = ssl.wrap_socket(httpd.socket, keyfile='certs/tun.key', certfile='certs/tun.crt', server_side=True)
	try:
		httpd.serve_forever()
	except KeyboardInterrupt:
		sys.exit(1)
