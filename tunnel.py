#!/usr/bin/env python
import socket
import time
import threading
import ssl
import argparse
import requests
import sys
import os

import select
import fcntl

from uuid import uuid4

BUFFER = 8192
user_agent = 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)'

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

class Connection():
	
	def __init__(self, connection_id, use_ssl, remote, proxy):
		self.id = connection_id
		self.ssl = use_ssl
		self.scheme = 'https' if self.ssl else 'http'
		self.remote = remote
		self.endpoint = '%s://%s:%d/%s' % (self.scheme, remote['host'], int(remote['port']), self.id)
		self.headers = {'User-Agent': user_agent, 'Connection': 'close', b'Accept': None, 'Accept-Encoding': None, b'Content-Type': None}
		self.proxies = {}

		if proxy:
			self.proxies['http']  = proxy['host']+":"+proxy['port']
			self.proxies['https'] = self.proxies['http']

	def create(self, target):
		response = requests.post(self.endpoint, headers=self.headers, data=target, proxies=self.proxies, verify=False)
		return True if response.status_code == 200 else False

	def send(self, data):
		response = requests.put(self.endpoint, headers=self.headers, data={'data': data}, proxies=self.proxies, verify=False)
		return True if response.status_code == 200 else False

	def receive(self):
		response = requests.get(self.endpoint, headers=self.headers, proxies=self.proxies, verify=False)
		return response.content if response.status_code == 200 else None

	def close(self):
		response = requests.delete(self.endpoint, headers=self.headers, proxies=self.proxies, verify=False)
		return response.status_code

class SendThread(threading.Thread):

	def __init__(self, client):
		threading.Thread.__init__(self, name="Send-Thread")
		self.client = client
		self._stop = threading.Event()

	def run(self):
		while not self.stopped():

			try:
				# Socket mdoe
				if self.client.socket:

					data = self.client.socket.recv(BUFFER)
					if not data: 
						self.client.receiver.stop()
						self.client.receiver.join()
						self.client.snd_worker.close()
						return

					self.client.snd_worker.send(data)

				# Stdin mode
				else:

					r, w, x = select.select([sys.stdin],[],[], 0)
					if len(r):
						data = r[0].read()
						if len(data):
							self.client.snd_worker.send(data)
						else: break

			except socket.timeout:
				pass

	def stop(self):
		self._stop.set()

	def stopped(self):
		return self._stop.isSet()

class ReceiveThread(threading.Thread):

	def __init__(self, client):
		threading.Thread.__init__(self, name="Receive-Thread")
		self.client = client
		self._stop = threading.Event()

	def run(self):
		while not self.stopped():
			data = self.client.rec_worker.receive()
			if data:
			
				# Socket mode
				if self.client.socket:
					sent = self.client.socket.sendall(data)

				# Stdin mode
				else:
					sent = sys.stdout.write(data)
					sys.stdout.flush()

			else:
				if self.client.socket:
					time.sleep(.5)

	def stop(self):
		self._stop.set()

	def stopped(self):
		return self._stop.isSet()

class ClientWorker(object):

	def __init__(self, socket, use_ssl, emote_addr, target, proxy):

		self.socket = socket
		self.cid = str(uuid4())
		self.ssl = use_ssl
		self.remote = remote 
		self.target = target
		self.proxy = proxy

	def start(self):

		self.connection = Connection(self.cid, self.ssl, self.remote, self.proxy)

		if self.connection.create(self.target):
			self.rec_worker = Connection(self.cid, self.ssl, self.remote, self.proxy)
			self.snd_worker = Connection(self.cid, self.ssl, self.remote, self.proxy)

			self.sender = SendThread(self)
			self.receiver = ReceiveThread(self)

			if self.socket:
				self.receiver.daemon = True
				self.sender.daemon = True

			self.sender.start()
			self.receiver.start()

	def stop(self):
		# stop read and send threads
		self.sender.stop()
		self.receiver.stop()

		# send close signal to remote server
		self.connection.close()

		# wait for read and send threads to stop and close local socket
		self.sender.join()
		self.receiver.join()
		self.socket.close()

def start_tunnel(listen_port, use_ssl, remote, target, proxy):

	if listen_port is None: # Stdin mode

		fcntl.fcntl(sys.stdin,  fcntl.F_SETFL, os.O_NONBLOCK)
		fcntl.fcntl(sys.stdout, fcntl.F_SETFL, os.O_NONBLOCK)

		print "stdin mode"

		worker = ClientWorker(None, use_ssl, remote, target, proxy)
		worker.start()

	else:
		listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		listen_sock.settimeout(None)
		listen_sock.bind(('', int(listen_port)))
		listen_sock.listen(1)

		print "waiting for connection"
		workers = []
		try:
			while True:
				c_sock, addr = listen_sock.accept() 
				c_sock.settimeout(20)
				print "New client connection: %s:%s" % addr
				worker = ClientWorker(c_sock, use_ssl, remote, target, proxy)
				workers.append(worker)
				worker.start()
		except (KeyboardInterrupt, SystemExit):
			print "\rExiting..."
			listen_sock.close()
			for w in workers:
				w.stop()
			sys.exit()

		return self._stop.isSet()

if __name__ == "__main__":
	"""Parse argument from command line and start tunnel"""

	parser = argparse.ArgumentParser(description='Start Tunnel')
	parser.add_argument('-p', dest='listen_port', help='Port the tunnel listens to, (default: 8889)', type=int)
	parser.add_argument('-s', default=False, dest='ssl', action='store_true', help='Enable SSL (default: disabled)')
	parser.add_argument('-r', default='localhost:9999', dest='remote', help='Specify the host and port of the remote server to tunnel to (default: 127.0.0.1:9999)')
	parser.add_argument('-o', default='', dest='proxy', help='Specify the host and port of the proxy server (format: host:port)')
	parser.add_argument('target', metavar='Target Address', help='Specify the host and port of the target address (format: host:port)')

	args = parser.parse_args()

	target = {"host": args.target.split(":")[0], "port": args.target.split(":")[1]}
	remote = {"host": args.remote.split(":")[0], "port": args.remote.split(":")[1]}
	proxy = {"host": args.proxy.split(":")[0], "port": args.proxy.split(":")[1]} if (args.proxy) else {}
	
	start_tunnel(args.listen_port, args.ssl, remote, target, proxy)
