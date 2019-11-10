#!/usr/bin/python3
import socket
from wslib import *
from wsconn import *
		

class WSServer:
	def __init__(self, host, port):
		self.host = host
		self.port = port
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

	def start(self):
		self.socket.bind((self.host, self.port))
		self.socket.listen(2)

		print("Server is listening on port {}".format(self.port))

	def accept_conn(self):
		# thread_list = []
		while (True):
			conn, addr = self.socket.accept()
			print("accepted connection from {}".format(addr))
			ws_conn = WSConn(conn)
			ws_conn.run()

# main 
host = "127.0.0.1"
port = 6969
ws_server = WSServer(host, port)
ws_server.start()
ws_server.accept_conn()