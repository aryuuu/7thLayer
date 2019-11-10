#!/usr/bin/python3
from wslib import *
import socket
import threading


class WSConn(threading.Thread):
	# init
	def __init__(self, conn):
		threading.Thread.__init__(self)
		self.conn = conn
		self.hostadd, self.port = self.conn.getpeername()

	#
	def run(self):
		handshake = self.conn.recv(0x20000).decode('utf-8')
		
		# reply the handshake, wether it is valid or not
		response, success = reply_handshake(handshake)
		self.conn.sendall(response.encode('ascii'))
		print("replied a handshake ")
		# if the handshake if valid, and the connection continued
		if (is_handshake_valid(handshake)):
			close = False

			# while client is not sending close frame control
			while(not close):
				# receive frame from client
				buff = self.conn.recv(0x20000)
				# parse the frame
				try:
					frame = parse_frame(buff)
				except:
					# pass
					# continue
					reply_frame = build_frame(1, 0, 0, 0, CONNECTION_CLOSE, 0, 0, None, "".encode('utf-8'))
					self.conn.sendall(reply_frame)
					close = True
					print("Bye mate, you are so empty")
					continue

				# payload_buff = ''
				method = ''
				body = ''
				bin_body = b''

				print("FIN", frame["FIN"])
				print("OPCODE", frame["OPCODE"])

				if(frame["OPCODE"] not in [0,1,2,8,9,10]):
					reply_frame = build_frame(1, 0, 0, 0, CONNECTION_CLOSE, 0, 0, None, "".encode('utf-8'))
					self.conn.sendall(reply_frame)
					close = True
					print("Bye mate, i don't know you")
					continue

				if (frame["FIN"] == 1):

					# build reply frame
					if (frame["OPCODE"] == CONNECTION_CLOSE):
						close = True
						reply_frame = build_frame(1, 0, 0, 0, CONNECTION_CLOSE, 0, 0, None, "".encode('utf-8'))
						print("NOOO DON'T LEAVE :(")
						print("========================")
						print()

					elif (frame["OPCODE"] == PING):
						reply_frame = build_frame(1, 0, 0, 0, PONG, 0, len(frame["PAYLOAD"]), None, frame["PAYLOAD"])
						print("PONG")

					elif (frame["OPCODE"] == TEXT or method == '!echo'): # the payload on this one is most likely to be method and body, according to the specs
						payload = frame["PAYLOAD"]
						temp_method, temp_body = parse_payload(payload)

						# check if it is conti
						if (temp_method != None):
							method = temp_method
						# print(temp_body)	
						if (temp_body != None):
							try:
								body += temp_body
							except:
								body += temp_body.decode('utf-8')

						if (method == "!echo"):
							reply_frame = build_frame(1, 0, 0, 0, TEXT, 0, len(body), None, body.encode('utf-8'))

						elif (method == "!submission"):
							sauce = open("7thLayer.zip", 'rb').read()
							reply_frame = build_frame(1, 0, 0, 0, BINARY, 0, len(sauce), None, sauce)
					
					# elif (method == '!submission'):
					# 	sauce = open("7thLayer.zip", 'rb').read()
					# 	reply_frame = build_frame(1, 0, 0, 0, BINARY, 0, len(sauce), None, sauce)

						# sauce = open("7thLayer.zip", 'rb').read()
						# checksum = hashlib.md5(sauce).digest()

						# if (checksum == body):
						# 	result = "1".encode('utf-8')
						# else:
						# 	result = "0".encode('utf-8')

						# reply_frame = build_frame(1, 0, 0, 0, BINARY, 0, 1, None, result)

					elif (frame["OPCODE"] == BINARY or method == '!check'):
						bin_body += frame["PAYLOAD"]
						# received = open('received', 'wb')

						sauce = open("7thLayer.zip", 'rb').read()
						checksum = hashlib.md5(sauce).digest()
						copy = hashlib.md5(bin_body).digest()


						if (checksum == copy):
							result = "1".encode('utf-8')
						else:
							result = "0".encode('utf-8')

						reply_frame = build_frame(1, 0, 0, 0, TEXT, 0, 1, None, result)

						# received.write(bin_body)

					# reset method and body 
					method = ''
					body = ''
					bin_body = b''
					# send the reply_frame to our beloved client
					self.conn.sendall(reply_frame)

				else:
					

					payload = frame["PAYLOAD"]

					if (frame["OPCODE"] != BINARY and method != "!check"):
						temp_method, temp_body = parse_payload(payload)
						try:
							body += temp_body
						except:
							body += temp_body.decode('utf-8')
					else:
						method = '!check'
						bin_body = payload
						# bin_body += temp_body

		self.conn.close()			
