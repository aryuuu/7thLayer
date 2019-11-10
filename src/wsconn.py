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
		handshake = self.conn.recv(4096).decode('utf-8')
		
		# reply the handshake, wether it is valid or not
		response, success = reply_handshake(handshake)
		self.conn.send(response.encode('utf-8'))
		print("replied a handshake ")
		# if the handshake if valid, and the connection continued
		if (is_handshake_valid(handshake)):
			close = False

			# while client is not sending close frame control
			while(not close):
				# receive frame from client
				buff = self.conn.recv(4096)
				# parse the frame
				frame = parse_frame(buff)
				payloadd_buff = ''
				method = ''
				body = ''


				if (frame["FIN"] == 1):

					# build reply frame
					if (frame["OPCODE"] == CONNECTION_CLOSE):
						close = True
						reply_frame = build_frame(fin=1, rsv1=0, rsv2=0, rsv3=0, opcode=CONNECTION_CLOSE, mask=0, payload_len=0, masking_key=None, payload="")

					elif (frame["OPCODE"] == PING):
						reply_frame = build_frame(fin=1, rsv1=0, rsv2=0, rsv3=0, opcode=PONG, mask=0, payload_len=len(frame["PAYLOAD"]), masking_key=None, payload=frame["PAYLOAD"])

					elif (frame["OPCODE"] == TEXT): # the payload on this one is most likely to be method and body, according to the specs
						payload = frame["PAYLOAD"]
						temp_method, temp_body = parse_payload(payload)

						# check if it is conti
						if (temp_method != None):
							method = temp_method

						body += temp_body

						if (method == "!echo"):
							reply_frame = build_frame(fin=1, rsv1=0, rsv2=0, rsv3=0, opcode=TEXT, mask=0, payload_len=len(body), masking_key=None, payload=body)

						elif (method == "!submission"):
							sauce = open("7thLayer.zip", 'rb').read()
							reply_frame = build_frame(fin=1, rsv1=0, rsv2=0, rsv3=0, opcode=BINARY, mask=0, payload_len=len(sauce), masking_key=None, payload=sauce)
					
					elif (frame["OPCODE"] == BINARY):

						# elif (method == "!check"):
						sauce = open("7thLayer.zip", 'rb').read()
						checksum = hashlib.md5(sauce).digest()

						if (checksum == body):
							result = "1".encode('utf-8')
						else:
							result = "0".encode('utf-8')

						reply_frame = build_frame(fin=1, rsv1=0, rsv2=0, rsv3=0, opcode=BINARY, mask=0, payload_len=1, masking_key=None, payload=result)
				
					# send the reply_frame to our beloved client
					self.conn.send(reply_frame)

				else:
					# block for handling fragmentation
					# elif(frame["OPCODE"] == CONTINUATION):
					# 	payload = frame["PAYLOAD"]
					# 	temp_method, temp_body = parse_payload(payload)
					
					# # block for handling methods (!echo, !submission, !check)
					# elif(frame["OPCODE"] == TEXT):
					# 	payload = frame["PAYLOAD"]
					# 	temp_method, temp_body = parse_payload(payload)

					# 	# check if it is conti
					# 	if (temp_method != None):
					# 		method = temp_method

					# 	body += temp_body

					payload = frame["PAYLOAD"]
					temp_method, temp_body = parse_payload(payload)

					body += temp_body

		self.conn.close()			
