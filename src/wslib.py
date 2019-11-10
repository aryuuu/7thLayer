#!/usr/bin/python3

import hashlib
import base64
import codecs




# constants
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

TRUE = 1
FALSE = 0



# opcodes
## data frame opcodes
CONTINUATION = 0x00
TEXT = 0x01
BINARY = 0x02

## control frame opcodes
CONNECTION_CLOSE = 0x08
PING = 0x09
PONG = 0x0A

# INDICES for each metadata in byte
FIN_IDX = 0x00
RSV1_IDX = 0x00
RSV2_IDX = 0x00
RSV3_IDX = 0x00

# if this doesnt work dont forget to distract each end idx by 1
OPCODE_IDX = 0x00

MASK_IDX = 0x01

PAYLOAD_LEN_START_IDX = 0x01
PAYLOAD_LEN_END_IDX = PAYLOAD_LEN_START_IDX

PAYLOAD_LEN_START_EXT_IDX = 0x02
PAYLOAD_LEN_END_EXT_16_IDX = PAYLOAD_LEN_START_EXT_IDX + 2
PAYLOAD_LEN_END_EXT_64_IDX = PAYLOAD_LEN_START_EXT_IDX + 8

# # this will only true if length of payload length is 7+64 bit
# MASKING_KEY_START_IDX = PAYLOAD_LEN_END_EXT_64
# MASKING_KEY_END_IDX = MASKING_KEY_START_IDX + 32

# PAYLOAD_START_IDX = MASKING_KEY_END_IDX













#this method is just like int_to_ascii, but returns bytes instead of string
#i hope there is no more weird bug
def imp_int_to_utf8(num, zero_padding=2):
	decode_hex = codecs.getdecoder("hex_codec")
	num = str(hex(num))[2:].zfill(zero_padding)

	result = decode_hex(num)[0]
	return result



#this method return int value for a string
def utf8_to_int(stream):
	result = 0
	for i in stream:
		result = (result<<8) + ord(i)
	return result



# this function is used to mask or unmask payload with certain masking key
# takes two arguments: payload (masked or not) and masking key
# and returns masked (or unmasked) payload
# detail of masking algorthim https://tools.ietf.org/html/rfc6455#section-5.3
def mask_payload(payload, key):

	result = b''
	
	for i in range(len(payload)):
		# print("payload {} {}".format(i, payload))
		result += imp_int_to_utf8(payload[i] ^ key[i % 4])

	# padding = len(payload) % 8
	return result
	# return imp_int_to_utf8(result, padding)





# =======================================
# FRAME HANDLER BLOCK
# =======================================

# this function is used to build packet frame
# takes X arguments:
# returns packet frame which is binary string, ready to be sent

# here is reference for building packet frame [rfc6455]
"""
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-------+-+-------------+-------------------------------+
     |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
     |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
     |N|V|V|V|       |S|             |   (if payload len==126/127)   |
     | |1|2|3|       |K|             |                               |
     +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
     |     Extended payload length continued, if payload len == 127  |
     + - - - - - - - - - - - - - - - +-------------------------------+
     |                               |Masking-key, if MASK set to 1  |
     +-------------------------------+-------------------------------+
     | Masking-key (continued)       |          Payload Data         |
     +-------------------------------- - - - - - - - - - - - - - - - +
     :                     Payload Data continued ...                :
     + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
     |                     Payload Data continued ...                |
     +---------------------------------------------------------------+

     ... and so on, please check https://tools.ietf.org/html/rfc6455#section-5.2
 """

# to make it easier, i like to see the index of the frame in octal instead of decimal
# like so
"""
      0               1               2               3            
      0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
     +-+-+-+-+-------+-+-------------+-------------------------------+
     |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
     |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
     |N|V|V|V|       |S|             |   (if payload len==126/127)   |
     | |1|2|3|       |K|             |                               |
     +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
     |     Extended payload length continued, if payload len == 127  |
     + - - - - - - - - - - - - - - - +-------------------------------+
     |                               |Masking-key, if MASK set to 1  |
     +-------------------------------+-------------------------------+
     | Masking-key (continued)       |          Payload Data         |
     +-------------------------------- - - - - - - - - - - - - - - - +
     :                     Payload Data continued ...                :
     + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
     |                     Payload Data continued ...                |
     +---------------------------------------------------------------+

     much better for me, because reasons
 """


def build_frame(fin, rsv1, rsv2, rsv3, opcode, mask, payload_len, masking_key, payload):
	# build our frame first byte
	first_byte = (fin << 7) + (rsv1 << 6) + (rsv2 << 5) + (rsv3 << 4) + opcode
	first_byte = imp_int_to_utf8(first_byte)

	# build the next byte
	if (payload_len < 0x7e):
		second = imp_int_to_utf8((mask << 7) + payload_len)
	elif (payload_len < 2**16):
		second = imp_int_to_utf8((mask << 7) + 0x7e) + imp_int_to_utf8(payload_len, 4)
	else:
		second = imp_int_to_utf8((mask << 7) + 0x7f) + imp_int_to_utf8(payload_len, 16)

	# third = ''.encode('utf-8')
	if (mask == 1):
		third = masking_key
		last = mask_payload(payload, masking_key)
		return first_byte + second + third + last		
	else:
		last = payload
		# print(type(first_byte), type(second), type(last))
		return first_byte + second +  last

	# return first_byte + second + third + last





# this function is used to parse a frame
# takes utf-8 encoded string (packet frame) as argument
# returns dictionary of frame (like JSON) consist of FIN, RSV1, RSV2, RSV3, OPCODE, MASK, PAYLOAD_LEN, MASKING_KEY, PAYLOAD (decoded)
def parse_frame(frame):
	fin = frame[FIN_IDX] >> 7
	rsv1 = (frame[RSV1_IDX] & 0x40) >> 7
	rsv2 = (frame[RSV2_IDX] & 0x20) >> 7
	rsv3 = (frame[RSV3_IDX] & 0x10) >> 7

	opcode = frame[OPCODE_IDX] & 0x0f
	mask = frame[MASK_IDX] >> 7

	# set the payload, according to the categories 
	# https://tools.ietf.org/html/rfc6455#section-5.2
	pay_len = frame[PAYLOAD_LEN_START_IDX] & 0x7f
	if (pay_len <= 0x7d):
		payload_len = pay_len
	elif (pay_len == 0x7e):
		payload_len = int(frame[PAYLOAD_LEN_START_EXT_IDX:PAYLOAD_LEN_END_EXT_16_IDX].hex(), 16) 
	else:
		payload_len = int(frame[PAYLOAD_LEN_START_EXT_IDX:PAYLOAD_LEN_END_EXT_64_IDX].hex(), 16) 

	# check if mask exist to decide wether or not we should parse the masking key
	masking_key = None
	if (mask == 1):
		if(pay_len <= 0x7d):
			masking_key = frame[PAYLOAD_LEN_END_IDX+1:PAYLOAD_LEN_END_IDX+5]
			# print(masking_key)
			# for i in masking_key:
			# 	print(hex(i))
		elif(pay_len == 0x7e):
			masking_key = frame[PAYLOAD_LEN_END_EXT_16_IDX:PAYLOAD_LEN_END_EXT_16_IDX+4]
		else:
			masking_key = frame[PAYLOAD_LEN_END_EXT_64_IDX:PAYLOAD_LEN_END_EXT_64_IDX+4]

	# and again check if mask exist to parse our payload
	if(mask == 1):
		print("This frame is masked")
		if(pay_len <= 0x7d):
			payload = mask_payload(frame[PAYLOAD_LEN_END_IDX+5:], masking_key)
		elif(pay_len == 0x7e):
			payload = mask_payload(frame[PAYLOAD_LEN_END_EXT_16_IDX+4:], masking_key)
		else:
			payload = mask_payload(frame[PAYLOAD_LEN_END_EXT_64_IDX+4:], masking_key)
	else:
		print("this one is not masked")
		if(pay_len <= 0x7d):
			payload = frame[PAYLOAD_LEN_END_IDX+1:]
			# print("this one is short")
		elif(pay_len == 0x7e):
			payload = frame[PAYLOAD_LEN_END_EXT_16_IDX:]
			# print("this one is not very long")
		else:
			payload = frame[PAYLOAD_LEN_END_EXT_64_IDX:]
			# print("this one is long")

	result = {
		"FIN" : fin,
		"RSV1" :rsv1,
		"RSV2" :rsv2,
		"RSV3" :rsv3,
		"OPCODE" : opcode,
		"MASK" : mask,
		"PAYLOAD_LEN" : payload_len,
		"MASKING_KEY" : masking_key,
		"PAYLOAD" : payload
	}

	return result

# ============================================
# Handshake handler block
# ============================================

HEADERS = {
	"Upgrade": ['websocket'],
	"Connection" : ['upgrade'],
	"Sec-WebSocket-Accept": [],
	"Sec-WebSocket-Protocol" : [],
	"Sec-WebSocket-Key": [],
	"Sec-WebSocket-Version" : ["13"],
	"Origin" : [],
	"Host" : [],
}


CLIENT_HS_HEADERS = {
	# "upgrade": ['websocket'],
	# "connection" : ['upgrade'],
	"sec-websocket-version" : ["13"],
	# "origin" : [],
	# "host" : [],
	"sec-websocket-key": [],
}

SERVER_HS_HEADERS = {
	"upgrade": ['websocket'],
	"connection" : ['upgrade'],
	"sec-websocket-version" : ["13"],
	"sec-websocket-accept": [],
}

# this method is used to generate Sec-WebSocket-Accept value to send to client
# this method take websocket secret key from client
# and returns Sec-WebSocket-Key  <- a string, encoded
def gen_accept_key(sec_key):
	temp = sec_key+GUID
	print(temp)
	return base64.b64encode(hashlib.sha1(temp.encode('utf-8')).digest()).decode('utf-8')


# this function used to validate Sec-WebSocket-Key sent by client
# returns true if the decoded bytes of the key is 16 bytes long
# and false if it is not
def is_valid_sec_key(sec_key):
	return len(base64.b64decode(sec_key)) == 16

# this function is used to build a HTTP request
# takes 4 arguments: method, path, protocol, headers
# and returns a HTTP request
def build_http_request(method, path, protocol, headers):
	request_line = method + " " + path + " " + protocol
	req = request_line + '\r\n' + '\r\n'.join(headers) + '\r\n'

	return req.encode('utf-8')


# this function parse incoming HTTP request
# takes one parameter: HTTP request
# and returns dictionary
def parse_http_request(req):
	
	lines = req.strip().split('\n')

	request_line = lines[0].split(' ')
	method = request_line[0]
	path = request_line[1]
	protocol = request_line[2]

	headers = {}
	for line in lines[1:]:
		temp = line.split(':')
		headers[temp[0].lower().strip()] = [i.strip() for i in temp[1].split(',')] 

	result = {
		"METHOD": method,
		"PATH": path,
		"PROTOCOL": protocol,
		"HEADERS" : headers,
	}

	# for i in result:
		# print(i, result[i])
	# print("===============")
	return result

# this function return true if a websocket handshake request is valid
# and false if not
# takes one argument: HTTP request
def is_handshake_valid(request):
	
	req = parse_http_request(request)

	# allow only GET method
	if (req["METHOD"] != "GET"):
		print("method not Allowed")
		return False

	# # check if client has all the required headers to perform websocket handshake and matching value
	for h in CLIENT_HS_HEADERS:
		if (h not in req["HEADERS"]):
			print("header", h, "not in request")
			return False
		else:
			if (len(CLIENT_HS_HEADERS[h]) > 0):
				# print(">>>>>", req["HEADERS"][h][0])
				# print(">>>>>", CLIENT_HS_HEADERS[h][0])
				if (req["HEADERS"][h][0].lower() != CLIENT_HS_HEADERS[h][0].lower()):
				# if (i not in CLIENT_HS_HEADERS[h] for i in req["HEADERS"][h]):
					print("value of header", h, "not match")
					return False


	if(not is_valid_sec_key(req["HEADERS"]["sec-websocket-key"][0])):
		return False

	# print("Valid handshake...")
	return True


# this function is used to create a response to websocket handshake
# takes one argument: HTTP req
# and returns response for that request, status
def reply_handshake(request):
	req = parse_http_request(request)
	if (is_handshake_valid(request)):
		print("Valid handshake...")
		sec_key = gen_accept_key(req["HEADERS"]["sec-websocket-key"][0])
		success = True
		response = ["HTTP/1.1 101 Switching Protocols",
					 "Upgrade: websocket",
					 "Connection: Upgrade",
					 "Sec-WebSocket-Accept: {}".format(sec_key), 
					 ""]
		resp = 'HTTP/1.1 101 Switching Protocols\r\n'\
				+'Upgrade: websocket\r\n'\
				+'Connection: Upgrade\r\n'\
				+'Sec-WebSocket-Accept: %s\r\n' % sec_key+'\r\n'
# 		response = """HTTP/1.1 101 Switching Protocol
# Upgrade: websocket
# Connection: upgrade
# Sec-WebSocket-Key: {}""".format(sec_key)

	else:
		success = False
		response = ["HTTP/1.1 400 Bad Request",""]
		# response = """HTTP/1.1 400 Bad Request"""

	# print("\r\n".join(response)+'\r\n')
	print(resp)
	# return "\r\n".join(response)+'\r\n', success
	return resp, success

# this function is used to parse payload
# takes one argument: payload
# returns the method (!echo, !submission, !check) and body
def parse_payload(payload):
	
	methods = ["!echo", "!submission", ]
	body = None


	try:
		payload = payload.decode('utf-8').split(' ', 1)
	except:
		return None, payload
	
	if (payload[0] in methods):
		method = payload[0]
		if (len(payload) > 1):
			body = payload[1]
	else:
		method = None
		body = ' '.join(payload)
	return method, body



		




