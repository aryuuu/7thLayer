#!/usr/bin/python3

import hashlib
import base64

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

	result = ''
	
	for i in range(len(payload)):
		result += chr(ord(payload[i]) ^ ord(payload[i % 4]))

	return result



# this method is used to generate Sec-WebSocket-Accept value to send to client
# this method take websocket secret key from client
# and returns Sec-WebSocket-Key  <- a string, encoded
def gen_accept_key(sec_key):
	temp = sec_key+GUID
	return base64.b64encode(hashlib.sha1(temp.encode('utf-8')).digest())


# this function used to validate Sec-WebSocket-Key sent by client
# returns true if the decoded bytes of the key is 16 bytes long
# and false if it is not
def validate_sec_key(sec_key):
	return len(base64.b64decode(sec_key)) == 16

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

     much better for me, 
 """


def build_frame(fin=FALSE, rsv1=0, rsv2=0, rsv3=0, opcode=CONTINUATION, mask=0, payload_len, masking_key=None, payload):
	# build our frame first byte
	first_byte = (fin << 7) + (rsv1 << 6) + (rsv2 << 5) + (rsv3 << 4) + opcode
	first_byte = imp_int_to_utf8(first_byte)

	# build the next byte
	if (payload_len < 0x7e):
		second = imp_int_to_utf8((mask << 7) + payload_len)
	elif (payload_len == 0x7e):
		second = imp_int_to_utf8((mask << 7) + 0x7e) + imp_int_to_utf8(payload_len, 16)
	else:
		second = imp_int_to_utf8((mask << 7) + 0x7f) + imp_int_to_utf8(payload_len, 64)

	third = ''.encode('utf-8')
	if (mask == 1):
		third = masking_key
		last = mask_payload(payload, masking_key)
	else:
		last = payload

	return first_byte + second + third + last





# this function is used to parse a frame
# takes utf-8 encoded string (packet frame) as argument
# returns dictionary of frame (like JSON) consist of FIN, RSV1, RSV2, RSV3, OPCODE, MASK, PAYLOAD_LEN, MASKING_KEY, PAYLOAD
def parse_frame(frame):
	fin = frame[FIN_IDX] >> 7
	rsv1 = frame[RSV1_IDX] << 1 >> 7
	rsv2 = frame[RSV2_IDX] << 2 >> 7
	rsv3 = frame[RSV3_IDX] << 3 >> 7

	opcode = frame[OPCODE_IDX] & 0x0f
	mask = frame[MASK_IDX] >> 7

	pay_len = frame[PAYLOAD_START_IDX] & 0x7f
	if (pay_len <= 0x7d):
		payload_len = pay_len
	elif (PAY_LEN == 0x7e):
		payload_len = frame[PAYLOAD_LEN_START_IDX:PAYLOAD_LEN_END_EXT_16_IDX] & 0x0fffff
	else:
		payload_len = frame[PAYLOAD_LEN_START_IDX:PAYLOAD_LEN_END_EXT_64_IDX] & 0x0fffffffffffffffff

	# check if mask exist
	if (mask == 1):
		if(pay_len == 0x7d):
			masking_key = frame[PAYLOAD_LEN_END_IDX:PAYLOAD_LEN_END_IDX+4]
		elif(pay_len == 0x7e):
			masking_key = frame[PAYLOAD_LEN_START_EXT_IDX:PAYLOAD_LEN_END_EXT_16_IDX+4]
		else:
			masking_key = frame[PAYLOAD_LEN_START_EXT_IDX:PAYLOAD_LEN_END_EXT_64_IDX+4]

	# and again check if mask exist
	if(mask == 1):
		if(pay_len == 0x7d):
			payload = frame[PAYLOAD_LEN_END_IDX+4:]
		elif(pay_len == 0x7e):
			payload = frame[PAYLOAD_LEN_END_EXT_16_IDX+4:]
		else:
			payload = frame[PAYLOAD_LEN_END_EXT_64_IDX+4:]


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
