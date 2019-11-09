#!/usr/bin/python3
import socket

# create a socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = "127.0.0.1"
port = 6969

# bind socket to the port
server_socket.bind((host, port))
