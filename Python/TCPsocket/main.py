from Socket.TCPsocket import TCPsocket

import config

#送信元
SRC_IP   = config.SRC_IP
SRC_PORT = config.SRC_PORT

#宛先
DST_IP   = config.DST_IP
DST_PORT = config.DST_PORT

if __name__ == '__main__':
	try:
		tcp = TCPsocket(SRC_IP, SRC_PORT)
		#tcp.send("Hello".encode('utf-8'), DST_IP, DST_PORT)
		print(tcp.recv())
	except OSError as e:
		print(e)
