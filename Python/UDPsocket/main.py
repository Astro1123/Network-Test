from Socket.UDPsocket import UDPsocket

import config

#送信元
SRC_IP   = config.SRC_IP
SRC_PORT = config.SRC_PORT

#宛先
DST_IP   = config.DST_IP
DST_PORT = config.DST_PORT

if __name__ == '__main__':
	try:
		udp = UDPsocket(SRC_IP, SRC_PORT)
		#udp.send("Hello".encode('utf-8'), DST_IP, DST_PORT)
		print(udp.recv())
	except OSError as e:
		print(e)
