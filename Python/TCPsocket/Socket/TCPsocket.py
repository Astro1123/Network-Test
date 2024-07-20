import socket
import select
import time

class TCPsocket:
	def __init__(self, src_ip, src_port):
		self._src_addr = (src_ip, src_port)
		self._M_SIZE = 1024
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		self.timeout_sec = 10
		self.blocking = False
	
	def __del__(self):
		self.sock.close()
	
	def send(self, message, dst_ip, port):
		self.sock.connect((dst_ip, port))
		return self.sock.send(message)
		
	def recv(self):
		self.sock.bind(self._src_addr)
		self.sock.listen()
		result = dict()
		s_time = time.time()
		fd_set = set()
		fd_set.add(self.sock)

		while True:
			r, _, _ = select.select(list(fd_set), [], [], 0)
			if len(r) > 0:
				if self.sock in r:
					client, addr = self.sock.accept()
					message = client.recvfrom(self._M_SIZE)
					result["Message"] = message
					result["Address"] = addr
					client.close()
					break
			if not self.blocking:
				c_time = time.time()
				if c_time - s_time >= self.timeout_sec:
					print("Timeout.")
					break
		
		return result
	
	def set_timeout(timeout):
		self.timeout_sec = timeout
	
	def set_blocking(blocking):
		self.blocking = blocking
	
	def get_timeout(timeout):
		return self.timeout_sec
	
	def get_blocking(blocking):
		return self.blocking
	