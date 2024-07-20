import ipaddress
import socket
import select
import struct
import time

from .ioctl import ioctl

class Rawsocket:
	def __init__(self, interface):
		self._ETH_P_ALL = 3

		self.sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, 
								  socket.htons(self._ETH_P_ALL))
		self.sock.bind((interface, 0))
		self.interface = interface

		self.timeout_sec = 10
		self.blocking = False

		self._PACKET_MR_PROMISC = 1    # Promiscuous mode

		self._SOL_PACKET = 263
		self._PACKET_ADD_MEMBERSHIP = 1

		res = ioctl.get_ip(interface, self.sock)
		if res[0]:
			self.if_ip_addr = res[1]
		
		res = ioctl.get_mac(interface, self.sock)
		if res[0]:
			self.if_mac_addr = res[1]
		
	def __del__(self):
		self.sock.close()
	
	def recv_eth(self, length=1514):
		s_time = time.time()
		fd_set = set()
		fd_set.add(self.sock)
		
		while True:
			r, _, _ = select.select(list(fd_set), [], [], 0)
			result = dict()
			if len(r) > 0:
				if self.sock in r:
					data = self.sock.recv(length)
					result = self.parse_eth(data)
					break
			if not self.blocking:
				c_time = time.time()
				if c_time - s_time >= self.timeout_sec:
					print("Timeout.")
					break
		return result
	
	def parse_eth(self, data):
		result = dict()
		#result['Raw'] = data
		result["DstMAC"] = int.from_bytes(data[:6], 'big')
		result["SrcMAC"] = int.from_bytes(data[6:12], 'big')
		result["EthProto"] = int.from_bytes(data[12:14], 'big')
		result["Payload"] = data[14:]
		return result
	
	def mac_to_num(self, mac):
		if mac.find(":") != -1:
			mac_bytes_str = mac.split(':')
			mac_bytes = [ int(s, 16).to_bytes(1, 'big') for s in mac_bytes_str ]
			result = b''
			for b in mac_bytes:
				result += b
			return result
		elif mac.find("-") != -1:
			mac_bytes_str = mac.split('-')
			mac_bytes = [ int(s, 16).to_bytes(1, 'big') for s in mac_bytes_str ]
			result = b''
			for b in mac_bytes:
				result += b
			return result
		elif len(mac) == 12:
			i = 0
			j = 2
			mac_bytes_str = list()
			for _ in range(len(s) // 2):
				mac_bytes_str.append(mac[i:j])
				i += 2
				j += 2
			mac_bytes = [ int(s, 16).to_bytes(1, 'big') for s in mac_bytes_str ]
			result = b''
			for b in mac_bytes:
				result += b
			return result
		else:
			return None
	
	def send_eth(self, dst_mac, eth_proto, payload):
		src_mac = self.if_mac_addr
		data = self.eth_header(dst_mac, src_mac, eth_proto) + payload
		#self.show(data)
		return self.sock.sendall(data)
	
	def show(self, data):
		print(f"{data[0]:02x}:{data[1]:02x}:{data[2]:02x}:{data[3]:02x}:{data[4]:02x}:{data[5]:02x}")
		print(f"{data[6]:02x}:{data[7]:02x}:{data[8]:02x}:{data[9]:02x}:{data[10]:02x}:{data[11]:02x}")
		print(f"{data[12]:02x}{data[13]:02x}")
		print(data[14:34].hex())
		print(int.from_bytes(data[34:36], 'big'))
		print(int.from_bytes(data[36:38], 'big'))
		print(int.from_bytes(data[38:40], 'big'))
		print(data[40:42].hex())
		print(data[42:])
	
	def eth_header(self, dst_mac, src_mac, eth_proto):
		dst = self.mac_to_num(dst_mac)
		src = self.mac_to_num(src_mac)
		proto = eth_proto.to_bytes(2, 'big')
		return dst + src + proto
	
	def ipv4_to_num(self, ip):
		return int(ipaddress.IPv4Address(ip))
	
	def ipv6_to_num(self, ip):
		return int(ipaddress.IPv6Address(ip))

	def num_to_mac(self, num):
		byte = num.to_bytes(6, 'big')
		string = f'{byte[0]:02x}:{byte[1]:02x}:{byte[2]:02x}:{byte[3]:02x}:{byte[4]:02x}:{byte[5]:02x}'
		return string

	def num_to_ipv4(self, num):
		byte = num.to_bytes(6, 'big')
		string = f'{byte[0]}.{byte[1]}.{byte[2]}.{byte[3]}'
		return string
	
	def set_timeout(timeout):
		self.timeout_sec = timeout
	
	def set_blocking(blocking):
		self.blocking = blocking
	
	def get_timeout(timeout):
		return self.timeout_sec
	
	def get_blocking(blocking):
		return self.blocking

	# Promiscuous mode (Linux)
	def set_promiscuous():
		ifindex = socket.if_nametoindex(self.interface)
		action = self._PACKET_MR_PROMISC
		alen = 0
		address = b'\0'

		packet_mreq = struct.pack('iHH8s', ifindex, type, alen, address)
		self.sock.setsockopt(self._SOL_PACKET,
							 self._PACKET_ADD_MEMBERSHIP, packet_mreq)
