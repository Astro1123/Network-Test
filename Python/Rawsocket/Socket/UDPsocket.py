import socket
import random
from .IPsocket import IPsocket

class UDPsocket(IPsocket):
	def __init__(self, interface):
		super().__init__(interface)
		self._PROTO_UDP = 17
	
	def __del__(self):
		super().__del__()
	
	def udp_checksum_ipv4(self, dst_ip, src_port, dst_port, length, payload):
		wl = list()

		src_ip = self.if_ip_addr
		sIP = self.ipv4_to_num(src_ip)
		dIP = self.ipv4_to_num(dst_ip)
		wl.append((sIP & 0xffff0000) >> 16)
		wl.append(sIP & 0x0000ffff)
		wl.append((dIP & 0xffff0000) >> 16)
		wl.append(dIP & 0x0000ffff)
		wl.append(length)
		wl.append(17)
		wl.append(src_port)
		wl.append(dst_port)
		wl.append(length)
		wl.append(0x0000)
		for i in range(0, len(payload), 2):
			word = payload[i] << 8
			if i + 1 < len(payload):
				word |= payload[i+1]
			wl.append(word)
		return self.udp_checksum_sub(wl)
	
	def udp_checksum_ipv6(self, src_ip, dst_ip, src_port, dst_port, length, payload):
		wl = list()

		sIP = self.ipv6_to_num(src_ip)
		dIP = self.ipv6_to_num(dst_ip)
		wl.append((sIP & 0xffff0000) >> 16)
		wl.append(sIP & 0x0000ffff)
		wl.append((dIP & 0xffff0000) >> 16)
		wl.append(dIP & 0x0000ffff)
		wl.append(src_port)
		wl.append(dst_port)
		wl.append(length)
		wl.append(0x0000)
		data = [payload[i:i+2] for i in range(0, len(payload), 2)]
		for d in data:
			if len(d) == 1:
				word = d + b'\x00'
			else:
				word = d
			wl.append(int.from_bytes(word, 'big'))
		return self.udp_checksum_sub(wl)
	
	def udp_checksum_sub(self, wl):
		wl_sum = 0
		for n in wl:
			wl_sum += n
		low = wl_sum & 0x0000ffff
		high = ( ( wl_sum & 0xffff0000 ) >> 16 ) & 0xffff
		cs =  ( low + high ) ^ 0xffff
		if cs == 0x0000:
			cs = 0xffff
		return cs
	
	def udp_header(self, src_port, dst_port, length, data=None, checksum=None):
		header  = b''
		header += src_port.to_bytes(2, 'big')
		header += dst_port.to_bytes(2, 'big')
		header += length.to_bytes(2, 'big')
		if not checksum:
			header += b'\x00\x00'
		else:
			if data["version"] == 4:
				cs = self.udp_checksum_ipv4(data["dst_ip"], src_port, dst_port, length, data["payload"])
			elif data["version"] == 6:
				cs = self.udp_checksum_ipv6(data["src_ip"], data["dst_ip"], src_port, dst_port, length, data["payload"])
			header += cs.to_bytes(2, 'big')
		return header
	
	def recv_udp(self, version=0, length=1514):
		if version == 4:
			result = self.recv_ipv4(length)
			result = self.parse_udp(result)
		elif version == 6:
			result = self.recv_ipv4(length)
			result = self.parse_udp(result)
		else:
			result = self.recv_eth(length)
			payload = result["Payload"]
			n = int.from_bytes(payload[:1], 'big')
			v = (n & 0xf0) >> 4
			if v == 4:
				result = self.parse_ipv4(result)
				result = self.parse_udp(result)
			elif v == 6:
				result = self.parse_ipv6(result)
				result = self.parse_udp(result)
		return result
	
	def parse_udp(self, data):
		payload = data["Payload"]
		data["SrcPort"] = int.from_bytes(payload[:2], 'big')
		data["DstPort"] = int.from_bytes(payload[2:4], 'big')
		data["Length"] = int.from_bytes(payload[4:6], 'big')
		data["Checksum"] = int.from_bytes(payload[6:8], 'big')
		data["Payload"] = payload[8:]
		return data
	
	def send_udp_ipv4(self, dst_mac, dst_IP, dst_port, payload, 
					  src_port=None, checksum=True, 
					  ttl=128, tos=0x00, flags=0x2, fragment_offset=0x0000):
		length = 8 + len(payload)
		if src_port == None:
			src_port = (65535-49152)*random.random()+49152
		data = dict()
		if checksum:
			data["dst_ip"] = dst_IP
			data["version"] = 4
			data["payload"] = payload
		header = self.udp_header(src_port, dst_port, length, data, checksum)
		return self.send_ipv4(dst_mac, self._PROTO_UDP, 
							  dst_IP, header + payload, 
							  ttl, tos, flags, fragment_offset)
	
	def send_udp_ipv6(self, dst_mac, src_ip, dst_ip, dst_port, payload, 
					  src_port=None, checksum=False, 
					  hop_limit=128, traffic_class=0x00, flow_label=0x000000):
		if src_port == None:
			src_port = (65535-49152)*random.random()+49152
		data = dict()
		if checksum:
			data["dst_ip"] = dst_IP
			data["src_ip"] = src_IP
			data["version"] = 6
			data["payload"] = payload
		header = self.udp_header(src_port, dst_port, length, data, checksum)
		length = 8 + len(payload)
		return self.send_ipv6(pdst_mac, self._PROTO_UDP, 
							  src_ip, dst_ip, header + payload,
				  			  hop_limit, traffic_clas, flow_label)
	