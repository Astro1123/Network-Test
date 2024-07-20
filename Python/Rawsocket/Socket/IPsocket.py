import socket
from .Rawsocket import Rawsocket

class IPsocket(Rawsocket):
	def __init__(self, interface):
		super().__init__(interface)
		self.identification_v4 = 0
		self._PROTO_IPV4 = 0x0800
		self._PROTO_IPV6 = 0x86dd
	
	def __del__(self):
		super().__del__()
	
	def ip_checksum(self, wl):
		wl_sum = 0
		for n in wl:
			wl_sum += n
		low = wl_sum & 0x0000ffff
		high = ( ( wl_sum & 0xffff0000 ) >> 16 ) & 0xffff
		return ( low + high ) ^ 0xffff
	
	def send_ipv4(self, dst_mac, ip_proto, dst_IP, payload, 
				  ttl=128, tos=0x00, flags=0x2, fragment_offset=0x0000):
		total_length = len(payload) + 20
		identification = self.identification_v4
		src_IP = self.if_ip_addr
		self.identification_v4 = (self.identification_v4 + 1) & 0xffff
		header = self.ipv4_header(total_length, identification, ip_proto, src_IP, 
								  dst_IP, ttl, tos, flags, fragment_offset)
		return self.send_eth(dst_mac, self._PROTO_IPV4, header + payload)
	
	def recv_ipv4(self, length=1514):
		result = self.recv_eth(length)
		return self.parse_ipv4(result)
	
	def parse_ipv4(self, data):
		eth_payload = data["Payload"]
		n = int.from_bytes(eth_payload[:1], 'big')
		data["Version"] = (n & 0xf0) >> 4
		data["IHL"] = (n & 0x0f)
		data["ToS"] = int.from_bytes(eth_payload[1:2], 'big')
		data["TotalLength"] = int.from_bytes(eth_payload[2:4], 'big')
		data["Identification"] = int.from_bytes(eth_payload[4:6], 'big')
		n = int.from_bytes(eth_payload[6:8], 'big')
		data["Flags"] = (n & 0xe000) >> 13
		data["FragmentOffset"] = (n & 0x1fff)
		data["TTL"] = int.from_bytes(eth_payload[8:9], 'big')
		data["Protocol"] = int.from_bytes(eth_payload[9:10], 'big')
		data["IPChecksum"] = int.from_bytes(eth_payload[10:12], 'big')
		data["SrcIP"] = int.from_bytes(eth_payload[12:16], 'big')
		data["DstIP"] = int.from_bytes(eth_payload[16:20], 'big')
		idx = 20
		if data["IHL"] > 5:
			idx += (data["IHL"] - 5) * 4
		data["Payload"] = eth_payload[idx:]
		return data

	def ipv4_header(self, total_length, identification, ip_proto, 
					src_IP, dst_IP, ttl=128, tos=0x00, flags=0x2, 
					fragment_offset=0x0000):
		
		sIP = self.ipv4_to_num(src_IP)
		dIP = self.ipv4_to_num(dst_IP)
		wl = list()
		wl.append(((0x45 << 8) | tos))
		wl.append(total_length)
		wl.append(identification)
		flags_and_offset = ( ( ( flags & 0x0007 ) << 13 ) | 
							 ( fragment_offset & 0x1fff ) )
		wl.append(flags_and_offset)
		wl.append((ttl << 8) | ip_proto)
		wl.append(0x0000)
		wl.append((sIP >> 16) & 0xffff)
		wl.append(sIP & 0xffff)
		wl.append((dIP >> 16) & 0xffff)
		wl.append(dIP & 0xffff)
		
		header  = b'\x45'
		header += tos.to_bytes(1, 'big')
		header += total_length.to_bytes(2, 'big')
		header += identification.to_bytes(2, 'big')
		header += flags_and_offset.to_bytes(2, 'big')
		header += ttl.to_bytes(1, 'big')
		header += ip_proto.to_bytes(1, 'big')
		header += self.ip_checksum(wl).to_bytes(2, 'big')
		header += sIP.to_bytes(4, 'big')
		header += dIP.to_bytes(4, 'big')
		return header
	
	def send_ipv6(self, dst_mac, next_header, src_IP, dst_ip, payload,
				  hop_limit=128, traffic_class=0x00, flow_label=0x000000):
		payload_length = len(payload)
		header = self.ipv6_header(payload_length, next_header, src_ip, dst_ip, 
								  hop_limit, traffic_class, flow_label)
		return self.send_eth(dst_mac, self._PROTO_IPV6, header + payload)
	
	def ipv6_header(self, payload_length, next_header, src_ip, dst_ip, 
					hop_limit=128, traffic_class=0x00, 
					flow_label=0x000000, payload=None):
		sIP = self.ipv4_to_num(src_ip)
		dIP = self.ipv4_to_num(dst_ip)
		header += ( ( 0x6 << 4 ) | ( ( traffic_class & 0xf0 ) >> 4 ) ).to_bytes(1, 'big')
		header += ( ( flow_label & 0x0fffff ) | ( ( traffic_class & 0x0f ) << 20 ) ).to_bytes(3, 'big')
		header += payload_length.to_bytes(2, 'big')
		header += next_header.to_bytes(1, 'big')
		header += hop_limit.to_bytes(1, 'big')
		header += sIP.to_bytes(16, 'big')
		header += dIP.to_bytes(16, 'big')
		if payload != None:
			header += payload
		return header
	
	def recv_ipv6(self, length=1514):
		result = self.recv_eth(length)
		return parse_ipv6(result)
	
	def parse_ipv6(self, data):
		eth_payload = data["Payload"]
		n = int.from_bytes(eth_payload[:4], 'big')
		data["Version"] = (n & 0xf0000000) >> 28
		data["TrafficClass"] = (n & 0x0ff00000) >> 20
		data["FlowLabel"] = (n & 0x000fffff)
		data["PayloadLength"] = int.from_bytes(eth_payload[4:6], 'big')
		data["NextHeader"] = int.from_bytes(eth_payload[6:7], 'big')
		data["HopLimit"] = int.from_bytes(eth_payload[7:8], 'big')
		data["SrcIP"] = int.from_bytes(eth_payload[8:24], 'big')
		data["DstIP"] = int.from_bytes(eth_payload[24:40], 'big')
		data["Payload"] = eth_payload[40:]
		return data
		
	