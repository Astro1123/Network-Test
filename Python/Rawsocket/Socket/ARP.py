import ipaddress
import socket
import time
from .Rawsocket import Rawsocket

class ARP(Rawsocket):
	def __init__(self, interface):
		super().__init__(interface)
		self._ETH_TYPE_ARP = 0x0806
		self._PTYPE = 0x0800
		#self._PROTO_IPV6 = 0x86dd
		self._HTYPE = 0x0001
		self._HLEN = 6
		self._PLEN = 4
		self._ARP_REQ = 1
		self._ARP_RPY = 2
		self.arp_timeout_sec = 10
	
	def __del__(self):
		super().__del__()
	
	def execute(self, dstIP):
		srcMAC = self.if_mac_addr
		srcIP = self.if_ip_addr
		self.arp_req(srcMAC, srcIP, dstIP)
		return self.arp_rpy(srcMAC, srcIP, dstIP)
	
	def send_garp(self, dstIP):
		srcMAC = self.if_mac_addr
		srcIP = self.if_ip_addr
		self.garp(srcMAC, srcIP)
	
	def send_probe(self, dstIP):
		srcMAC = self.if_mac_addr
		self.arp_req(srcMAC, dstIP)
		return self.arp_rpy(srcMAC, srcIP, dstIP)
	
	def recv_arp(self, oper=None):
		stime = time.time()
		while True:
			result = self.recv_eth()
			ctime = time.time()
			if ctime - stime >= self.arp_timeout_sec:
				print("Timeout.")
				result = dict()
				break
			if result["EthProto"] != self._ETH_TYPE_ARP:
				continue
			result = self.parseARP(result)
			if oper == None:
				break
			elif oper == result["OPER"]:
				break
		return result
	
	def arp_probe(self, srcMAC, dstIP):
		dstMAC = 'ff:ff:ff:ff:ff:ff'
		payload  = b''
		payload += self._HTYPE.to_bytes(2, 'big')
		payload += self._PTYPE.to_bytes(2, 'big')
		payload += self._HLEN.to_bytes(1, 'big')
		payload += self._PLEN.to_bytes(1, 'big')
		payload += self._ARP_REQ.to_bytes(2, 'big')
		payload += self.mac_to_num(srcMAC)
		payload += self.ipv4_to_num('0.0.0.0').to_bytes(4, 'big')
		payload += self.mac_to_num("00:00:00:00:00:00")
		payload += self.ipv4_to_num(dstIP).to_bytes(4, 'big')
		self.send_eth(dstMAC, self._ETH_TYPE_ARP, payload)

	def arp_req(self, srcMAC, srcIP, dstIP):
		dstMAC = 'ff:ff:ff:ff:ff:ff'
		payload  = b''
		payload += self._HTYPE.to_bytes(2, 'big')
		payload += self._PTYPE.to_bytes(2, 'big')
		payload += self._HLEN.to_bytes(1, 'big')
		payload += self._PLEN.to_bytes(1, 'big')
		payload += self._ARP_REQ.to_bytes(2, 'big')
		payload += self.mac_to_num(srcMAC)
		payload += self.ipv4_to_num(srcIP).to_bytes(4, 'big')
		payload += self.mac_to_num("00:00:00:00:00:00")
		payload += self.ipv4_to_num(dstIP).to_bytes(4, 'big')
		self.send_eth(dstMAC, self._ETH_TYPE_ARP, payload)

	def garp(self, srcMAC, srcIP):
		dstMAC = 'ff:ff:ff:ff:ff:ff'
		payload  = b''
		payload += self._HTYPE.to_bytes(2, 'big')
		payload += self._PTYPE.to_bytes(2, 'big')
		payload += self._HLEN.to_bytes(1, 'big')
		payload += self._PLEN.to_bytes(1, 'big')
		payload += self._ARP_REQ.to_bytes(2, 'big')
		payload += self.mac_to_num(srcMAC)
		payload += self.ipv4_to_num(srcIP).to_bytes(4, 'big')
		payload += self.mac_to_num("00:00:00:00:00:00")
		payload += self.ipv4_to_num(srcIP).to_bytes(4, 'big')
		self.send_eth(dstMAC, self._ETH_TYPE_ARP, payload)

	def parseARP(self, result):
		data = result["Payload"]
		result["HTYPE"] = int.from_bytes(data[:2], 'big')
		result["PTYPE"] = int.from_bytes(data[2:4], 'big')
		result["HLEN"] = int.from_bytes(data[4:5], 'big')
		result["PLEN"] = int.from_bytes(data[5:6], 'big')
		result["OPER"] = int.from_bytes(data[6:8], 'big')
		data = data[8:]
		result["SHA"] = int.from_bytes(data[:self._HLEN], 'big')
		data = data[self._HLEN:]
		result["SPA"] = int.from_bytes(data[:self._PLEN], 'big')
		data = data[self._PLEN:]
		result["THA"] = int.from_bytes(data[:self._HLEN], 'big')
		data = data[self._HLEN:]
		result["TPA"] = int.from_bytes(data[:self._PLEN], 'big')
		return result

	def arp_rpy(self, srcMAC, srcIP, dstIP):
		stime = time.time()
		while True:
			result = self.recv_eth()
			ctime = time.time()
			if ctime - stime >= self.arp_timeout_sec:
				print("Timeout.")
				result = dict()
				break
			if result["DstMAC"] != int.from_bytes(self.mac_to_num(srcMAC), 'big'):
				continue
			if result["EthProto"] != self._ETH_TYPE_ARP:
				continue
			result = self.parseARP(result)
			if result["OPER"] != self._ARP_RPY:
				continue
			elif result["SPA"] != self.ipv4_to_num(dstIP):
				continue
			else:
				break
			break
		return result
	
	def set_arp_timeout(timeout):
		self.arp_timeout_sec = timeout
	
	def get_arp_timeout(timeout):
		return self.arp_timeout_sec

	