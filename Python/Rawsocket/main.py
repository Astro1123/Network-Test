from Socket.UDPsocket import UDPsocket
from Socket.IPsocket import IPsocket
from Socket.Rawsocket import Rawsocket
from Socket.ARP import ARP

import config

# インターフェース名
INTERFACE = config.INTERFACE

# 送信元
SRC_PORT  = config.SRC_PORT

# 宛先
DST_MAC   = config.DST_MAC
DST_IP    = config.DST_IP
DST_PORT  = config.DST_PORT

def recvUDP(ifname, dst_port, dstIP=None, srcPort=None, srcIP=None):
	udp = UDPsocket(ifname)
	while True:
		result = udp.recv_udp()
		if result['EthProto'] != 0x0800:
			continue
		elif result['Protocol'] != 17:
			continue
		if dstIP != None and result["DstIP"] != dstIP:
			continue
		if srcIP != None and result["SrcIP"] != srcIP:
			continue
		if srcPort != None and result["SrcPort"] != srcPort:
			continue
		if result["DstPort"] == dst_port:
			break
	print(result)

def sendUDP(ifname, message, dstMAC, dstIP, dstPort,
			srcPort=None, checksum=True):
	udp = UDPsocket(ifname)
	cs = None
	payload = message.encode('utf-8')
	udp.send_udp_ipv4(dstMAC, dstIP,
					  dstPort, payload, srcPort, checksum)

def executeARP(ifname, dstIP):
	arp = ARP(ifname)
	result = arp.execute(dstIP)
	print(result)
	print()
	print(f'{dstIP} -> {arp.num_to_mac(result["DstMAC"])}')

if __name__ == '__main__':
	try:
		#recvUDP(INTERFACE, DST_PORT)
		sendUDP(INTERFACE, "Hello", DST_MAC, DST_IP, DST_PORT, SRC_PORT)
		executeARP(INTERFACE, DST_IP)
	except OSError as e:
		print(e)
