import struct
from fcntl import ioctl

# linux/sockios.h
SIOCGIFHWADDR   = 0x8927  # Get hardware address
SIOCGIFADDR     = 0x8915  # get PA address

# linux/socket.h
AF_UNIX      = 1
AF_INET      = 2

def get_ifaddr(interface, fd):
    iface = interface.encode(encoding='utf-8')
    ifreq  = struct.pack('16sH14s', iface, AF_INET, b'\x00'*14)
    try:
        ifaddr = ioctl(fd.fileno(), SIOCGIFADDR, ifreq)
    except IOError:
        return (False, None, None, None)
    _, sa_family, port, in_addr = struct.unpack('16sHH4s8x', ifaddr)
    return (True, sa_family, port, in_addr)

def get_ip(interface, fd):
    res, _, _, ip = get_ifaddr(interface, fd)
    if res != True:
        return (False, None)
    return (True, f'{ip[0]}.{ip[1]}.{ip[2]}.{ip[3]}')

def get_port(interface, fd):
    res, _, port, _ = get_ifaddr(interface, fd)
    if res != True:
        return (False, None)
    return (True, port)

def get_mac(interface, fd):
    iface = interface.encode(encoding='utf-8')
    ifreq  = struct.pack('16sH14s', iface, AF_UNIX, b'\x00'*14)
    ifaddr = ioctl(fd.fileno(), SIOCGIFHWADDR, ifreq)
    address = struct.unpack('16sH14s', ifaddr)[2]
    mac = struct.unpack('6B8x', address)
    macaddr = f'{mac[0]:02x}:{mac[1]:02x}:{mac[2]:02x}:{mac[3]:02x}:{mac[4]:02x}:{mac[5]:02x}'
    return (True, macaddr)
