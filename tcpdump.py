from ctypes import *
import socket
from struct import *
import struct
import sys

class IP(Structure):
    _fields_= [
         ("version", c_ubyte, 4),
         ("ihl", c_ubyte, 4),
         ("tos", c_ubyte),
         ("len", c_ushort),
         ("id", c_ushort),
         ("offset", c_ushort),
         ("ttl", c_ubyte),
         ("protocol_num", c_ubyte),
         ("sum", c_ushort),
         ("src", c_uint32),
         ("dst", c_uint32)]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}
        self.src_address = socket.inet_ntoa(struct.pack("@I" ,self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("@I" ,self.dst))

        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)
#-------------------------------------------------------------------------------
class TCP(Structure):
    _fields_ = [
         ("src_p", c_ubyte),
         ("dst_p", c_ubyte),
         ("seq", c_uint32),
         ("ack", c_uint32),
         ("len", c_ushort, 4),
         ("rsv", c_ushort, 6),
         ("flag", c_ushort, 6),
         ("win", c_ushort),
         ("check", c_ushort),
         ("up", c_ushort)]
    def __new__(self, socket_buffer = None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass
#-------------------------------------------------------------------------------
class UDP(Structure):
    _fields_=[
         ("src_p", c_ushort),
         ("dst_p", c_ushort),
         ("len", c_ushort),
         ('check', c_ushort)]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        pass
#-------------------------------------------------------------------------------
class ICMP(Structure):
    _fields_=[
         ("type", c_ubyte),
         ("code", c_ubyte),
         ("check", c_ushort),
         ("data", c_uint32)]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        pass
#-------------------------------------------------------------------------------
class IPv6(Structure):
    _fields_=[
         ("version", c_uint32, 4),
         ("tc", c_uint32, 8),
         ("flow", c_uint32, 20),
         ("payload", c_ushort),
         ("n_header", c_ubyte),
         ("hop", c_ubyte),
         ("src", c_ulonglong),
         ("dst", c_ulonglong)]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.protocol_map = {58:"ICMP", 6:"TCP", 17:"UDP"}
        self.src_v6 = socket.inet_ntop(socket.AF_INET6, socket_buffer[8:24])
        self.dst_v6 = socket.inet_ntop(socket.AF_INET6, socket_buffer[24:40])

        try:
            self.protocol = self.protocol_map[self.n_header]
        except:
             self.protocol = str(self.n_header)

def arp_head(arp_data):
   h_type, p_type, h_len, p_len, opc, s_addr, s_paddr, t_addr, t_paddr = struct.unpack('!HHBBH6s4s6s4s', arp_data[14:42])
   pro_tp = socket.htons(p_type)
   t_mac = get(t_addr)
   s_mac = get(s_addr)
   s_ip = socket.inet_ntoa(s_paddr)
   t_ip = socket.inet_ntoa(t_paddr)
   return h_type, pro_tp, h_len, p_len, opc, s_mac, s_ip, t_mac, t_ip

def ethernet_head(ethr_data):
   dst, src, e_protocol = struct.unpack('!6s6sH', ethr_data[:14])
   dst_mac = get(dst)
   src_mac = get(src)
   proto = socket.htons(e_protocol)
   return dst_mac, src_mac, proto

def get(r_addr):
   f_bytes = map('{:02x}'.format, r_addr)
   return ':'.join(f_bytes).upper()

try:
 inter = input('Type the interface name: ')
 sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
 sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
 sock.bind((inter, 0))
except OSError:
   print ('No such interface')
   sys.exit()
except KeyboardInterrupt:
   print ('Exit.')
   sys.exit()

while True:
 try:
   data = sock.recvfrom(65565)[0]
   eth = ethernet_head(data)
   print ('----------------------------------------------------------------------------------------------------------')
   print ('Destination MAC: ',eth[0],' Source MAC: ',eth[1],' Protocol: ',eth[2])
   if eth[2] == 8:
     ip = IP(data[14:])
     print('(IP)',' Source IP: ',ip.src_address, ' Destination IP: ',ip.dst_address)
     if ip.protocol == 'TCP':
        tcp = TCP(data[34:])
        print('(TCP)'' Source port: ',tcp.src_p,' Destination port: ',tcp.dst_p,' Flags: ',tcp.flag,' Ark: ',tcp.ack,' Win: ',tcp.win,' Length: ',tcp.len)
     elif ip.protocol == 'UDP':
        udp = UDP(data[34:])
        print('(UDP)'' Source port: ',udp.src_p,' Destination port: ',udp.dst_p,' Check: ',udp.check,' Length: ',udp.len)
     elif ip.protocol == 'ICMP':
        icmp = ICMP(data[34:])
        print('(ICMP)',' Type: ',icmp.type,' Code: ',icmp.code,' Check: ',icmp.check)
   elif eth[2] == 1544:
     arp = arp_head(data)
     print('(ARP)',' Header Type: ',arp[0],' Protocol Type: ',arp[1],' Header Length: ',arp[2],' Protocol Length: ',arp[3],' Source IP: ',arp[6],' Target IP: ',arp[8])
   elif eth[2] == 56710:
     ipv6 = IPv6(data[14:])
     print('(IPv6)',' Source IPv6: ',ipv6.src_v6, ' Destination IPv6: ',ipv6.dst_v6)
     if ipv6.protocol == 'TCP':
        tcp = TCP(data[34:])
        print('(TCP)'' Source port: ',tcp.src_p,' Destination port: ',tcp.dst_p,' Flags: ',tcp.flag,' Ark: ',tcp.ack,' Win: ',tcp.win,' Length: ',tcp.len)
     elif ipv6.protocol == 'UDP':
        udp = UDP(data[34:])
        print('(UDP)'' Source port: ',udp.src_p,' Destination port: ',udp.dst_p,' Check: ',udp.check,' Length: ',udp.len)
     elif ipv6.protocol == 'ICMP':
        icmp = ICMP(data[34:])
        print('(ICMPv6)',' Type: ',icmp.type,' Code: ',icmp.code,' Check: ',icmp.check)
 except ValueError:
        pass
 except KeyboardInterrupt:
        print (' Exit!')
        sock.close()
        sys.exit()
 except Exception:
        print ('Error')
        sock.close()
        sys.exit()
