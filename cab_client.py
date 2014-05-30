import socket
import struct
import sys
import array
def ipv4_to_str(integre):
    ip_list = [str((integre >> (24 - (n * 8)) & 255)) for n in range(4)]
    return '.'.join(ip_list)

def ipv4_to_int(string):
    ip = string.split('.')
    assert len(ip) == 4
    i = 0
    for b in ip:
        b = int(b)
        i = (i << 8) | b
    return i 

class pkt_h:
    def __init__(self,ip_src=0, ip_dst = 0, port_src = 0, port_dst = 0):
        self.ip_src = ip_src
	self.ip_dst = ip_dst
	self.port_src = port_src 
	self.port_dst = port_dst
class bktOrR(object):
    def __init__(self, ip_src = 0, ip_src_mask = 0, ip_dst = 0, ip_dst_mask = 0, port_src = 0, port_src_mask = 0, port_dst = 0, port_dst_mask = 0):
	self.ip_src = ip_src
        self.ip_src_mask = ip_src_mask
        self.ip_dst = ip_dst
        self.ip_dst_mask = ip_dst_mask
        self.port_src = port_src
        self.port_src_mask = port_src_mask
        self.port_dst = port_dst
        self.port_dst_mask = port_dst_mask
    def __str__(self):
	return "%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t" % (self.ip_src, self.ip_src_mask, self.ip_dst, self.ip_dst_mask, self.port_src, self.port_src_mask, self.port_dst, self.port_dst_mask) 

def query(request):
    if not isinstance(request,pkt_h):
        retrun 
    server_ip = '127.0.0.1'
    server_port = 9000
    buffer_size = 10240
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server_ip,server_port))
    
    request_len = 16
    message = struct.pack('!IIIII',request_len, request.ip_src,request.ip_dst , request.port_src, request.port_dst)
    
    try:
    	s.send(message)
    	s.shutdown(socket.SHUT_WR)
    	data = s.recv(buffer_size)
    finally:
    	s.close()
    
    (body_length,) =  struct.unpack('!I',data[0:4])
    
    rules_num = body_length/32
    print "received: " + str(rules_num) + " rules"
    bucket = [] 
    for i in range(rules_num):
	bucket.append(bktOrR())
        (bucket[i].ip_src,bucket[i].ip_src_mask,bucket[i].ip_dst, bucket[i].ip_dst_mask) = struct.unpack('!IIII', data[4 + i*32: 4+ i * 32 + 16])
    return bucket

if __name__ == "__main__":
    request = pkt_h(ipv4_to_int('10.0.0.1'),ipv4_to_int('10.0.0.2'), 4000,8000) 
    rules = query(request)
    for i in rules:
    	print i
