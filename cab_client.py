import socket
import struct
import sys
import array
import logging

logger = logging.getLogger("tcp")

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
    
################################################################################
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
class cab_client:
    def __init__(self):
        self.server_ip = '128.238.147.221'
        self.server_port = '9000'
        self.bufer_size = 102400
        self.skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    def create_connection(self):
        if skt == None:
            try:
                self.skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.skt.connect((server_ip,server_port))
            except socket.error,(value,message):
                self.handle_error()
    def handle_error(self):
        self.skt = None
        logger.error("TCP ERROR:\t%s %s",value,message)
        logger.info("TCP INFO:\ttry to re-connect " + self.server_ip + " : " + self.server_port)
        sleep(1)
        self.create_connection()

    def query(request):
        if not isinstance(request,pkt_h):
            return None
        request_len = 16
        message = struct.pack('!IIIII',request_len, request.ip_src,request.ip_dst , request.port_src, request.port_dst)
        try: 
    	    s.send(message)
    	    s.shutdown(socket.SHUT_WR)
        except socket.error,(value,message):
            self.handle_error()
    	data = s.recv(buffer_size)
        (body_length,) =  struct.unpack('!I',data[0:4])
        rules_num = body_length/32
        rules = [] 
        for i in range(rules_num):
            rules.append(bktOrR())
            #ignore port
            (rules[i].ip_src,rules[i].ip_src_mask,rules[i].ip_dst, rules[i].ip_dst_mask) = struct.unpack('!IIII', data[4 + i*32: 4+ i * 32 + 16])
            return rules
    
#for test
if __name__ == "__main__":
    src = ipv4_to_int('10.0.0.1')
    dst =  ipv4_to_int('10.0.0.2')
    src_str = ipv4_to_str(src)
    dst_str = ipv4_to_str(dst)
    print "int : %s %s" % (src,dst)
    print "str : %s %s" % (src_str,dst_str)
    request = pkt_h(src, dst, 4000, 8000) 
    rules = query(request)
    for i in rules:
    	print i
