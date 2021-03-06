from fcntl import ioctl
import socket
import struct
import sys
import logging
from common import StrtoHex

logger = logging.getLogger('icn_data') 

_PAD = b'\x00'

#We get this value from file bits/ioctls.h 
SIOCGIFHWADDR = 0x8927

ICN_MAP = {
    "ETH_TYPE" : 0x0901 ,
    "Version"  : 0x0064,
    "Interest_Type_With_Known_GUID" :  0x31 ,
    "Interest_Type_With_Unkown_GUID" : 0x30 ,
    "Content_Type" : 0x40
}

def get_hwaddr(ifname):
    hw_addr = []
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    try:
        #struct ifreq is defined in Linux, which occupies 40 bytes.
        #changes will be written in this buffer after finishing ioctl system call.
        #from the structure of we can know that 18~24 bytes represent hw address
        ifreq = ioctl(sock.fileno(), SIOCGIFHWADDR, struct.pack('40s', ifname))

        mac_addr = ifreq[18:24]
        for item in mac_addr :
            value = struct.unpack("B", str(item))[0]
            hw_addr.append( str(hex(value)[2:]) )   
        return hw_addr    
    except:
        print sys.exc_info()
        logger.error( "network interface %s does not exist in system" %(ifname) )
        return None 

class EtherHeader:
    def __init__(self, dstMAC_hexstring, srcMAC_hexstring, ethertype):
        self.dmac = []
        self.smac = []
        self.ethertype = 0
        self.set_MAC(dstMAC_hexstring)
        self.set_MAC(srcMAC_hexstring)
        self.set_ethertype(ethertype)
    
    def set_MAC(self, hexstring):
        #  @parm: hexstring should be a hex string like "aaaaffff"
        for i in xrange(0, len(hexstring)/2):
            int_c = int(hexstring[i*2:i*2+2],16)    
            #print (hexstring[i*2:i*2+2]),int_c
            self.dmac.append(int_c)
            
    def set_ethertype(self, ethertype):
        self.ethertype = ethertype
        
    def packed(self):
        packed = b""
        for value in self.dmac:
            packed += struct.pack("!B", value)
        for value in self.smac:
            packed += struct.pack("!B", value)

        packed += struct.pack("!H",  self.ethertype)
        return packed 

class InterestPkt :
    GUID_Byte_len = 16
    Fixed_Length = 38
    
    def __init__(self, GUID_hexstring, HRName, Payload_hexstring, Interest_Type = ICN_MAP["Interest_Type_With_Known_GUID"]):
        self.pktype = Interest_Type
        self.pktlength =  0
        self.GUID = []
        self.resv = _PAD * 16  
        self.HRN_len = len(HRName)
        self.HRN = HRName
        self.payload = []
        
        self.set_GUID(GUID_hexstring)
        self.set_Payload(Payload_hexstring)
        
        #packet total length, not including the Ethernet header 
        self.pktlength = InterestPkt.Fixed_Length + self.HRN_len + len(self.payload)
        
    def set_GUID(self, hexstring):
        if len(hexstring) != InterestPkt.GUID_Byte_len * 2 :
            logger.error( "GUID %s does not have correct length %u" %(hexstring, InterestPkt.GUID_Byte_len) )
            return
        for i in xrange(0, len(hexstring)/2):
            int_c = int(hexstring[i*2:i*2+2],16)    
            #print (hexstring[i*2:i*2+2]),int_c
            self.GUID.append(int_c)
            
    def set_Payload(self, hexstring):
        for i in xrange(0, len(hexstring)/2) :
            int_c = int(hexstring[i*2:i*2+2],16)    
            #print (hexstring[i*2:i*2+2]),int_c
            self.payload.append(int_c)
    
    def packed(self):
        packed = b""
        packed += struct.pack("!H",  self.pktype)
        packed += struct.pack("!H",  self.pktlength)
        for value in self.GUID :
            packed += struct.pack("!B", value)
            
        packed += _PAD * 16
        
        packed += struct.pack("!H",  self.HRN_len)
        packed += struct.pack( "!%us" %(self.HRN_len), self.HRN )
        
        for value in self.payload :
            packed += struct.pack("!B", value)
        
        return packed

class EtherParser :
    Fixed_Length = 14
    def __init__(self, raw):
        self.raw = raw
        
        self.dmac = None
        self.smac = None
        self.ethertype = 0
        
        if raw is not None :
            self.parse(raw)
            
    def parse(self, raw_data):
        raw = b""
        
        if not isinstance(raw_data, bytes) :
            #logger.debug("the type of the raw data is not bytes type %s" %(str(raw_data)))
            for i in xrange(0, len(raw_data)/2):
                value = int(raw_data[i*2:i*2+2],16)    
                raw += struct.pack("!B", value) 
        else :
            raw = raw_data
            
        raw_len = len(raw)
        if raw_len < EtherParser.Fixed_Length :
            logger.info('receive an packet data, which is too short to parse header: data len %u' % (raw_len) )
            return
        
        self.dmac = struct.unpack('!6s', raw[0:6])[0]
        self.smac = struct.unpack('!6s', raw[6:12])[0]
        self.ethertype = struct.unpack('!H', raw[12:14])[0]
        
        return
        

class InterestParser :
    Fixed_Length = 26
    def __init__(self, raw):
        self.raw = raw
        
        self.version = 0         # 2 byte
        self.total_len = 0         # 2 byte
        self.icn_type = 0        # 1 byte
        self.resv = _PAD * 3     
        self.GUID = None        #  16 byte
        self.HRN_len = 0        #  2 byte 
        self.HRN = None
        
        if raw is not None :
            self.parse(raw)
    
    def parse(self, raw_data):
        raw = b""
        
        if not isinstance(raw_data, bytes) :
            #logger.debug("the type of the raw data is not bytes type %s" %(str(raw_data)))
            for i in xrange(0, len(raw_data)/2):
                value = int(raw_data[i*2:i*2+2],16)    
                raw += struct.pack("!B", value) 
        else :
            raw = raw_data
        
        raw_len = len(raw)
        if raw_len < InterestParser.Fixed_Length :
            logger.info('receive an interest packet data, which is too short to parse header: data len %u' % (raw_len) )
            return
        
        self.version = struct.unpack('!H', raw[0:2])[0]
        if self.version != ICN_MAP["Version"] :
            logger.info('ICN packet version %u is not correct, should be %u' % (self.version, ICN_MAP["Version"]) )
            return
        
        self.total_len = struct.unpack('!H', raw[2:4])[0]
        
        assert self.total_len == raw_len
        
        self.icn_type = struct.unpack('!B', raw[4:5])[0]
        if (self.icn_type == ICN_MAP["Interest_Type_With_Known_GUID"]) or (self.icn_type == ICN_MAP["Interest_Type_With_Unkown_GUID"]) :
            pass
        else :
            logger.info('icn type is not interest type, pkt type : %x'  % (self.icn_type) )
            return
        
        self.resv = struct.unpack('!3s', raw[5:8])[0]
                
        self.GUID = struct.unpack('!16s', raw[8:24])[0]
        
        self.HRN_len = struct.unpack('!H', raw[24:26])[0]
        
        self.HRN = struct.unpack('!%us' %(self.HRN_len), raw[26 : 26 + self.HRN_len])[0]
        
        return
    
class ContentParser:
    #Fixed_Length = 33
    def __init__(self, raw):
        self.raw = raw
        
        #self.version = 0         # 2 byte
        #self.total_len = 0       # 2 byte
        #self.icn_type = 0        # 1 byte
        #self.resv = _PAD * 3     
        #self.GUID = None         # 16 byte
        #self.seq = _PAD * 4      # 4  byte
        #self.EFLAG = 0           # 1  byte
        self.HRN_len = 0        
        self.HRN = None
        #self.Data_len = 0
        #self.Data = None
        
        if raw is not None :
            self.parse(raw)
            
    def parse(self, raw_data):
        raw = b""
        
        if not isinstance(raw_data, bytes) :
            #logger.debug("the type of the raw data is not bytes type %s" %(str(raw_data)))
            for i in xrange(0, len(raw_data)/2):
                value = int(raw_data[i*2:i*2+2],16)    
                raw += struct.pack("!B", value) 
        else :
            raw = raw_data
            
        #raw_len = len(raw)
        #if raw_len < ContentParser.Fixed_Length :
            #logger.msg('receive a content packet data, which is too short to parse header: data len %u' % (raw_len) )
            #return
        
        #self.version = struct.unpack('!H', raw[0:2])[0]
        #if self.version != ICN_MAP["Version"] :
            #logger.info('ICN packet version %u is not correct, should be %u' % (self.version, ICN_MAP["Version"]) )
            #return
        
        #self.total_len = struct.unpack('!H', raw[2:4])[0]
        
        #self.icn_type = struct.unpack('!B', raw[4:5])[0]
        #if (self.icn_type != ICN_MAP["Content_Type"])  :
            #logger.msg('packet type is not content type, icn type : %x'  % (self.icn_type) )
            #return
        
        #self.resv = struct.unpack('!3s', raw[5:8])[0]
        
        #self.GUID = struct.unpack('!16s', raw[8:24])[0]
        #logger.debug( "GUID is %s" %(StrtoHex(self.GUID)) )
        
        #self.seq =  struct.unpack('!L', raw[24:28])[0]
        #logger.debug( "seq is %x" %(self.seq) )
        
        #self.EFLAG = struct.unpack('!B', raw[28:29])[0]
        
        self.HRN_len = struct.unpack('!H', raw[29:31])[0]
        #logger.debug( "HRN_len is %x" %(self.HRN_len) )
        
        self.HRN = struct.unpack('!%us' %(self.HRN_len), raw[31 : 31 + self.HRN_len])[0]
        #logger.debug( "HRN is %s" %(self.HRN) )
        
        #self.Data_len = struct.unpack('!H', raw[31 + self.HRN_len : 33 + self.HRN_len])[0]
        #logger.debug( "Data_len is %x" %(self.Data_len) )
        
        #self.Data = struct.unpack('!%us' %(self.Data_len), raw[33 + self.HRN_len : ])[0]
        
        #assert self.total_len == raw_len - 2 - self.Data_len
        
        return
    
if __name__ == "__main__" :
    InteresPkt = b""
    srcMac_string = "".join(get_hwaddr("em1"))
    dstMac_string = "".join(get_hwaddr("em2"))
    ether_header = EtherHeader(srcMac_string, dstMac_string, ICN_MAP["ETH_TYPE"])
    InteresPkt += ether_header.packed()
    print len(InteresPkt)
    
