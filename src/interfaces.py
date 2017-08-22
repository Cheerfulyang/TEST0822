from lib.jsonrpc import JSONRPCProxy
import SocketServer as socketserver
import threading
import logging
import json
import socket
from forward_table import ForwardTable, UEItem, UE2EUIDItem, UERequestItem, CONTENTItem, CONTENT2EUIDItem, CONTENTRequestItem
import icn_data as PKTConstruct
import struct
from configure import IGW2ICN_PortName_List, IGWEUID
import traceback
from Queue import Queue  
from common import StrtoHex
import time
import binascii

logger = logging.getLogger('interfaces')

'''
1. Interface Msg Definition
'''

RPC_Method_By_GNCAR = {
    "requestEUID_UE"        :  "requestEuidOverIp_UE",
    "requestEUID_CONTENT"   :  "requestEuidOverIp_CONTENT",
    "requestEUID_BOTH"      :  "requestEuidOverIp_BOTH",
    "notifyUpdate_UE"       :  "updateEuidNaBindingOverIp_UE",
    "notifyUpdate_CONTENT"  :  "updateEuidNaBindingOverIp_CONTENT",
    "notifyUpdate_BOTH"     :  "updateEuidNaBindingOverIp_BOTH",
    "updateMapping_UE"      :  "updateMapping_UE",
    "updateMapping_CONTENT" :  "updateMapping_CONTENT",
    "updateMapping_BOTH"    :  "updateMapping_BOTH"
} 

UE_ICN_Control_Msg_Map = {
    "Request_EUID_UE"            :       "Request_EUID_UE",          # UE APP need reply, then IGW need notify GNCAR to create mapping
    "Request_EUID_CONTENT"       :       "Request_EUID_CONTENT",
    "Request_EUID_BOTH"          :       "Request_EUID_BOTH",
    "Request_Switching_UE"       :       "Request_Switching_UE",      # UE APP need no reply, but IGW need
    "Request_Switching_CONTENT"  :       "Request_Switching_CONTENT",
    "Request_Switching_BOTH"     :       "Request_Switching_BOTH",
}

UE_ICN_Data_Msg_Map = {
    "Data"  : "Data"
}

IGW_ICN_Control_Msg_Map = {
    "Response_EUID" : "Response_EUID",
    "UeName"        : "UeName",
    "UeEuid"        : "UeEuid",
    "ContentName"   : "ContentName",
    "ContentEuid"   : "ContentEuid"
}

UE_Request_EUID_Msg_Map = {
    "ICN_MSG_TYPE"   :     "IcnMsgType",
    "ENBIP"          :     "eNbIp",
    "REUID"          :     "MsgRequestEuid",
    "UENAME"         :     "UeName",
    "CONTENTNAME"    :     "ContentName",
    "ENBNA"          :     "eNBNa"
}

UE_Request_Switch_Msg_Map = {
    "ENBNA"         :     "eNBNa",
    "UPDATE"        :     "MsgUpdateMapping",
    "ENBNA"         :     "eNBNa",
    "UEEUID"        :     "UeEuid",
    "CONTENTEUID"   :     "ContentEuid"
}

UE_Request_ICNData_Msg_Map = {
    "ICN_MSG_TYPE"   :     "IcnMsgType",
    "EUIDSRC"        :     "EuidSrc",
    "EUIDDST"        :     "EuidDst",
    "PAYLOAD"        :     "Payload"
}

'''
2. Basic Const Variable Definition
'''

BIND_SEND_PORT = 50001
BIND_RECV_PORT = 0x00
ETH_P_ALL = 0x0003
ETH_HEADER_LEN = 14

RPC_GNCAR = None
FWD_ICN   = None
FWD_TABLE = None
UDPServer = None
output_num = 0
input_num= 0
sw_index = False
sw_time1 = None
sw_time2 = None
sw_portid = None
 
'''
3. Class and Function Definition
'''

def calculate_packet_num() :
	print "output packet number :%d" %(output_num)
	print "recv packet number : %d" %(input_num)		

class SendPacket2UE(threading.Thread):  
  
    def __init__(self, t_name, queue):  
  
        threading.Thread.__init__(self, name=t_name)  
  
        self.queue = queue  
  
    def run(self):  
  	global output_num
        while True :
            
            data = self.queue.get()  
            
            Icn_type = struct.unpack('!B', data[18:19])[0]
            if Icn_type == 64 :
                HRName_len = struct.unpack('!H', data[59:61])[0]
                HRName = struct.unpack('!%us' %(HRName_len), data[61 : 61 + HRName_len])[0]
                RequestEUIDList = FWD_TABLE.UERequestMap[HRName]
            
            #ICNData[UE_Request_ICNData_Msg_Map["ICN_MSG_TYPE"]] = UE_ICN_Data_Msg_Map["Data"]
            #ICNData[UE_Request_ICNData_Msg_Map["EUIDSRC"]] = IGWEUID
            
                for euid in RequestEUIDList :
                
                #ICNData[UE_Request_ICNData_Msg_Map["EUIDDST"]] = euid
                
                #ICNData[UE_Request_ICNData_Msg_Map["PAYLOAD"]] =  data[ETH_HEADER_LEN:] 
                
                #ICNData_string = json.dumps(ICNData)
            
                    try:
                        UENAME = FWD_TABLE.UE2EUIDMap[euid]
                        DstPort = FWD_TABLE.UEMap[UENAME].UDPort
                        DstIP = FWD_TABLE.UEMap[UENAME].IP
                    except:
                        raise KeyError

                    UDPServer.server.socket.sendto( data[ETH_HEADER_LEN:] , (DstIP, DstPort) )
                output_num += 1 
            if Icn_type == 33 :
                HRName_len = struct.unpack('!H', data[54:56])[0]
                HRName = struct.unpack('!%us' %(HRName_len), data[56 : 56 + HRName_len])[0]
                RequestEUIDList = FWD_TABLE.CONTENTRequestMap[HRName]
                for euid in RequestEUIDList :
                    try:
                        CONTENTNAME = FWD_TABLE.CONTENT2EUIDMap[euid]
                        DstPort = FWD_TABLE.CONTENTMap[CONTENTNAME].UDPort
                        DstIP = FWD_TABLE.CONTENTMap[CONTENTNAME].IP
                        print "tried"
                    except:
                        raise KeyError
                    UDPServer.server.socket.sendto( data[ETH_HEADER_LEN:] , (DstIP, DstPort) )
                output_num += 1
                
class SendPacket2ICN(threading.Thread):  
  
    def __init__(self, t_name, q):  
  
        threading.Thread.__init__(self, name=t_name)  
  
        self.queue = q  
  
    def run(self):  
        global output_num
        while True :
            
            data = self.queue.get()  
            
            Icn_type = struct.unpack('!B', data[18:19])[0]
            CONTENTEUID = "000220a7ef59c05263e320d8ed366bf8"
            try:
                CONTENTNAME = FWD_TABLE.CONTENT2EUIDMap[CONTENTEUID]
                eNodeBIP = FWD_TABLE.CONTENTMap[CONTENTNAME].eNodeBIP
            #record ICN request address info. When ICN data is returned, a UDP packet will be reconstructed.  
            #The destination IP and Port will be changed to recorded address info.
            #ICN request will be forwarded according to the eNodeBIP
                PortID = FWD_TABLE.eNodeBMap[eNodeBIP].PortID
            except:
                traceback.print_exc()
            
            if Icn_type == 64 :
                FWD_ICN.OutputPort[PortID].send(data)
                output_num += 1
                

def instantiateFWDTABLE( Configure_eNodeBMap={} ):
    global FWD_TABLE
    FWD_TABLE = ForwardTable( eNodeBMap = Configure_eNodeBMap )
    return

class JSONError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

class JSONBadFormat(JSONError):
    pass

class JSONBadRequest(JSONError):
    pass

class JSONBadMethod(JSONError):
    pass

class IGW2GNCAR: 
    def __init__(self, host, port):
        self.jsonrpc = JSONRPCProxy(host, port)

    #def requestEUID(self, ueName):
    #    method = RPC_Method_By_GNCAR["requestEUID"]
    #    params = {"ueName" : ueName}
    #    return self.jsonrpc.request(method, params)
    def requestEUID_UE(self, ueName, portnum):
        method = RPC_Method_By_GNCAR["requestEUID_UE"]
        params = {"ueName" : ueName, "portNum" : portnum}
        return self.jsonrpc.request(method, params)
    
    def requestEUID_CONTENT(self, contentName, portnum):
        method = RPC_Method_By_GNCAR["requestEUID_CONTENT"]
        params = {"contentName" : contentName, "portNum" : portnum}
        return self.jsonrpc.request(method, params)
    
    def requestEUID_BOTH(self, ueName, contentName, portnum):
        method = RPC_Method_By_GNCAR["requestEUID_BOTH"]
        params = {"ueName" : ueName, "contentName" : contentName, "portNum" : portnum}
        return self.jsonrpc.request(method, params)

    def notifyUpdate_UE(self, ueName, portnum, eNodeB_NA):
        method = RPC_Method_By_GNCAR["notifyUpdate_UE"]
        params = {"ueName": ueName, "portNum" : portnum, "eNodebNa": eNodeB_NA}
        self.jsonrpc.notify(method, params)
        
    def notifyUpdate_CONTENT(self, contentName, portnum, eNodeB_NA):
        method = RPC_Method_By_GNCAR["notifyUpdate_CONTENT"]
        params = {"contentName": contentName, "portNum" : portnum, "eNodebNa": eNodeB_NA}
        self.jsonrpc.notify(method, params)
        
    def notifyUpdate_BOTH(self, ueName, contentName, portnum, eNodeB_NA):
        method = RPC_Method_By_GNCAR["notifyUpdate_BOTH"]
        params = {"ueName": ueName, "contentName": contentName, "portNum" : portnum, "eNodebNa": eNodeB_NA}
        self.jsonrpc.notify(method, params)
        
    def updateMapping_UE(self, ueEuid, portnum, eNodeB_NA):
        method = RPC_Method_By_GNCAR["updateMapping_UE"]
        params = {"ueEuid": ueEuid, "portNum" : portnum, "eNodeb2Na": eNodeB_NA}
        return self.jsonrpc.request(method, params)
    
    def updateMapping_CONTENT(self, contentEuid, portnum, eNodeB_NA):
        method = RPC_Method_By_GNCAR["updateMapping_CONTENT"]
        params = {"contentEuid": contentEuid, "portNum" : portnum, "eNodeb2Na": eNodeB_NA}
        return self.jsonrpc.request(method, params)
    
    def updateMapping_BOTH(self, ueEuid, contentEuid, portnum, eNodeB_NA):
        method = RPC_Method_By_GNCAR["updateMapping_BOTH"]
        params = {"ueEuid": ueEuid, "contentEuid": contentEuid, "portNum" : portnum, "eNodeb2Na": eNodeB_NA}
        return self.jsonrpc.request(method, params)
    
    def test_sayhello(self, method="sayHello", params={"hello":"1"}):
        return self.jsonrpc.request(method, params)
    
def instantiate_IGW2GNCAR(GNCAR_IP, GNCAR_Port):
    global RPC_GNCAR
    try:
        RPC_GNCAR = IGW2GNCAR(GNCAR_IP, GNCAR_Port)
    except:
        print traceback.format_exc()
	raise Exception("instantiate IGW2GNCAR failed!")
    return

class IGW2ICNNetwork:
    def __init__( self, ethname_list =[] ):
        self.OutputPort = []
        self._bindeth(ethname_list, self.OutputPort)
        self._handledata(ethname_list)
               
    def _bindeth(self, ethname, OutputPort):
        for i in range( 0, len(ethname) ):
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            try:
                sock.bind( (ethname[i], BIND_SEND_PORT) )
            except:
                raise Exception("create connection to ICN network failed")
            OutputPort.append(sock)
            
    def handledata_thread(self, interface_name, queue):
        global input_num, sw_index, sw_time1, sw_time2, sw_portid
        self.queue = queue
        recv_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        recv_socket.bind((interface_name, BIND_RECV_PORT))
        
        logger.debug( 'listening on %s' % (interface_name) )
	#logger.debug( '\033[1;32;40m listening on %s \033[0m' % (interface_name) )

        # just for 5IGW sw test for only one euid
        if interface_name == "eth2":
            current_portid = 0
        else:
            current_portid = 1

        while True :
                data, addr = recv_socket.recvfrom(1514) 
                if addr[2] != socket.PACKET_OUTGOING :    
                    #check whether packet type is ICN protocol
                    ethertype = struct.unpack('!H', data[12:14])[0]
                    if ethertype != 0x0901 :
                            pass
                    else : 
                            self.queue.put(data)
			    input_num += 1  
                        
        
            
    def VerifyData(self, ICNData_json):
        if UE_Request_ICNData_Msg_Map["EUIDSRC"] not in ICNData_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_ICNData_Msg_Map["EUIDSRC"]) )
            
        if UE_Request_ICNData_Msg_Map["EUIDDST"] not in ICNData_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_ICNData_Msg_Map["EUIDDST"]) )
            
        if UE_Request_ICNData_Msg_Map["PAYLOAD"] not in ICNData_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_ICNData_Msg_Map["PAYLOAD"]) )
            
        return True
    
    def _handledata(self, ethname_list):
        
        for i in range(0, len(ethname_list)) :
            queue = Queue() 
            
            get_data = threading.Thread(target=self.handledata_thread, args=(ethname_list[i], queue) )
            get_data.setDaemon(True)
            get_data.start()
            
            send_data = SendPacket2UE('SendPacket' + str(i), queue)
            send_data.setDaemon(True)
            send_data.start()

    
def instantiate_IGW2ICNNetwork(ethname=[]):
    global FWD_ICN
    try:
        FWD_ICN = IGW2ICNNetwork(ethname)
    except:
	print traceback.format_exc()
        raise Exception("instantiate IGW2ICNNetwork failed!")
    return

        
class IGWUDPHandle(socketserver.BaseRequestHandler):
    def handle(self):
        #this is a udp request, the format is : (data, self.socket), client_addr
        #request_string = str(self.request[0])
        UDP_string = str(self.request[0])
        server_socket  = self.request[1]
        Icn_Type = struct.unpack('!B', UDP_string[4:5])[0]
        request_string = UDP_string[8:]
        #Interest and Data Packets are forwarded directly to the ICN
        if Icn_Type == 48:   #"0x30"
            self.handle_requestICNData(UDP_string)
        if Icn_Type == 64:
            self.handle_reponseData(UDP_string)
        if Icn_Type == 0:
            try:
                request_json = json.loads(request_string)
            except:
                raise JSONBadFormat('Failed to parse request: {}'.format(request_string))
            print request_string
            if UE_Request_EUID_Msg_Map["ICN_MSG_TYPE"] not in request_json:
                raise JSONBadRequest("Missing 'IcnMsgType' field")
            
            logger.debug( "UE Msg type is %s " %(request_json[UE_Request_EUID_Msg_Map["ICN_MSG_TYPE"]]) )
            
            if request_json[UE_Request_EUID_Msg_Map["ICN_MSG_TYPE"]] == UE_ICN_Control_Msg_Map['Request_EUID_UE'] :
                self.handle_requestEUID_UE(request_json, server_socket)
            elif request_json[UE_Request_EUID_Msg_Map["ICN_MSG_TYPE"]] == UE_ICN_Control_Msg_Map['Request_EUID_CONTENT'] :
                self.handle_requestEUID_CONTENT(request_json, server_socket)
            elif request_json[UE_Request_EUID_Msg_Map["ICN_MSG_TYPE"]] == UE_ICN_Control_Msg_Map['Request_EUID_BOTH'] :
                self.handle_requestEUID_BOTH(request_json, server_socket)
            elif request_json[UE_Request_EUID_Msg_Map["ICN_MSG_TYPE"]] == UE_ICN_Control_Msg_Map['Request_Switching_UE'] :
                self.handle_notifySwitching_UE(request_json)
            elif request_json[UE_Request_EUID_Msg_Map["ICN_MSG_TYPE"]] == UE_ICN_Control_Msg_Map['Request_Switching_CONTENT'] :
                self.handle_notifySwitching_CONTENT(request_json)
            elif request_json[UE_Request_EUID_Msg_Map["ICN_MSG_TYPE"]] == UE_ICN_Control_Msg_Map['Request_Switching_BOTH'] :
                self.handle_notifySwitching_BOTH(request_json)
            else :
                raise JSONBadMethod( "method '%s' is not supported" %(request_json[UE_Request_EUID_Msg_Map["ICN_MSG_TYPE"]]) )



    def handle_requestEUID_UE(self, request_json, server_socket):
        
        if UE_Request_EUID_Msg_Map["ENBIP"] not in request_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_EUID_Msg_Map["ENBIP"]) )
            
        if UE_Request_EUID_Msg_Map["REUID"] not in request_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_EUID_Msg_Map["REUID"]) )
            
        MsgRequestEuid_json = request_json[ UE_Request_EUID_Msg_Map["REUID"] ]
        
        if UE_Request_EUID_Msg_Map["UENAME"] not in MsgRequestEuid_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_EUID_Msg_Map["UENAME"]) )
            
        if UE_Request_EUID_Msg_Map["ENBNA"] not in  MsgRequestEuid_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_EUID_Msg_Map["ENBNA"]) )
        
        ENBIP  = request_json[ UE_Request_EUID_Msg_Map["ENBIP"] ]
        UENAME = MsgRequestEuid_json[ UE_Request_EUID_Msg_Map["UENAME"] ]
        ENBNA  = MsgRequestEuid_json[ UE_Request_EUID_Msg_Map["ENBNA"] ]
        #PORTNUM = FWD_TABLE.eNodeBMap[ENBIP].PortID
        PORTNUM = None
        if FWD_TABLE.eNodeBMap[ENBIP].PortID == 0:
            PORTNUM = "5IGW-1"
        elif FWD_TABLE.eNodeBMap[ENBIP].PortID == 1:
            PORTNUM = "5IGW-2"
        else:
            PORTNUM = ""
        

        #logger.debug( "\n----------RequestEUID Msg, ENBIP:%s, UENAME:%s, ENBNA:%s  ----------" %(ENBIP, UENAME, ENBNA) )
        logger.debug( "----------RequestEUID Msg, ENBIP:%s, UENAME:%s, ENBNA:%s, PORTNUM:%s  ----------" %(ENBIP, UENAME, ENBNA, PORTNUM) )
            
        if UENAME == "" or UENAME == None:    
            logger.debug( "UENAME is empty!" )
        else:
            if PORTNUM == "" or PORTNUM == None:    
                logger.debug( "PORTNUM is empty!" )
            else:    
                result_json = RPC_GNCAR.requestEUID_UE(UENAME, PORTNUM)
                    #result_json = RPC_GNCAR.requestEUID(UENAME)
                if 'ueName' not in result_json :
                    logger.debug( "Response msg:%s", str(result_json))
                    raise JSONBadRequest( "Missing '%s' field" %("ueName") )
                if 'ueEuid' not in result_json :
                    logger.debug( "Response msg:%s", str(result_json))
                    raise JSONBadRequest( "Missing '%s' field" %("ueEuid") )
                    
                UENAME = result_json['ueName']
                UEEUID = result_json['ueEuid']
                
                    #logger.debug( "\n----------Response of RequestEUID Msg, UENAME:%s, EUID:%s ----------" %(UENAME, UEEUID) )
                #logger.debug( "----------Response of RequestEUID Msg, UENAME:%s, EUID:%s ----------" %(UENAME, UEEUID) )
                logger.debug( "----------Response of RequestEUID Msg, UENAME:%s, EUID:%s, PORTNUM:%s ----------" %(UENAME, UEEUID, PORTNUM) )
                
                UE2ENBIP = UEItem(UENAME, self.client_address[1], self.client_address[0], ENBIP, UEEUID)
                FWD_TABLE.UEMap_Add_Item(UE2ENBIP)
                
                UE2EUID  = UE2EUIDItem(UENAME, UEEUID)
                FWD_TABLE.UE2EUIDMap_Add_Item(UE2EUID)
                
                FWD_TABLE.show_fwd_table()
                
                result_data = {}
                result_data[ UE_Request_EUID_Msg_Map["ICN_MSG_TYPE"] ] = "Response_EUID_UE"
                result_data[IGW_ICN_Control_Msg_Map["UeName"]] = UENAME
                result_data[IGW_ICN_Control_Msg_Map["UeEuid"]] = UEEUID
                
                DataString = json.dumps(result_data)
		
                ResponseString = b""
                ResponseString += struct.pack("!HHHH",  0x0064, 0x0000, 0x0100, 0x0001)
                ResponseString += DataString              
                self.Send_Response(server_socket, ResponseString)
                
                RPC_GNCAR.notifyUpdate_UE(UENAME, PORTNUM, ENBNA)
        
    def handle_requestEUID_CONTENT(self, request_json, server_socket):
        
        if UE_Request_EUID_Msg_Map["ENBIP"] not in request_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_EUID_Msg_Map["ENBIP"]) )
            
        if UE_Request_EUID_Msg_Map["REUID"] not in request_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_EUID_Msg_Map["REUID"]) )
            
        MsgRequestEuid_json = request_json[ UE_Request_EUID_Msg_Map["REUID"] ]
        
        if UE_Request_EUID_Msg_Map["CONTENTNAME"] not in MsgRequestEuid_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_EUID_Msg_Map["CONTENTNAME"]) )
            
        if UE_Request_EUID_Msg_Map["ENBNA"] not in  MsgRequestEuid_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_EUID_Msg_Map["ENBNA"]) )
        
        ENBIP  = request_json[ UE_Request_EUID_Msg_Map["ENBIP"] ]
        CONTENTNAME = MsgRequestEuid_json[ UE_Request_EUID_Msg_Map["CONTENTNAME"] ]
        ENBNA  = MsgRequestEuid_json[ UE_Request_EUID_Msg_Map["ENBNA"] ]
        #PORTNUM = FWD_TABLE.eNodeBMap[ENBIP].PortID
        PORTNUM = None
        if FWD_TABLE.eNodeBMap[ENBIP].PortID == 0:
            PORTNUM = "5IGW-1"
        elif FWD_TABLE.eNodeBMap[ENBIP].PortID == 1:
            PORTNUM = "5IGW-2"
        else:
            PORTNUM = ""
        

        #logger.debug( "\n----------RequestEUID Msg, ENBIP:%s, UENAME:%s, ENBNA:%s  ----------" %(ENBIP, UENAME, ENBNA) )
        logger.debug( "----------RequestEUID Msg, ENBIP:%s, CONTENTNAME:%s, ENBNA:%s, PORTNUM:%s  ----------" %(ENBIP, CONTENTNAME, ENBNA, PORTNUM) )
            
        if CONTENTNAME == "" or CONTENTNAME == None:    
            logger.debug( "CONTENTNAME is empty!" )
        else:
            if PORTNUM == "" or PORTNUM == None:    
                logger.debug( "PORTNUM is empty!" )
            else:    
                result_json = RPC_GNCAR.requestEUID_CONTENT(CONTENTNAME, PORTNUM)
                if 'contentName' not in result_json :
                        logger.debug( "Response msg:%s", str(result_json))
                        raise JSONBadRequest( "Missing '%s' field" %("contentName") )
                if 'contentEuid' not in result_json :
                    logger.debug( "Response msg:%s", str(result_json))
                    raise JSONBadRequest( "Missing '%s' field" %("contentEuid") )
                    
                CONTENTNAME = result_json['contentName']
                CONTENTEUID = result_json['contentEuid']
                
                logger.debug( "----------Response of RequestEUID Msg, CONTENTNAME:%s, EUID:%s, PORTNUM:%s ----------" %(CONTENTNAME, CONTENTEUID, PORTNUM) )
                
                CONTENT2ENBIP = CONTENTItem(CONTENTNAME, self.client_address[1], self.client_address[0], ENBIP, CONTENTEUID)
                FWD_TABLE.CONTENTMap_Add_Item(CONTENT2ENBIP)
                
                RecordReqItem = CONTENTRequestItem(CONTENTEUID, CONTENTNAME)
                FWD_TABLE.CONTENTRequestMap_Add_Item(RecordReqItem)
                
                CONTENT2EUID  = CONTENT2EUIDItem(CONTENTNAME, CONTENTEUID)
                FWD_TABLE.CONTENT2EUIDMap_Add_Item(CONTENT2EUID)
                
                #FWD_TABLE.show_fwd_table()
                
                result_data = {}
                result_data[ UE_Request_EUID_Msg_Map["ICN_MSG_TYPE"] ] = "Response_EUID_CONTENT"
                result_data[IGW_ICN_Control_Msg_Map["ContentName"]] = CONTENTNAME
                result_data[IGW_ICN_Control_Msg_Map["ContentEuid"]] = CONTENTEUID
                
                DataString = json.dumps(result_data)
                ResponseString = b""
                ResponseString += struct.pack("!HHHH",  0x0064, 0x0000, 0x0100, 0x0001)
                ResponseString += DataString          
                        
                self.Send_Response(server_socket, ResponseString)
                
                RPC_GNCAR.notifyUpdate_CONTENT(CONTENTNAME, PORTNUM, ENBNA)
        
    def handle_requestEUID_BOTH(self, request_json, server_socket):
        
        if UE_Request_EUID_Msg_Map["ENBIP"] not in request_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_EUID_Msg_Map["ENBIP"]) )
            
        if UE_Request_EUID_Msg_Map["REUID"] not in request_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_EUID_Msg_Map["REUID"]) )
            
        MsgRequestEuid_json = request_json[ UE_Request_EUID_Msg_Map["REUID"] ]
        
        if UE_Request_EUID_Msg_Map["UENAME"] not in MsgRequestEuid_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_EUID_Msg_Map["UENAME"]) )
        
        if UE_Request_EUID_Msg_Map["CONTENTNAME"] not in MsgRequestEuid_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_EUID_Msg_Map["CONTENTNAME"]) )
            
        if UE_Request_EUID_Msg_Map["ENBNA"] not in  MsgRequestEuid_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_EUID_Msg_Map["ENBNA"]) )
        
        ENBIP  = request_json[ UE_Request_EUID_Msg_Map["ENBIP"] ]
        UENAME = MsgRequestEuid_json[ UE_Request_EUID_Msg_Map["UENAME"] ]
        CONTENTNAME = MsgRequestEuid_json[ UE_Request_EUID_Msg_Map["CONTENTNAME"] ]
        ENBNA  = MsgRequestEuid_json[ UE_Request_EUID_Msg_Map["ENBNA"] ]
        #PORTNUM = FWD_TABLE.eNodeBMap[ENBIP].PortID
        PORTNUM = None
        if FWD_TABLE.eNodeBMap[ENBIP].PortID == 0:
            PORTNUM = "5IGW-1"
        elif FWD_TABLE.eNodeBMap[ENBIP].PortID == 1:
            PORTNUM = "5IGW-2"
        else:
            PORTNUM = ""
        

        #logger.debug( "\n----------RequestEUID Msg, ENBIP:%s, UENAME:%s, ENBNA:%s  ----------" %(ENBIP, UENAME, ENBNA) )
        logger.debug( "----------RequestEUID Msg, ENBIP:%s, UENAME:%s, CONTENTNAME:%s, ENBNA:%s, PORTNUM:%s  ----------" %(ENBIP, UENAME, CONTENTNAME, ENBNA, PORTNUM) )
        
        if CONTENTNAME == "" or CONTENTNAME == None:    
            logger.debug( "CONTENTNAME is empty!" )    
        if UENAME == "" or UENAME == None:    
            logger.debug( "UENAME is empty!" )
        else:
            if PORTNUM == "" or PORTNUM == None:    
                logger.debug( "PORTNUM is empty!" )
            else:    
                result_json = RPC_GNCAR.requestEUID_UE(UENAME, PORTNUM)
                    #result_json = RPC_GNCAR.requestEUID(UENAME)
                if 'ueName' not in result_json :
                        logger.debug( "Response msg:%s", str(result_json))
                raise JSONBadRequest( "Missing '%s' field" %("ueName") )
                if 'ueEuid' not in result_json :
                    logger.debug( "Response msg:%s", str(result_json))
                    raise JSONBadRequest( "Missing '%s' field" %("ueEuid") )
                if 'contentName' not in result_json :
                    logger.debug( "Response msg:%s", str(result_json))
                    raise JSONBadRequest( "Missing '%s' field" %("contentName") )
                if 'contentEuid' not in result_json :
                    logger.debug( "Response msg:%s", str(result_json))
                    raise JSONBadRequest( "Missing '%s' field" %("contentEuid") )
                    
                UENAME = result_json['ueName']
                UEEUID = result_json['ueEuid']
                CONTENTNAME = result_json['contentName']
                CONTENTEUID = result_json['contentEuid']
                
                    #logger.debug( "\n----------Response of RequestEUID Msg, UENAME:%s, EUID:%s ----------" %(UENAME, UEEUID) )
                #logger.debug( "----------Response of RequestEUID Msg, UENAME:%s, EUID:%s ----------" %(UENAME, UEEUID) )
                logger.debug( "----------Response of RequestEUID Msg, UENAME:%s, CONTENTNAME:%s, EUID:%s, PORTNUM:%s ----------" %(UENAME, CONTENTNAME, UEEUID, PORTNUM) )
                
                UE2ENBIP = UEItem(UENAME, self.client_address[1], self.client_address[0], ENBIP, UEEUID)
                FWD_TABLE.UEMap_Add_Item(UE2ENBIP)
                
                UE2EUID  = UE2EUIDItem(UENAME, UEEUID)
                FWD_TABLE.UE2EUIDMap_Add_Item(UE2EUID)
                
                FWD_TABLE.show_fwd_table()
                
                result_data = {}
                result_data[ UE_Request_EUID_Msg_Map["ICN_MSG_TYPE"] ] = "Response_EUID_BOTH"
                result_data[IGW_ICN_Control_Msg_Map["UeName"]] = UENAME
                result_data[IGW_ICN_Control_Msg_Map["UeEuid"]] = UEEUID
                result_data[IGW_ICN_Control_Msg_Map["ContentNameName"]] = CONTENTNAME
                result_data[IGW_ICN_Control_Msg_Map["ContentNameEuid"]] = CONTENTEUID
                
                DataString = json.dumps(result_data)
                ResponseString = b""
                ResponseString += struct.pack("!HHHH",  0x0064, 0x0000, 0x0100, 0x0001)
                ResponseString += DataString               
                self.Send_Response(server_socket, DataString)
                
                RPC_GNCAR.notifyUpdate_BOTH(UENAME, CONTENTNAME, PORTNUM, ENBNA)

        
    def handle_notifySwitching_UE(self, request_json):
        if UE_Request_Switch_Msg_Map["ENBNA"] not in request_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_Switch_Msg_Map["ENBNA"]) )
        
        if UE_Request_Switch_Msg_Map["UPDATE"] not in request_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_Switch_Msg_Map["UPDATE"]) )
        
        UpdateMsgMap_json = request_json[ UE_Request_Switch_Msg_Map["UPDATE"] ]
        
        if UE_Request_Switch_Msg_Map["ENBNA"] not in UpdateMsgMap_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_Switch_Msg_Map["ENBNA"]) ) 
            
        if UE_Request_Switch_Msg_Map["UEEUID"] not in UpdateMsgMap_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_Switch_Msg_Map["UEEUID"]) )  
            
        eNodeBIP = request_json[ UE_Request_Switch_Msg_Map["ENBNA"] ]    
        UEEUID = UpdateMsgMap_json[ UE_Request_Switch_Msg_Map["UEEUID"] ] 
        eNodeBNA = UpdateMsgMap_json[ UE_Request_Switch_Msg_Map["ENBNA"] ] 
        if FWD_TABLE.eNodeBMap[eNodeBIP].PortID == 0:
            PORTNUM = "5IGW-1"
        elif FWD_TABLE.eNodeBMap[eNodeBIP].PortID == 1:
            PORTNUM = "5IGW-2"
        else:
            PORTNUM = ""
        

        global sw_index, sw_time1, swtime2, sw_portid


        if FWD_TABLE.UEMap[FWD_TABLE.UE2EUIDMap[UEEUID]].eNodeBIP != eNodeBIP:
            result_json = RPC_GNCAR.updateMapping_UE(UEEUID, PORTNUM, eNodeBNA)
        
        if "status" not in result_json :
            raise JSONBadRequest( "Missing '%s' field" %("status") )
        
        StatusCode = result_json["status"]
        
        if StatusCode == "ACK" :
            logger.debug( "----------UE Request Switch succeed. New binding is (%s, %s, %s, %s) ----------" %(UEEUID, eNodeBIP, eNodeBNA, PORTNUM) )
            #logger.debug( "\033[1;32;40m ----------UE Request Switch succeed. New binding is (%s, %s, %s) ---------- \033[0m" %(UEEUID, eNodeBIP, eNodeBNA) ) 
            try:
                UENAME = FWD_TABLE.UE2EUIDMap[UEEUID]
                FWD_TABLE.UEMap[UENAME].eNodeBIP = eNodeBIP
            except:
                raise KeyError
        
            FWD_TABLE.show_fwd_table()
        
            #send interest
            InterestPkt = b""
              
              
            if FWD_TABLE.eNodeBMap[eNodeBIP].PortID == 0:
                interest = "fe163e00595390b11c5aa88b09010064000032000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000b6f6365616e332e7769636f"
            else:
                interest = "fe163e00595390b11c5aa88c09010064000032000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000b6f6365616e332e7769636f"
                #interest = "11223344556666554433221109010064000032000000ffffffffffffffffffffffffffffffff000b6f6365616e322e7769636f"
        
            for i in xrange(0, len(interest)/2):
                        value = int(interest[i*2:i*2+2], 16)
                        InterestPkt += struct.pack("!B", value)
            #UENAME = FWD_TABLE.UE2EUIDMap[UEEUID]
            #eNodeBIP = FWD_TABLE.UEMap[UENAME].eNodeBIP
            #PortID = FWD_TABLE.eNodeBMap[eNodeBIP].PortID
            #print("----------------------")
            #print(eNodeBIP)
            #print(FWD_TABLE.eNodeBMap[eNodeBIP].PortID)
            #print("-----------------------")    
            #FWD_ICN.OutputPort[1].send(InterestPkt)
            portid = FWD_TABLE.eNodeBMap[eNodeBIP].PortID
            FWD_ICN.OutputPort[portid].send(InterestPkt)
            sw_index = True
            sw_time1 = time.time()
            sw_portid = portid
            logger.debug( "UE Request Switch and resend interest. New binding is (%s, %s)" %(UEEUID, eNodeBNA) )            

        elif StatusCode == "NACK" :
            logger.error( "UE Request Switch failed. New binding is (%s, %s)"  %(UEEUID, eNodeBNA) )
            
        else :
            logger.error( "undefined status code:%s for Request Switch Msg"    %(StatusCode) )
            
            
    def handle_notifySwitching_CONTENT(self, request_json):
        if UE_Request_Switch_Msg_Map["ENBNA"] not in request_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_Switch_Msg_Map["ENBNA"]) )
        
        if UE_Request_Switch_Msg_Map["UPDATE"] not in request_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_Switch_Msg_Map["UPDATE"]) )
        
        UpdateMsgMap_json = request_json[ UE_Request_Switch_Msg_Map["UPDATE"] ]
        
        if UE_Request_Switch_Msg_Map["ENBNA"] not in UpdateMsgMap_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_Switch_Msg_Map["ENBNA"]) ) 
            
        if UE_Request_Switch_Msg_Map["CONTENTEUID"] not in UpdateMsgMap_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_Switch_Msg_Map["CONTENTEUID"]) )  
            
        eNodeBIP = request_json[ UE_Request_Switch_Msg_Map["ENBNA"] ]    
        CONTENTEUID = UpdateMsgMap_json[ UE_Request_Switch_Msg_Map["CONTENTEUID"] ] 
        eNodeBNA = UpdateMsgMap_json[ UE_Request_Switch_Msg_Map["ENBNA"] ] 
        if FWD_TABLE.eNodeBMap[eNodeBIP].PortID == 0:
            PORTNUM = "5IGW-1"
        elif FWD_TABLE.eNodeBMap[eNodeBIP].PortID == 1:
            PORTNUM = "5IGW-2"
        else:
            PORTNUM = ""
        

        global sw_index, sw_time1, swtime2, sw_portid

        result_json = RPC_GNCAR.updateMapping_CONTENT(CONTENTEUID, PORTNUM, eNodeBNA)
        if "status" not in result_json :
            raise JSONBadRequest( "Missing '%s' field" %("status") )
        
        StatusCode = result_json["status"]
        
        if StatusCode == "ACK" :
            logger.debug( "----------CONTENT Request Switch succeed. New binding is (%s, %s, %s, %s) ----------" %(CONTENTEUID, eNodeBIP, eNodeBNA, PORTNUM) )

            portid = FWD_TABLE.eNodeBMap[eNodeBIP].PortID           

        elif StatusCode == "NACK" :
            logger.error( "CONTENT Request Switch failed. New binding is (%s, %s)"  %(CONTENTEUID, eNodeBNA) )
            
        else :
            logger.error( "undefined status code:%s for Request Switch Msg"    %(StatusCode) )
            
            
    def handle_notifySwitching_BOTH(self, request_json):
        if UE_Request_Switch_Msg_Map["ENBNA"] not in request_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_Switch_Msg_Map["ENBNA"]) )
        
        if UE_Request_Switch_Msg_Map["UPDATE"] not in request_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_Switch_Msg_Map["UPDATE"]) )
        
        UpdateMsgMap_json = request_json[ UE_Request_Switch_Msg_Map["UPDATE"] ]
        
        if UE_Request_Switch_Msg_Map["ENBNA"] not in UpdateMsgMap_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_Switch_Msg_Map["ENBNA"]) ) 
            
        if UE_Request_Switch_Msg_Map["UEEUID"] not in UpdateMsgMap_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_Switch_Msg_Map["UEEUID"]) ) 
        if UE_Request_Switch_Msg_Map["CONTENTEUID"] not in UpdateMsgMap_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_Switch_Msg_Map["CONTENTEUID"]) )   
            
        eNodeBIP = request_json[ UE_Request_Switch_Msg_Map["ENBNA"] ]    
        UEEUID = UpdateMsgMap_json[ UE_Request_Switch_Msg_Map["UEEUID"] ]
        CONTENTEUID = UpdateMsgMap_json[ UE_Request_Switch_Msg_Map["CONTENTEUID"] ]  
        eNodeBNA = UpdateMsgMap_json[ UE_Request_Switch_Msg_Map["ENBNA"] ] 
        if FWD_TABLE.eNodeBMap[eNodeBIP].PortID == 0:
            PORTNUM = "5IGW-1"
        elif FWD_TABLE.eNodeBMap[eNodeBIP].PortID == 1:
            PORTNUM = "5IGW-2"
        else:
            PORTNUM = ""
        

        global sw_index, sw_time1, swtime2, sw_portid
	ENB = FWD_TABLE.CONTENTMap[FWD_TABLE.CONTENT2EUIDMap[CONTENTEUID]].eNodeBIP
        if ENB != eNodeBIP:
	    result_json = RPC_GNCAR.updateMapping_BOTH(UEEUID, CONTENTEUID, PORTNUM, eNodeBNA)
        
        if "status" not in result_json :
            raise JSONBadRequest( "Missing '%s' field" %("status") )
        
        StatusCode = result_json["status"]
        
        if StatusCode == "ACK" :
            logger.debug( "----------UE Request Switch succeed. New binding is (%s, %s, %s, %s, %s) ----------" %(UEEUID, CONTENTEUID, eNodeBIP, eNodeBNA, PORTNUM) )
            #logger.debug( "\033[1;32;40m ----------UE Request Switch succeed. New binding is (%s, %s, %s) ---------- \033[0m" %(UEEUID, eNodeBIP, eNodeBNA) ) 
            try:
                UENAME = FWD_TABLE.UE2EUIDMap[UEEUID]
                CONTENTNAME = FWD_TABLE.CONTENT2EUIDMap[CONTENTEUID]
                FWD_TABLE.UEMap[UENAME].eNodeBIP = eNodeBIP
                FWD_TABLE.CONTENTMap[CONTENTNAME].eNodeBIP = eNodeBIP
            except:
                raise KeyError
        
            FWD_TABLE.show_fwd_table()
        
            #UENAME = FWD_TABLE.UE2EUIDMap[UEEUID]
            #eNodeBIP = FWD_TABLE.UEMap[UENAME].eNodeBIP
            #PortID = FWD_TABLE.eNodeBMap[eNodeBIP].PortID
            #print("----------------------")
            #print(eNodeBIP)
            #print(FWD_TABLE.eNodeBMap[eNodeBIP].PortID)
            #print("-----------------------")    
            #FWD_ICN.OutputPort[1].send(InterestPkt)
            portid = FWD_TABLE.eNodeBMap[eNodeBIP].PortID
            #FWD_ICN.OutputPort[portid].send(InterestPkt)
            sw_index = True
            sw_time1 = time.time()
            sw_portid = portid
            #logger.debug( "Both Request Switch and resend interest. New binding is (%s, %s)" %(UEEUID, eNodeBNA) )            

        elif StatusCode == "NACK" :
            logger.error( "Both Request Switch failed. New binding is (%s, %s)"  %(UEEUID, eNodeBNA) )
            
        else :
            logger.error( "undefined status code:%s for Request Switch Msg"    %(StatusCode) )
            
        
    def handle_notifySwitching(self, request_json):
        if UE_Request_Switch_Msg_Map["ENBNA"] not in request_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_Switch_Msg_Map["ENBNA"]) )
        
        if UE_Request_Switch_Msg_Map["UPDATE"] not in request_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_Switch_Msg_Map["UPDATE"]) )
        
        UpdateMsgMap_json = request_json[ UE_Request_Switch_Msg_Map["UPDATE"] ]
        
        if UE_Request_Switch_Msg_Map["ENBNA"] not in UpdateMsgMap_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_Switch_Msg_Map["ENBNA"]) ) 
            
        if UE_Request_Switch_Msg_Map["EUID"] not in UpdateMsgMap_json:
                raise JSONBadRequest( "Missing '%s' field" %(UE_Request_Switch_Msg_Map["EUID"]) )  
            
        eNodeBIP = request_json[ UE_Request_Switch_Msg_Map["ENBNA"] ]    
        UEEUID = UpdateMsgMap_json[ UE_Request_Switch_Msg_Map["EUID"] ] 
        eNodeBNA = UpdateMsgMap_json[ UE_Request_Switch_Msg_Map["ENBNA"] ] 
        if FWD_TABLE.eNodeBMap[eNodeBIP].PortID == 0:
            PORTNUM = "5IGW-1"
        elif FWD_TABLE.eNodeBMap[eNodeBIP].PortID == 1:
            PORTNUM = "5IGW-2"
        else:
            PORTNUM = ""
        

	global sw_index, sw_time1, swtime2, sw_portid


        if FWD_TABLE.UEMap[FWD_TABLE.UE2EUIDMap[UEEUID]].eNodeBIP != eNodeBIP:
                
          result_json = RPC_GNCAR.updateMapping(UEEUID, PORTNUM, eNodeBNA)
        
          if "status" not in result_json :
              raise JSONBadRequest( "Missing '%s' field" %("status") )
        
          StatusCode = result_json["status"]
        
          if StatusCode == "ACK" :
              logger.debug( "----------UE Request Switch succeed. New binding is (%s, %s, %s, %s) ----------" %(UEEUID, eNodeBIP, eNodeBNA, PORTNUM) )
	      #logger.debug( "\033[1;32;40m ----------UE Request Switch succeed. New binding is (%s, %s, %s) ---------- \033[0m" %(UEEUID, eNodeBIP, eNodeBNA) ) 
              try:
                  UENAME = FWD_TABLE.UE2EUIDMap[UEEUID]
                  FWD_TABLE.UEMap[UENAME].eNodeBIP = eNodeBIP
              except:
                  raise KeyError
        
              FWD_TABLE.show_fwd_table()
	    
              #send interest
              InterestPkt = b""
	      if FWD_TABLE.eNodeBMap[eNodeBIP].PortID == 0:
	      	interest = "fe163e00595390b11c5aa88b09010064000032000000ffffffffffffffffffffffffffffffff000b6f6365616e332e7769636f"
	      else:
		interest = "fe163e00595390b11c5aa88c09010064000032000000ffffffffffffffffffffffffffffffff000b6f6365616e332e7769636f"
              #interest = "11223344556666554433221109010064000032000000ffffffffffffffffffffffffffffffff000b6f6365616e322e7769636f"
        
              for i in xrange(0, len(interest)/2):
                        value = int(interest[i*2:i*2+2], 16)
                        InterestPkt += struct.pack("!B", value)
              #UENAME = FWD_TABLE.UE2EUIDMap[UEEUID]
	      #eNodeBIP = FWD_TABLE.UEMap[UENAME].eNodeBIP
	      #PortID = FWD_TABLE.eNodeBMap[eNodeBIP].PortID
	      #print("----------------------")
	      #print(eNodeBIP)
              #print(FWD_TABLE.eNodeBMap[eNodeBIP].PortID)
 	      #print("-----------------------")	
              #FWD_ICN.OutputPort[1].send(InterestPkt)
	      portid = FWD_TABLE.eNodeBMap[eNodeBIP].PortID
	      #FWD_ICN.OutputPort[FWD_TABLE.eNodeBMap[eNodeBIP].PortID].send(InterestPkt)
	      FWD_ICN.OutputPort[portid].send(InterestPkt)
              sw_index = True
              sw_time1 = time.time()
	      sw_portid = portid
              logger.debug( "UE Request Switch and resend interest. New binding is (%s, %s)" %(UEEUID, eNodeBNA) )            

          elif StatusCode == "NACK" :
              logger.error( "UE Request Switch failed. New binding is (%s, %s)"  %(UEEUID, eNodeBNA) )
            
          else :
              logger.error( "undefined status code:%s for Request Switch Msg"    %(StatusCode) )
        
    
    def handle_requestICNData(self, UDP_string):    
        #UEEUID1 = struct.unpack('!16B', UDP_string[8:24])[0]
        #Payload = request_json[UE_Request_ICNData_Msg_Map["PAYLOAD"]]
        UEEUID1 = UDP_string[8:24]
        UEEUID = binascii.b2a_hex(UEEUID1) 
        print UEEUID
        try:
            UENAME = FWD_TABLE.UE2EUIDMap[UEEUID]
            eNodeBIP = FWD_TABLE.UEMap[UENAME].eNodeBIP
            #record ICN request address info. When ICN data is returned, a UDP packet will be reconstructed.  
            #The destination IP and Port will be changed to recorded address info.
            FWD_TABLE.UEMap[UENAME].UDPort = self.client_address[1]
            FWD_TABLE.UEMap[UENAME].IP = self.client_address[0]
            #ICN request will be forwarded according to the eNodeBIP
            PortID = FWD_TABLE.eNodeBMap[eNodeBIP].PortID
        except:
            traceback.print_exc()
        
        #maintain the content list each UE requests, when a data packet comes back, then we can
        #find which UE has requested it by matching the HRN. This process does too much work and 
        #should be modified to improve performance.
        #ICNData = PKTConstruct.InterestParser(Payload)
        HRN_len = struct.unpack('!H', UDP_string[40:42])[0]
        HRN = struct.unpack('!%us' %(HRN_len), UDP_string[42 : 42 + HRN_len])[0]
        RecordReqItem = UERequestItem(UEEUID, HRN)
        FWD_TABLE.UERequestMap_Add_Item(RecordReqItem)
        
        UDPPkt = b""
        if PortID == 0:
            sMac = "90b11c5aa88b"
        else:
            sMac = "90b11c5aa88c"
        EthHeader = PKTConstruct.EtherHeader( "fe163e005953" ,
                                              sMac ,
                                               PKTConstruct.ICN_MAP["ETH_TYPE"]         )
        UDPPkt += EthHeader.packed()
        #Payload is a hex string representing a InterestPkt payload
        UDPPkt += UDP_string
        #ICNData = json.dumps(request_json)
        FWD_ICN.OutputPort[PortID].send(UDPPkt)
        
    def Send_Response(self, server_socket, response):
        server_socket.sendto(response, self.client_address)

    def handle_reponseData(self, UDP_string):    
        #UEEUID = struct.unpack('!16B', UDP_string[8:24])[0]
        #CONTENTEUID1 = UDP_string[24:40][0]
        #CONTENTEUID = binascii.b2a_hex(CONTENTEUID1) 
	CONTENTEUID = "000220a7ef59c05263e320d8ed366bf8"
        #UEEUID = "000180ea54a717d9803ab19a7f4cce60"     
        #try:
        CONTENTNAME = FWD_TABLE.CONTENT2EUIDMap[CONTENTEUID]
        eNodeBIP = FWD_TABLE.CONTENTMap[CONTENTNAME].eNodeBIP
            #record ICN request address info. When ICN data is returned, a UDP packet will be reconstructed.  
            #The destination IP and Port will be changed to recorded address info.
        FWD_TABLE.CONTENTMap[CONTENTNAME].UDPort = self.client_address[1]
        FWD_TABLE.CONTENTMap[CONTENTNAME].IP = self.client_address[0]
            #ICN request will be forwarded according to the eNodeBIP
        PortI = FWD_TABLE.eNodeBMap[eNodeBIP].PortID
        #except:
            #traceback.print_exc()
        
        
        UDPPkt = b""
        if PortI == 0:
            sMac = "90b11c5aa88b"
        else:
            sMac = "90b11c5aa88c"
        EthHeader = PKTConstruct.EtherHeader( "fe163e005953" ,
                                              sMac ,
                                               PKTConstruct.ICN_MAP["ETH_TYPE"]         )
        UDPPkt += EthHeader.packed()
        #Payload is a hex string representing a InterestPkt payload
        UDPPkt += UDP_string
        #ICNData = json.dumps(request_json)
        q.put(UDPPkt)
        #FWD_ICN.OutputPort[PortID].send(UDPPkt)
               

class IGWUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    
class IGW2UEAPP:
    def __init__(self, server_address):
        global q 
        q = Queue()
        self.server = IGWUDPServer(server_address, IGWUDPHandle)
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.setDaemon(True)
        self.server_thread.start()
        
        self.send_data = SendPacket2ICN('SendPacket' , q)
        self.send_data.setDaemon(True)
        self.send_data.start()
        
def instantiate_IGWUPDServer( Server_Address ):
    global UDPServer
    try:
        UDPServer = IGW2UEAPP( Server_Address )
    except:
        raise Exception("UDPServer build failed!")
    return
    
