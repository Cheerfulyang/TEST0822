import socket
port=8081
import json

eth_name = "em2"

def bind_socket(eth_name):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    try:
        sock.bind( (eth_name, 5000) )
    except:
        raise Exception("create connection to ICN network failed")
    return sock


if __name__ == "__main__" :
    send_socket = bind_socket(eth_name)

    s=socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.bind((eth_name, 0))
    print('begin to receive')
    while True:
        data,addr=s.recvfrom(1024)
        if addr[2] != socket.PACKET_OUTGOING:
            ICNData_string = str(data)
            try:
                    ICNData_json = json.loads(ICNData_string)
            except:
                    handle_go_on = False
            else :
                    handle_go_on = True
            if handle_go_on :
                print ICNData_string
                srcEUID = ICNData_json['EuidSrc']
                dstEUID = ICNData_json['EuidDst']
                payload = ICNData_json['Payload']
                IcnMsgType = ICNData_json['IcnMsgType']
                 
                DataContent = {"EuidSrc":dstEUID, "EuidDst":srcEUID, "Payload":payload, "IcnMsgType":IcnMsgType}
                DataString = json.dumps(DataContent)
                
                send_socket.sendall(DataString)   
            
