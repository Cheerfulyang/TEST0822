from src import IGW2GNCAR, IGW2UEAPP

def test_for_request_euid():
    IGW = IGW2GNCAR('192.168.101.10', 1234)
    print IGW.requestEUID("/Mobile/13600001111")
    
def test_for_udpserver():
    server_address = ("192.168.100.121", 1234)
    IGW = IGW2UEAPP(server_address)

if __name__ == "__main__" :
    print "start udp server"
    test_for_udpserver()