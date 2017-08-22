import logging

logger = logging.getLogger('fwd_table') 

class UEItem :
    def __init__(self, UEName, UDPort, IP, eNodeBIP, EUID):
        self.UEName = UEName
        self.UDPort = UDPort
        self.IP = IP
        self.eNodeBIP = eNodeBIP
        self.EUID = EUID
        
class CONTENTItem :
    def __init__(self, CONTENTName, UDPort, IP, eNodeBIP, EUID):
        self.CONTENTName = CONTENTName
        self.UDPort = UDPort
        self.IP = IP
        self.eNodeBIP = eNodeBIP
        self.EUID = EUID
            
class eNodeBItem :
    def __init__(self, eNodeBIP, SwitchID, ControllerID, PortID):
        self.eNodeBIP = eNodeBIP
        self.SwitchID = SwitchID
        self.ControllerID = ControllerID
        self.PortID = PortID

class UE2EUIDItem :
    def __init__(self, UEName, EUID):
        self.UEName = UEName
        self.EUID = EUID

class CONTENT2EUIDItem :
    def __init__(self, CONTENTName, EUID):
        self.CONTENTName = CONTENTName
        self.EUID = EUID
        
class UERequestItem :
    def __init__(self, EUID, HRName):
        self.EUID = EUID
        self.HRName = HRName
        
class CONTENTRequestItem :
    def __init__(self, EUID, HRName):
        self.EUID = EUID
        self.HRName = HRName

class ForwardTable :
    def __init__(self, UEMap={}, CONTENTMap={}, eNodeBMap={}, UE2EUIDMap={}, CONTENT2EUIDMap={}):
        self.UEMap = UEMap                # {"UEName"   :    UEItem}
	self.CONTENTMap = CONTENTMap
        self.UE2EUIDMap = UE2EUIDMap      # {"EUID"     :    UEName}
        self.CONTENT2EUIDMap = CONTENT2EUIDMap   # {"EUID"     :    CONTENTName}
        self.eNodeBMap = eNodeBMap        # {"eNodeBIP" :    eNodeBItem}
        self.UERequestMap = {}            # {"HRName"   :    [EUID1, EUID2, ...]}
        self.CONTENTRequestMap = {}       # {"HRName"   :    [EUID1, EUID2, ...]}
        
    def UEMap_Add_Item(self, Item):
        if not isinstance(Item, UEItem) :
            raise Exception("Inserted Item is not UEItem Type")
        
        if Item.UEName not in self.UEMap :
            self.UEMap[Item.UEName] = Item
            if Item.EUID is not None:
                self.UE2EUIDMap[Item.EUID] = Item.UEName
        else :
            logger.debug("UEItem is already existed")
            
    def CONTENTMap_Add_Item(self, Item):
        if not isinstance(Item, CONTENTItem) :
            raise Exception("Inserted Item is not CONTENTItem Type")
        
        if Item.CONTENTName not in self.CONTENTMap :
            self.CONTENTMap[Item.CONTENTName] = Item
            if Item.EUID is not None:
                self.CONTENT2EUIDMap[Item.EUID] = Item.CONTENTName
        else :
            logger.debug("CONTENTItem is already existed")

    def UE2EUIDMap_Add_Item(self, Item):
        if not isinstance(Item, UE2EUIDItem) :
            raise Exception("Inserted Item is not UE2EUIDItem Type")        
        
        if Item.EUID not in self.UE2EUIDMap :
            self.UE2EUIDMap[Item.EUID] = Item.UEName
            
        else :
            logger.debug("UE2EUIDItem is already existed")
    def CONTENT2EUIDMap_Add_Item(self, Item):
        if not isinstance(Item, CONTENT2EUIDItem) :
            raise Exception("Inserted Item is not CONTENT2EUIDItem Type")        
        
        if Item.EUID not in self.CONTENT2EUIDMap :
            self.CONTENT2EUIDMap[Item.EUID] = Item.CONTENTName
            
        else :
            logger.debug("CONTENT2EUIDItem is already existed")
            
    def eNodeBMap_Add_Item(self, Item):
        if not isinstance(Item, eNodeBItem) :
            raise Exception("Inserted Item is not eNodeBItem Type")    
        
        if Item.eNodeBIP not in self.eNodeBMap :
            self.eNodeBMap[Item.eNodeBIP] = Item
        else :
            logger.debug("eNodeBItem is already existed")
            
    def UERequestMap_Add_Item(self, Item):
        if not isinstance(Item, UERequestItem) :
            raise Exception("Inserted Item is not UERequest Type") 
        
        EUIDList = []  
        if Item.HRName not in self.UERequestMap :
            EUIDList.append(Item.EUID)
            self.UERequestMap[Item.HRName] = EUIDList
        else :
            EUIDList = self.UERequestMap[Item.HRName]
            if Item.EUID not in EUIDList :
                EUIDList.append(Item.EUID)
        
        for euid in EUIDList :     
            logger.debug( "Data:%s, is requested by EUID:%s . " %(Item.HRName, euid) )
            
    def CONTENTRequestMap_Add_Item(self, Item):
        if not isinstance(Item, CONTENTRequestItem) :
            raise Exception("Inserted Item is not CONTENTRequest Type") 
        
        EUIDList = []  
        if Item.HRName not in self.CONTENTRequestMap :
            EUIDList.append(Item.EUID)
            self.CONTENTRequestMap[Item.HRName] = EUIDList
        else :
            EUIDList = self.CONTENTRequestMap[Item.HRName]
            if Item.EUID not in EUIDList :
                EUIDList.append(Item.EUID)
        
        for euid in EUIDList :     
            logger.debug( "Data:%s, is requested from EUID:%s . " %(Item.HRName, euid) )
            
    def show_fwd_table(self):
        if len(self.UEMap) > 0 :
            for key in self.UEMap :
                logger.info( "UENAME Map: %s <<<--->>> %u %s %s %s" %(key, self.UEMap[key].UDPort, self.UEMap[key].IP,   \
                                                                     self.UEMap[key].eNodeBIP, self.UEMap[key].EUID) )
        if len(self.UE2EUIDMap) > 0 :
            for key in self.UE2EUIDMap :
                logger.info( "UEEUID Map: %s <<<--->>> %s" %(key, self.UE2EUIDMap[key]) )
        
