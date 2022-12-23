from bitstring import BitArray, BitStream
import random

from cryptography.fernet import Fernet




#dictionary to convert type to binary
type_to_bnr = { "PING":BitArray("0b0000"),
                "MSG":BitArray("0b0001"),
                "KEY":BitArray("0b0010"),
                "TOR":BitArray("0b0011"),
                "HTTP":BitArray("0b0100"),
                "ACK":BitArray("0b0101"),
                "CHAL":BitArray("0b0110")}
                


def bnr_to_type(Type):
    """convert binary to type"""
    key_list = list(type_to_bnr.keys())
    val_list = list(type_to_bnr.values())
    try:
        p = val_list.index(Type)
        Type = key_list[p]
    except Exception as e:
        raise e
    return Type


def peers_to_bnr(peers):
    """convert list of peers to binary"""
    data = BitArray()
    random.shuffle(peers) #bring some randomness because why not after all it's a P2P network. Mayber it will faster a litlle bit the connection
    for client in peers:
        data += ip_to_BitArray( client[0] )
    return data

def bnr_to_peers(data):
    """convert binary to list of peers"""
    peers = []
    data = BitStream(data)
    
    while data.pos < data.len:
        ip = BitArray(data.read(32))
        peers.append((BitArray_to_ip(ip)))
        
    return peers
                

def ip_to_BitArray(ip):
    """convert ip to binary"""
    ip = ip.split(".")
    new = BitArray()
    for i in ip:
        i = int(i)
        new += BitArray(uint=i,length=8)
    return new

def BitArray_to_ip(ip):
    """convert ip from binary to string"""
    ip = BitStream(ip)
    string = ""
    for i in range(0,32,8):
        string += str(ip.read(8).int) + "."
    return string[:-1]



def str_to_bin(data):
    """convert string to binary on 8 bits each char"""
    return "".join(["{0:08b}".format(ord(i)) for i in data])

def bin_to_str(data):
    """convert binary to string"""
    return "".join([chr(int(data[i:i+8],2)) for i in range(0,len(data),8)])

def compute_checksum(header):
    """compute checksum of packet"""
    return BitArray(int=hash(header.bin),length=100)[-17:-1]

def packet_builder(Type,ip_source,ip_destination,data,ttl=255):
    """Create bitarray packet from data"""
    Type = type_to_bnr[Type]
    ip_source = ip_to_BitArray(ip_source)
    ip_destination = ip_to_BitArray(ip_destination)
    ttl = BitArray(uint=ttl,length=8)
    

    
    if type(data) == str:
        data =BitArray( "0b"+str_to_bin(data))
    if type(data) == bytes:
        data = BitArray(bytes=data)
    
    total_length = len(Type)+len(ip_source)+len(ip_destination)+len(ttl)+len(data) + 16 +16+8 #add 16 bits for length of checksum and padding
    padding = BitArray(uint=total_length%8,length=8)    #padding to make total length a multiple of 8


    if total_length%8 != 0:
        data += BitArray(uint=0,length=total_length%8)
        total_length += total_length%8                  #add padding to total length
    
    try:#sometimes problem with data length
        header = Type+BitArray(uint=total_length,length=16)+ttl+padding+ip_source+ip_destination
    except Exception as e:
        print("error in packet_builder :",e)
        return b''
    checksum = compute_checksum(header)
    header += checksum

    packet = header + data
    return packet

def packet_debuilder(packet):
    """return a dict with all info of packet"""
    packet = BitArray( packet)
    Type = packet[0:4]
    total_length = packet[4:20]
    ttl = packet[20:28]
    padding = packet[28:36]
    ip_source = packet[36:68]
    
    ip_destination = packet[68:100]
    
    checksum = packet[100:116]
    data = packet[116:]
    if padding.uint != 0:
        data = data[:-padding.uint]
    if Type == type_to_bnr["MSG"] or Type == type_to_bnr["HTTP"]:
        data = bin_to_str(data.bin)

    header = Type+total_length+ttl+padding+ip_source+ip_destination
    ip_source = BitArray_to_ip(ip_source)
    ip_destination = BitArray_to_ip(ip_destination)


    Type = bnr_to_type(Type)


    return {"Type":Type,
            "total_length": total_length.uint,
            "ttl":ttl.uint,
            "padding":padding.uint,
            "ip_source":ip_source,
            "ip_destination":ip_destination,
            "checksum":checksum,
            "data":data,
            "header":header}



def tor_builder(ip_source,path,data,ttl=255):
    """
    Build a packet for TOR network
    path of size 3  
    source -> entry point -> relay -> exit point -> destination
    """
    key = path[2][1]
    f = Fernet(key)
    data = f.encrypt(data)
    data = packet_builder("TOR",path[1][0],path[2][0],data,ttl=0)

    key = path[1][1]
    f = Fernet(key)
    data = f.encrypt(data.bytes)
    data = packet_builder("TOR",path[0][0],path[1][0],data,ttl=1)

    key = path[0][1]
    f = Fernet(key)
    data = f.encrypt(data.bytes)
    data = packet_builder("TOR",ip_source,path[0][0],data,ttl=2)



    return data

def tor_debuilder(packet,path,ans):
    """
    debuilder for tor packet
    """
    packet = packet_debuilder(ans)
        
    f = Fernet(path[0][1])
    data = f.decrypt(packet["data"].bytes)
    f = Fernet(path[1][1])
    data = f.decrypt(data)
    f = Fernet(path[2][1])
    data = f.decrypt(data)
        
    data = data.decode("utf-8")
    return data
    

def is_valide_packet(packet):
    """check if packet is valide"""
    try:
        packet = BitArray(packet)
        if len(packet) < 116:
            return False
        return True
    except:
        return False







def create_cipher_packet(Type,ip_source,ip_destination,data,key,ttl=255):
    """create a packet with data encrypted with key"""

    f = Fernet(key)
    if type(data) == str:
        data = f.encrypt(data.encode("utf-8"))
    elif type(data) != bytes:
        data = f.encrypt(data.bytes)
    else:
        data = f.encrypt(data)
    data = packet_builder(Type,ip_source,ip_destination,data,ttl)
    return data









