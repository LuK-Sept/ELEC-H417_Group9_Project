import socket
import threading
import time

import requests
from packet import bnr_to_peers, create_cipher_packet, is_valide_packet, packet_builder, packet_debuilder
from cryptography.fernet import Fernet

def send_ACK(host,data):
    HOST = host  # The server's hostname or IP address
    PORT = 5555  # The port used by the server

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
                                        
        s.send(data)

def get_ACK(host):
    HOST = host  # Standard loopback interface address (localhost)
    PORT = 5555  # Port to listen on (non-privileged ports are > 1023)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        s.settimeout(10)
        try:
            conn, addr = s.accept()
        except socket.timeout:
            return b''
        with conn:
                                            
            data = b''
            while data == b'':
                data = conn.recv(4096)
        
        return data


class NodeConnection(threading.Thread):
    def __init__(self, main_node, sock, id, host, port, key=""):

        super(NodeConnection, self).__init__()

        self.host = host
        self.port = port
        self.main_node = main_node
        self.sock = sock
        self.terminate_flag = threading.Event()
        self.last_ping = time.time()
        
        

        # The id of the connected node
        self.key = key
        self.id = id

        if self.main_node.verbose:
            print(
                "NodeConnection.send: Started with client ("
                + self.id
                + ") '"
                + self.host
                + ":"
                + str(self.port)
                + "'"
            )
        


    def stop(self):
        #stop the thread
        self.terminate_flag.set()

    def run(self):
        self.sock.settimeout(20.0)

        while not self.terminate_flag.is_set():
            if time.time() - self.last_ping > self.main_node.dead_time: # if the node is dead
                self.terminate_flag.set()
                if self.main_node.verbose:
                    print("node" + self.id + "is dead")
                for peer in self.main_node.peers:
                    if peer[0] == self.id:
                        self.main_node.peers.remove(peer)
                        break

            line = ""

            try:
                line = self.sock.recv(4096) #wait for a packet

            except socket.timeout:
            
                pass

            except Exception as e:
                self.terminate_flag.set()
                if self.main_node.verbose:
                    print(
                        "NodeConnection: Socket has been terminated (%s)" % line
                    )
                    print(e)

            if line != b'': #if we have a packet
                
                if not is_valide_packet(line):  # if the packet as a valid size 
                    continue
                self.last_ping = time.time()    #update the last ping time
                
                



                try:
                   
                    
                    packet = packet_debuilder(line)

                except Exception as e:
                        
                    print("error decrypting ")
                    print(e)
                    continue
                
                
                if packet["Type"] == "PING":    #if the packet is a ping
                    
                    try:
                        peers = bnr_to_peers(packet["data"])    #get the peers from the packet
                        
                        self.find_new_peers(peers)              #add the new peers to the list of discovered peers
                    except:
                        pass

                    
                if packet["Type"] == "MSG":                     #if the packet is a message
                    print(self.main_node.host+" MSG from " + packet["ip_source"] + " : " + packet["data"])
                                                                #print the message
                
                if packet["Type"] == "TOR":                     #if the packet is a TOR packet
                    print("TOR RECEIVED BY : ",self.main_node.host)
                    print("ttl : ",packet["ttl"])


                    data = packet["data"]
                    f = Fernet(self.main_node.key)              
                    
                    data = f.decrypt(packet["data"].bytes)      #decrypt the packet
                    if packet["ttl"] > 0:                       #check if i am the exit point of the TOR

                        onion =  packet_debuilder(data)
                        destination_ip = onion["ip_destination"]

                        for node in self.main_node.nodes_connected:
                            if node.host == destination_ip:
                                node.send("TOR",data)           #send the packet to the next node
                                

                                raw = get_ACK(self.main_node.host)  #wait for an answer if there is one
                                if raw == b'':
                                    continue
                                ans = packet_debuilder(raw)         #decrypt the answer
                                if ans == b'':
                                    continue
                                
                                if ans["Type"] == "ACK":            #if the answer is an ACK
                                    print("ACK RECEIVED BY : ",self.main_node.host)
                                    
                                    
                                    answer = create_cipher_packet("ACK",self.main_node.host,packet["ip_source"],ans["data"].bytes,self.main_node.key)
                                                                    #create the ACK packet encrypted with the key of the node


                                    send_ACK( packet["ip_source"],(answer.bytes))   #send the ACK packet
                                    
                                
                    else:                                #if i am the exit point
                        onion =  packet_debuilder(data)
                        if onion["Type"] == "HTTP":      #if the packet is a HTTP request
                            x = requests.get(onion["data"]) #send the request

                            
                            
                            
                            answer = create_cipher_packet("ACK",self.main_node.host,onion["ip_source"],x.text.encode("utf-8"),self.main_node.key)
                            #create the ACK packet encrypted with the key of the node containing the answer
                            if answer == b'':
                                continue
                            
                            

                            
                            send_ACK( onion["ip_source"],(answer.bytes))
                            #send the ACK packet
                            
                            continue
                        elif onion["Type"] == "CHAL":   #if the packet is a challenge

                            #create a socket and connect to the challenge server
                            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                            s.connect(("127.0.1.1",6000))
                            s.send(onion["data"].bytes) #send the challenge 
                            challenge = s.recv(4096)
                            #get the answer from the challenge server
                            s.close()
                            answer = create_cipher_packet("ACK",self.main_node.host,onion["ip_source"],challenge,self.main_node.key)

                            send_ACK( onion["ip_source"],(answer.bytes))
                            #send the ACK packet containing the answer
                            continue
                            

                        for node in self.main_node.nodes_connected: #send the packet to the next node if not of that type just send it
                            if node.host == onion["ip_destination"]:
                                
                                node.send(onion["Type"],data)
                                
                        
                    
                self.last_ping = time.time()

            time.sleep(0.05)

        self.main_node.node_disconnected(self)
        self.sock.settimeout(None)
        self.sock.close()
        del self.main_node.nodes_connected[self.main_node.nodes_connected.index(self)]
        time.sleep(1)

    def send(self,Type,data="NONE"):
       
        
        if type(data) == bytes: #if the data is already a bytes object
                self.sock.sendall(data)
        else:
            if Type == "TOR":   #if the packet is a TOR packet
                self.sock.sendall(data.bytes)   #send the packet
                
            else:            #if the packet is not a TOR packet create the packet and send it
                self.sock.sendall(packet_builder(Type,self.main_node.host,self.host,data).bytes)
        

    def find_new_peers(self,peers):

        new_peers = []
        for peer in peers: #peers is the list of peers received from the ping packet
            for node in self.main_node.nodes_connected:
                if peer == node.host:   #if the peer is already connected
                    break
                if peer == self.main_node.host:     #if the peer is the current node
                    break
                if len(self.main_node.try_to_connect) >= 10:    #if the list of peers to connect is full
                    break
                self.main_node.try_to_connect.add(peer)       #else add the peer to the list of peers to connect

    