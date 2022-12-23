





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
        # Variable for parsing the incoming json messages
        self.buffer = ""

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
        self.terminate_flag.set()

    def run(self):
        self.sock.settimeout(20.0)

        while not self.terminate_flag.is_set():
            if time.time() - self.last_ping > self.main_node.dead_time:
                self.terminate_flag.set()
                if self.main_node.verbose:
                    print("node" + self.id + "is dead")
                    for peer in self.main_node.peers:
                        if peer[0] == self.id:
                            self.main_node.peers.remove(peer)
                            break

            line = ""

            try:
                line = self.sock.recv(4096)

            except socket.timeout:
            
                pass

            except Exception as e:
                self.terminate_flag.set()
                if self.main_node.verbose:
                    print(
                        "NodeConnection: Socket has been terminated (%s)" % line
                    )
                    print(e)

            if line != b'':
                
                if not is_valide_packet(line):
                    continue
                self.last_ping = time.time()
                # if self.main_node.verbose:
                #     print("[" +self.main_node.host,end="] ")
                



                try:
                   
                    
                    packet = packet_debuilder(line)

                except Exception as e:
                        
                    print("error decrypting ")
                    print(e)
                    continue
                
                
                if packet["Type"] == "PING":
                    
                    # if self.main_node.verbose:
                        
                    #     print("PING from " + packet["ip_source"] )
                    try:
                        peers = bnr_to_peers(packet["data"])
                        # for peer in peers:
                        #     print("[" +self.main_node.host +"] "+"NEW PEERS INCOMING",peer[0])

                        self.find_new_peers(peers)
                    except:
                        pass

                    
                if packet["Type"] == "MSG":
                    print(self.main_node.host+" MSG from " + packet["ip_source"] + " : " + packet["data"])
                
                if packet["Type"] == "TOR":
                    print("TOR RECEIVED BY : ",self.main_node.host)
                    print("ttl : ",packet["ttl"])


                    data = packet["data"]
                    f = Fernet(self.main_node.key)
                    
                    data = f.decrypt(packet["data"].bytes)
                    if packet["ttl"] > 0:

                        onion =  packet_debuilder(data)
                        destination_ip = onion["ip_destination"]

                        for node in self.main_node.nodes_connected:
                            if node.host == destination_ip:
                                node.send("TOR",data)
                                

                                raw = get_ACK(self.main_node.host)
                                if raw == b'':
                                    continue
                                ans = packet_debuilder(raw)
                                if ans == b'':
                                    continue
                                
                                if ans["Type"] == "ACK":
                                    print("ACK RECEIVED BY : ",self.main_node.host)
                                    
                                    
                                    answer = create_cipher_packet("ACK",self.main_node.host,packet["ip_source"],ans["data"].bytes,self.main_node.key)
                                    # print("SENDING ANSWER TO : ",packet["ip_source"])
                                    # print("USING KEY : ",self.main_node.key)


                                    send_ACK( packet["ip_source"],(answer.bytes))
                                    
                                
                    else:
                        onion =  packet_debuilder(data)
                        if onion["Type"] == "HTTP":
                            x = requests.get(onion["data"])

                            # print(x.text)
                            
                            
                            answer = create_cipher_packet("ACK",self.main_node.host,onion["ip_source"],x.text.encode("utf-8"),self.main_node.key)
                            if answer == b'':
                                continue
                            # print("SENDING ANSWER TO : ",onion["ip_source"])
                            # print("IP OF MY NODE : ",self.host)
                            # print("USING KEY : ",self.main_node.key)
                            

                            
                            send_ACK( onion["ip_source"],(answer.bytes))
                            
                            
                            continue


                        for node in self.main_node.nodes_connected:
                            if node.host == onion["ip_destination"]:
                                # print("MA DATA : ",type(onion["data"]))
                                node.send(onion["Type"],data)
                                
                        
                    
                self.last_ping = time.time()

            time.sleep(0.05)

        self.main_node.node_disconnected(self)
        self.sock.settimeout(None)
        self.sock.close()
        del self.main_node.nodes_connected[self.main_node.nodes_connected.index(self)]
        time.sleep(1)

    def send(self,Type,data="NONE"):
        data = data 
        # self.sock.sendall(data.encode("utf-8"))
        if type(data) == bytes:
                self.sock.sendall(data)
        else:
            if Type == "TOR":
                self.sock.sendall(data.bytes)
                
            else:
                self.sock.sendall(packet_builder(Type,self.main_node.host,self.host,data).bytes)
        

    def find_new_peers(self,peers):
        new_peers = []
        for peer in peers:
            for node in self.main_node.nodes_connected:
                if peer == node.host:
                    break
                if peer == self.main_node.host:
                    break
                if len(self.main_node.try_to_connect) >= 10:
                    break
                self.main_node.try_to_connect.add(peer)

        
                #self.main_node.peers.append(peer)
        

        # self.last_ping = time.time()# to compensate the time to connect to new peers
    