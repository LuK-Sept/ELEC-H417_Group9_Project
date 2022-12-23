






import random
import socket
import threading
import time

from pinger import Pinger


from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from cryptography.fernet import Fernet


from pinger import Pinger
from packet import *
from connection import NodeConnection, get_ACK
    


class Client(threading.Thread):
    def __init__(self,host="",port=5000,verbose=False):
        threading.Thread.__init__(self)
        self.host = host
        self.port = port
        self.verbose = verbose
        #self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.nodes_connected = []
        self.peers = []
        self.pinger = Pinger(self)
        self.terminate_flag = threading.Event()
        self.dead_time = (
            120  # time to disconect from node if not pinged, nodes ping after 20s
        )
        self.try_to_connect = set()
        self.pr_key = private_key = RSA.generate(1024)
        self.pub_key = self.pr_key.publickey()
        self.key = Fernet.generate_key()
        

        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if self.verbose:
            print("Initialisation of the Node on port: " + str(self.port))
        self.sock.bind((self.host, self.port))

        self.sock.settimeout(10)
        self.sock.listen(5)

        # print("Host : ",self.host,"Key : ",self.key)

    def stop(self):
        self.terminate_flag.set()

    def run(self):
        self.pinger.start()
        while (not self.terminate_flag.is_set()):

            if self.verbose:
                print("[" +self.host +"] LIST OF PEERS ",self.peers)
            try:
                connection, client_address = self.sock.accept()
                
                connected_node_id = connection.recv(4096).decode("utf-8") #routine très importante d'échange de clées (ici en reception)
                connection.send(self.host.encode("utf-8"))

                pub_key = connection.recv(4096)
                pub_key = RSA.import_key(pub_key)

                cipher = PKCS1_OAEP.new(pub_key)
                data = cipher.encrypt(self.key)


                connection.send(data)
                other_key = connection.recv(4096)
                f = Fernet(self.key)
                other_key = f.decrypt(other_key)


                #print("debug",end=" ")
                #print(self.host,connected_node_id)
                if self.host != connected_node_id:
                    thread_client = self.create_new_connection(
                        connection,
                        connected_node_id,
                        connected_node_id,
                        client_address[1],
                        other_key
                    )
                    
                    

                else:
                    connection.close()

            except socket.timeout:
                if len(self.try_to_connect) > 0:
                    try:
                        for node in self.nodes_connected:
                            if node.host in self.try_to_connect:
                                self.try_to_connect.remove(node.host)

                        while len(self.try_to_connect) > 0:
                            peer = self.try_to_connect.pop()
                            self.connect_to(peer,5000)
                    except:
                        if self.verbose:
                            print('\033[93m' + "Cannot connect to peer"+ '\033[0m')
                        pass

            except Exception as e:
                raise e

            time.sleep(0.01)

        self.pinger.stop()
        for t in self.nodes_connected:
            t.stop()

        self.sock.close()
        if self.verbose:
            print("Node stopped")


    def connect_to(self, host, port=5000):

        for node in self.nodes_connected:
            if node.host == host:
                #print("[connect_to]: Already connected with this node.")
                return True

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.verbose:
                print("connecting to %s port %s" % (host, port))
            sock.connect((host, port))

            sock.send(self.host.encode("utf-8"))				#routine très importante d'échange de clées (ici en envoie)
            connected_node_id = sock.recv(1024).decode("utf-8")

            sock.send(self.pub_key.exportKey("PEM"))
            cipher_key = sock.recv(4096)
            cipher = PKCS1_OAEP.new(self.pr_key)
            key = cipher.decrypt(cipher_key)
            f = Fernet(key)
            my_key = f.encrypt(self.key)
            sock.send(my_key)




            if self.host == connected_node_id:
                if self.verbose:
                    print("Possible own ip: " + host)
                self.banned.append(host)
                sock.close()
                return False

            thread_client = self.create_new_connection(
                sock, connected_node_id, host, port,key
            )
            


        except Exception as e:
            if self.verbose:
                print(
                    "connect_to: Could not connect with node. (" + str(e) + ")"
                )



    def create_new_connection(self, sock, connected_node_id, host, port,key=""):
        thread_client = NodeConnection(self, sock, connected_node_id, host, port,key)
        thread_client.start()
        self.nodes_connected.append(thread_client)
        self.node_connected(thread_client)
        self.peers.append([connected_node_id,key])
       

        
        

    def node_connected(self, node):
        if self.verbose:
            print("node_connected: " + node.id)
        return True
        if node.host not in self.peers:
            self.peers.append([node.host,""])
        #self.send_peers()
        

    def node_disconnected(self, node):
        if self.verbose:
            print("node_disconnected: " + node.host)
        if node.host in self.peers:
            self.peers.remove(node.host)

    def send_message(self, data, reciever):
        for i in self.nodes_connected:
            if i.host == reciever:
                i.send("MSG",data)
    
    def send_tor(self, data, reciever):
        data = bytes(data,"utf-8")
        
        peers = self.peers.copy()
        path = []
        for node in peers:
            if node[0] == reciever:
                receiver = node
                peers.remove(node)
        for j in range(3):
            path.append(peers.pop(random.randint(0,len(peers)-1)))
        path.append(receiver)
        
        data = packet_builder("MSG",path[len(path)-2][0],path[len(path)-1][0],data).bytes
        
        
        packet = tor_builder(self.host,path,data)
        for i in self.nodes_connected:
            if i.host == path[0][0]:
                i.send("TOR",packet)

    def request_http(self, target):
            
        data = bytes(target,"utf-8")
        
        peers = self.peers.copy()
        path = []
        for j in range(3):
            path.append(peers.pop(random.randint(0,len(peers)-1)))
        
        
        data = packet_builder("HTTP",path[len(path)-2][0],path[len(path)-1][0],data).bytes
        
        
        packet = tor_builder(self.host,path,data)
        for i in self.nodes_connected:
            if i.host == path[0][0]:

                
                i.send("TOR",packet)
                
                try:
                    
                    ans = get_ACK(self.host)
                    if ans == b'':
                        raise Exception("No answer")
                    packet = packet_debuilder(ans)
                    f = Fernet(path[0][1])
                    html = f.decrypt(packet["data"].bytes)
                    f = Fernet(path[1][1])
                    html = f.decrypt(html)
                    f = Fernet(path[2][1])
                    html = f.decrypt(html)
                    html = html.decode("utf-8")
                    return html
                except Exception as e:
                    print(e)
                    print("Error in request_http")
                    raise e 

