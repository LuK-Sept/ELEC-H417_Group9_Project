
import socket
import threading

from bitstring import BitArray
from packet import str_to_bin






class Challenge(threading.Thread):
    """
    Thread that listen for a challenge and answer it
    """
    def __init__(self,host,password,port=6000,verbose=False):
        threading.Thread.__init__(self)
        self.host = host
        self.port = port
        self.password = password
        
        
        self.terminate_flag = threading.Event()
        
        
        

        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #initialize the socket
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        

        self.sock.bind((self.host, self.port))


        self.sock.settimeout(10)
        self.sock.listen(5)

       

    def stop(self):
        self.terminate_flag.set()

    def run(self):
        
        while (not self.terminate_flag.is_set()):

            try:
                connection, _ = self.sock.accept()
                
                packet = connection.recv(4096)  #receive the challenge and the hash
                
                


                chal = packet[:2]               #split the packet
                
                chal = BitArray(chal)
                cypher = packet[2:]
                cypher = BitArray(cypher)
                

                if abs(hash(str_to_bin(self.password) + chal.bin)) == cypher.uint:  #check if the hash is correct
                    ans = "\033[92m access granted \033[0m" 
                else:
                    ans = "\033[91m access denied  \033[0m"

                connection.send(ans.encode("utf-8"))    #send the answer
                connection.close()

            except socket.timeout:
                pass




