import threading
import time
from packet import peers_to_bnr


class Pinger(threading.Thread):
    def __init__(self, parent):
        self.terminate_flag = threading.Event()
        super(Pinger, self).__init__()  


        
        self.parent = parent
        self.dead_time = 120 

    def stop(self):
        #stop the thread
        self.terminate_flag.set()

    
    def run(self):
        if self.parent.verbose:
            print("Pinger Started")

        while (not self.terminate_flag.is_set()):  
            for i in self.parent.nodes_connected:       #ping all connected nodes
                data = peers_to_bnr(self.parent.peers)  #send the list of peers
                #print(data)
                i.send("PING",data)                     #send the ping
            time.sleep(10)                              #wait 10 seconds before pinging again               
        if self.parent.verbose:
            print("Pinger stopped")
