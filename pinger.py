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
        self.terminate_flag.set()

    
    def run(self):
        if self.parent.verbose:
            print("Pinger Started")
        while (not self.terminate_flag.is_set()):  
            for i in self.parent.nodes_connected:
                data = peers_to_bnr(self.parent.peers)
                #print(data)
                i.send("PING",data)
            time.sleep(10)
        if self.parent.verbose:
            print("Pinger stopped")
