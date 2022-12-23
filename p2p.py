import time
from challenge import Challenge
from packet import *
from client import Client



def waiting_for_connextion(nodes):
    end = False
    n = len(nodes)
    while(not end):
        end = True
        connexion = 0
        
        for node in nodes:
            connexion += len(node.nodes_connected)
        if connexion/2 < sum(n-1): 
            end = False
                
        print("waiting for all nodes to connect... " +str(int(connexion/2))+"/"+str(sum((n-1))),end ='\r')
        
    print()
    print('\033[93m'+"All nodes connected"+ '\033[0m')


def start_nodes(n):


    if n > 10:
        print("n>10 -> Proceding to a safe start of the nodes")
    nodes = []
    start = time.time()
    nodes.append(Client("127.0.0.1",5000,verbose=False))
    nodes[0].start()

    end = False
    print("Starting nodes...",end='\r')
    for i in range(2,n+1):
        nodes.append(Client("127.0.0."+str(i),5000))
        nodes[i-1].start()
        time.sleep(1) # make sure the thread is fully started
        # print("Start node number : ",i,end='\r')
        nodes[i-1].connect_to("127.0.0."+str(i-1),5000)

        if n > 10:#creation control
            end = False
            while(not end):
                end = True
                connexion = 0
                
                for node in nodes:
                    connexion += len(node.nodes_connected)
                if connexion/2 < sum(i-1): 
                    end = False
                        
                print("Waiting for node "+str(i)+" to connect... " +str(int(connexion/2))+"/"+str(sum((i-1))),end ='\r')

    print()
    


    waiting_for_connextion(nodes)


    

    end = time.time() - start
    print("Time to connect all nodes: ",end)
    
    return nodes

def is_valide_ip(ip,nodes):
    for node in nodes:
        if node.host == ip:
            return True
    return False




def message(nodes):
    prefix = "message "

    raw_ip = ""
    while(not is_valide_ip(raw_ip,nodes)):
        raw_ip = input(prefix +"Enter a valide ip adress for the sender of this form 127.0.0.x with 0<x<=n : ")

    sender_ip = raw_ip

    raw_ip = ""
    while(not is_valide_ip(raw_ip,nodes)):
        raw_ip = input(prefix +"Enter a valide ip adress for the receiver of this form 127.0.0.x with 0<x<=n : ")

    receiver_ip = raw_ip

    message = input(prefix +"Enter the message you want to send : ")

    for node in nodes:
        if node.host == sender_ip:
            node.send_message(message,receiver_ip)
            print("Message sent")
            break                    
    
    return nodes

    
def add_client(nodes):
    ve = ""
    while (ve != "y" and ve != "n"):
        ve = input("Do you want to see the verbose of the new client (y/n) (Warning : you will not see the indication anymore): ")
    
    if ve == "y":
        ve = True
    else:
        ve = False

    n = len(nodes)
    nodes.append(Client("127.0.0."+str(n+1),5000,verbose=ve))
    nodes[n].start()
    time.sleep(1) # make sure the thread is fully started
    nodes[n].connect_to("127.0.0."+str(n),5000)
    waiting_for_connextion(nodes)

    return nodes



def tor_message(nodes):
    prefix = "TOR message "

    raw_ip = ""
    while(not is_valide_ip(raw_ip,nodes)):
        raw_ip = input(prefix +"Enter a valide ip adress for the sender of this form 127.0.0.x with 0<x<=n : ")

    sender_ip = raw_ip

    raw_ip = ""
    while(not is_valide_ip(raw_ip,nodes)):
        raw_ip = input(prefix +"Enter a valide ip adress for the receiver of this form 127.0.0.x with 0<x<=n : ")

    receiver_ip = raw_ip

    message = input(prefix +"Enter the message you want to send : ")

    for node in nodes:
        if node.host == sender_ip:
            node.send_tor(message,receiver_ip)
            print("Message sent")
            break  
    
    time.sleep(3)
    print("",end='\r')                  
    
    return nodes

def tor_http(nodes):

    prefix = "TOR http "

    raw_ip = ""
    while(not is_valide_ip(raw_ip,nodes)):
        raw_ip = input(prefix +"Enter a valide ip adress for the sender of this form 127.0.0.x with 0<x<=n : ")

    sender_ip = raw_ip
    
    
    example = ""
    while (example != "y" and example != "n"):
        print(prefix + "Warning : your own url may note work because of the size of the html answer")
        example = input(prefix + "Do you want to test with the simple example (y/n) : ")
    
    if example == "y":
        raw = "https://www.w3schools.com/python/demopage.htm"
    else:
        raw = input(prefix +"Enter a valide url : ")


    
    

    sender_ip = raw_ip

    

    for node in nodes:
        if node.host == sender_ip:
            html = node.request_http(raw)
            print(html)
            break  
    
    time.sleep(3)
    print("",end='\r')                  
    
    return nodes


def challenge(nodes):
    
        
    prefix = "Challenge "

    raw_ip = ""
    while(not is_valide_ip(raw_ip,nodes)):
        raw_ip = input(prefix +"Enter a valide ip adress for the sender of this form 127.0.0.x with 0<x<=n : ")
    
    sender_ip = raw_ip

    password = input(prefix +"Enter the password you want to initialize the server with : ")



    chal = Challenge("127.0.1.1",password)
    chal.start()
    time.sleep(1) # make sure the thread is fully started
    
    password = input(prefix +"Enter the password that you want to use to connect to server : ")
    
    
    for node in nodes:
        if node.host == sender_ip:
            node.send_challenge(password)
            
            break                    
    chal.stop()
    
        
    
        
    return nodes

def stop_nodes(nodes):
    print("Stopping nodes...")
    for node in nodes:
        node.stop()
    return nodes


def help(nodes):
    print(
    """\033[94m
start : start the nodes
message : send a message from a node to another
add_client : add a client to the network
TOR_message : send a message from a node to another using TOR
TOR_http : send a http request from a node to another using TOR
challenge : send a challenge from a node to another
stop : stop the nodes
help : print this message
exit : exit the program \033[0m
""")

    return nodes


def sum(n):
    if n == 0:
        return 0
    else:
        return n + sum(n-1)



key_word = {
    "start":start_nodes,
    "message":message,
    "add_client":add_client,
    "TOR_message":tor_message,
    "TOR_http":tor_http,
    "challenge":challenge,
    "help":help,
    "stop":stop_nodes

}





print("We recommend to use 10 peers or less for a better experience")
n = int(input("Number of peers: "))
while(n < 4 or n > 254):
    n = int(input("Number of peers between 2 and 254: "))


nodes = start_nodes(n)



nodes = help(nodes)



while(True):
    key = input("Enter a command: ")
    try:
        nodes = key_word[key](nodes)
        
        if key == "stop":
            break
    except Exception as e:
        print(e)
        print("Command not found")



print("Exiting program...")
time.sleep(1)


