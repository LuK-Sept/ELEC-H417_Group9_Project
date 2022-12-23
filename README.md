# User notice for Peer to Peer TOR network

## Installation

```
pip install -r requirements.txt
```

To start :
```sh
python3 p2p.py
```

You are asked for a number of peers.
A good amount of peers is between 5 and 10.
If you set a number of peers higher than 10 this will make a safe star i.e waiting for all the client to be well connected before adding a new client.
It will slow the process but can reduce risk of error in the sockets.

## Mainloop

- **help**
Help is used to display all the possible command
- **message**
send a message from a node to another
- **add_client**
add a client to the network
- **TOR_message**
send a message from a node to another using TOR
- **TOR_http**
send a http request from a node to another using TOR
- **challenge**
send a challenge from a node to another
- **stop**
stop the nodes


