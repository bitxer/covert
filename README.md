# Covert
A ICMP, HTTP, DNS, TCP covert channel POC

# Starting Server
```
usage: server.py [-h] [-l ip] [-p port] [-k key] [-t proto]

Covert callback channel

optional arguments:
  -h, --help            show this help message and exit
  -l ip, --listen ip    IP address to listen on
  -p port, --port port  Destination port number for tcp-based covert channel
  -k key, --key key     Key used to decrypt message send through TCP-based
                        covert channel
  -t proto, --protocol proto
                        Protocol to listen for connection on
```

# Starting Client
```
usage: client.py [-h] [-d ip] [-p port] [-k key] [-t proto] (-f path | -m msg)

Covert callback channel

optional arguments:
  -h, --help            show this help message and exit
  -d ip, --destination ip
                        Destination IP of callback server
  -p port, --port port  Destination port number for tcp-based covert channel
  -k key, --key key     Key used to encrypt message send through TCP-based
                        covert channel
  -t proto, --protocol proto
                        Protocol to exfiltrate Data using
  -f path, --file path  File to exfiltrate
  -m msg, --message msg
                        Message to exfiltrate
```
