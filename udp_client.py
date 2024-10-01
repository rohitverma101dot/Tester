import socket
import sys
'''
The correct maximum UDP message size is 65507,
as determined by the following formula: 0xffff - (sizeof(IP Header) + sizeof(UDP Header)) = 65535-(20+8) = 65507
http://stackoverflow.com/questions/1098897/what-is-the-largest-safe-udp-packet-size-on-the-internet
search gateway MTU:
ping -s 1500 -M do <gateway>
'''
messages = [b'x' * 65507] * 3
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
print(s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF))
for data in messages:
    s.sendto(data, ('127.0.0.1', int(sys.argv[-1])))
    print(s.recv(1024))
s.close()