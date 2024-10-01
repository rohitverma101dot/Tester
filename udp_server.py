# encoding=utf8
'''
http://stackoverflow.com/questions/11026316/reading-all-the-data-from-a-udp-socket
'''

import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', int(sys.argv[-1])))
print('Bind UDP on {0}...'.format(int(sys.argv[-1])))

while True:
    data, address = s.recvfrom(65507)
    print('Received from', address, len(data))
    message = 'Hello {0!r} {1!r} '.format(address, int(sys.argv[-1]))
    s.sendto(message.encode(), address)