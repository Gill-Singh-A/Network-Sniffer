#! /usr/bin/env python3

import socket, binascii

eth_header_length = 14

def MACformat(mac):
    return ':'.join([mac[index*2: (index+1)*2] for index in range(6)]).upper()
def eth_headers(packet):
    destination_mac = MACformat(binascii.hexlify(packet[:6]).decode())
    source_mac = MACformat(binascii.hexlify(packet[6:12]).decode())
    eth_type = int(binascii.hexlify(packet[12:14]).decode())
    return destination_mac, source_mac, eth_type

if __name__ == "__main__":
    raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    try:
        while True:
            packet = raw_socket.recvfrom(65535)[0]
            destination_mac, source_mac, eth_type = eth_headers(packet)
            print(f"Ethernet Frame\nDestination MAC => {destination_mac}, Source MAC => {source_mac}, Protocol => {eth_type}")
    except KeyboardInterrupt:
        print("\nKeyboard Interrupt")
    except Exception as error:
        print(error)