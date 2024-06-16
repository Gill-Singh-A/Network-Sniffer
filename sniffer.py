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
def ip_headers(packet):
    ip_headers_content = packet[eth_header_length:]
    version = ip_headers_content[0] >> 4
    ihl = ip_headers_content[0] & 0xF
    header_length = ihl * 4
    total_length = int(binascii.hexlify(ip_headers_content[2:4]).decode(), 16)
    identification = int(binascii.hexlify(ip_headers_content[4:6]).decode(), 16)
    ttl = ip_headers_content[8]
    protocol = ip_headers_content[9]
    source_address = socket.inet_ntoa(ip_headers_content[12:16])
    destination_address = socket.inet_ntoa(ip_headers_content[16:20])
    return version, ihl, total_length, identification, ttl, protocol, source_address, destination_address, header_length

if __name__ == "__main__":
    raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    try:
        while True:
            packet = raw_socket.recvfrom(65535)[0]
            destination_mac, source_mac, eth_type = eth_headers(packet)
            print(f"Ethernet Frame\nDestination MAC => {destination_mac}, Source MAC => {source_mac}, Protocol => {eth_type}")
            version, ihl, total_length, identification, ttl, protocol, source_address, destination_address, ip_header_length = ip_headers(packet)
            print(f"\tIPv4 Packet\n\t\tVersion => {version}, Length => {total_length}, TTL => {ttl}\n\t\tProtocol => {protocol}, Source Address => {source_address}, Destination Address => {destination_address}")
            remaining_packet = packet[eth_header_length+ip_header_length: ]
    except KeyboardInterrupt:
        print("\nKeyboard Interrupt")
    except Exception as error:
        print(error)