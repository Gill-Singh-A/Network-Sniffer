#! /usr/bin/env python3

import socket, binascii

if __name__ == "__main__":
    raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    try:
        while True:
            packet = raw_socket.recvfrom(65535)[0]
    except KeyboardInterrupt:
        print("\nKeyboard Interrupt")
    except Exception as error:
        print(error)