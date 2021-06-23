import socket
import sys
from packet import IPPacket, TCPPacket, TransportLayerPacket, UDPPacket
from struct import *
from prettytable import PrettyTable


class Sniffer():

    def __init__(self):
        print("Created sniffer object")

    def print_packet_info(self, ip_packet:IPPacket, pdu:TransportLayerPacket):
        parameters = [ip_packet.get_src_ip(), ip_packet.get_dst_ip(), ip_packet.get_protocol(),
        pdu.get_src_port(), pdu.get_dst_port(), pdu.get_data_len()]
        headers = ["Src_Address", "Dst_address","Transport_layer_protocol", "Src_port", "Dst_port", "Payload_length"]
        table = PrettyTable(headers)
        table.add_row(parameters)
        print(table)

    def run(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except socket.error as msg:
            print(f"Socket could not be created. Error Code: {msg}")
            sys.exit()

        while True:
            packet = s.recvfrom(65565)

            # packet string from tuple
            packet = packet[0]

            ip_packet = IPPacket(packet)
            transport_layer_pdu = ip_packet.get_transport_layer_pdu()


            self.print_packet_info(ip_packet, transport_layer_pdu)
            

        print("Running")