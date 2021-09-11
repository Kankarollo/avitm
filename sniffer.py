from logging import log
import socket
import sys
from prettytable import PrettyTable
from threading import Thread
from multiprocessing import Queue
import time
import logging
from packet import IPPacket, TCPPacket, TCPPacketScapy, TransportLayerPacket, UDPPacket
from blocker import Blocker
from scapy.all import sniff,raw
from scapy.layers.inet import IP, TCP 

log = logging.getLogger("mylog")
class Sniffer():

    def __init__(self, hedge, whitelist):
        print("Created sniffer object")
        self.blocker_queue = Queue()
        self.socket = None
        host_ip = self.get_ip_address()
        self.blocker = Blocker(host_ip)
        self.blocker.set_hedge_flag(hedge)
        self.blocker.set_whitelist_file(whitelist)

    def print_packet_info(self, ip_packet:IPPacket, pdu:TransportLayerPacket):
        parameters = [ip_packet.get_src_ip(), ip_packet.get_dst_ip(), ip_packet.get_protocol(),
        pdu.get_src_port(), pdu.get_dst_port(), pdu.get_data_len()]
        headers = ["Src_Address", "Dst_address","Transport_layer_protocol", "Src_port", "Dst_port", "Payload_length"]
        table = PrettyTable(headers)
        table.add_row(parameters)
        print(table)

    def print_packet_data(self, pdu:TransportLayerPacket):
        headers = ["Payload"]
        parameters = [pdu.get_body()]
        table = PrettyTable(headers)
        table.add_row(parameters)
        print(table)

    def get_ip_address(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]

    def run(self):
        print("Running")
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except socket.error as msg:
            print(f"Socket could not be created. Error Code: {msg}")
            sys.exit()

        # Run blocker in new thread
        self.blocker.init_queue(self.blocker_queue)
        self.block_thread = Thread(target=self.blocker.run, daemon=False)
        self.block_thread.start()

        while True:
            packet = self.socket.recvfrom(65565)
            timestamp = time.time_ns()
            # packet string from tuple
            packet = packet[0]

            ip_packet = IPPacket(packet,timestamp)
            transport_layer_pdu = ip_packet.get_transport_layer_pdu()
            # self.print_packet_info(ip_packet, transport_layer_pdu)
            # self.print_packet_data(transport_layer_pdu)

            self.blocker_queue.put(transport_layer_pdu)

    def send_scapy_packet(self,scapy_packet):
        if TCP in scapy_packet and IP in scapy_packet:
            tcp_packet = TCPPacketScapy(scapy_packet)
            # self.print_packet_data(tcp_packet)
            self.blocker_queue.put(tcp_packet)

    def run_local(self):
        self.blocker.init_queue(self.blocker_queue)
        self.block_thread = Thread(target=self.blocker.run, daemon=False)
        self.block_thread.start()
        
        log.info("Running local version of Sniffer.")
        sniff(iface='enp34s0', filter="tcp", prn=self.send_scapy_packet)

    def stop(self):
        self.socket.close()
        log.warn(f"[SNIFFER]: CTRL+C detected. Stopping program.")

if __name__ == '__main__':
    sniffer = Sniffer(None,None)
    sniffer.run_local()
