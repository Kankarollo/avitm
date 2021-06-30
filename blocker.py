from time import sleep
from queue import Queue
import subprocess
from packet import TransportLayerPacket
import logging

log = logging.getLogger("mylog")

class Blocker():
    
    def __init__(self, host_ip):
        self.block_list = []
        self.host_ip = host_ip
        self.session_database = {}

    def __del__(self):
        self.clean_iptables()

    def heartbeat(self):
        while True:
            print("Just chillin...")
            sleep(0.5)

    def init_queue(self, queue: Queue):
        self.queue = queue

    def run(self):
        while True:
            transport_layer_pdu : TransportLayerPacket = self.queue.get()
            pdu_body = transport_layer_pdu.get_body()

            src_ip = transport_layer_pdu.get_src_ip()
            src_port = transport_layer_pdu.get_src_port()
            dst_ip = transport_layer_pdu.get_dst_ip()
            dst_port = transport_layer_pdu.get_dst_port()

            # Packets in two directions belong to the same session
            tup = (src_ip,src_port,dst_ip,dst_port)
            flip_tup = (dst_ip,dst_port,src_ip,src_port)

            if tup in self.session_database:
                self.session_database[tup].append(transport_layer_pdu) 
            elif flip_tup in self.session_database:
                self.session_database[flip_tup].append(transport_layer_pdu)
            else:
                self.session_database[tup] = [transport_layer_pdu]
            print(pdu_body)
            if self.is_malicious(pdu_body):
                malicious_ip = src_ip if src_ip != self.host_ip else dst_ip
                self.block_ip(malicious_ip)

    def is_malicious(self, payload):
        if "DUPA" in payload:
            return True

        return False
    
    def block_ip(self, ip):
        log.info(f"Blocked IP: {ip}")
        subprocess.call(["sudo" ,"iptables" ,"-A", "INPUT" ,"-s" ,ip ,"-j", "DROP"])
        subprocess.call(["sudo" ,"iptables" ,"-A", "OUTPUT" ,"-s" ,ip ,"-j", "DROP"])
        self.block_list.append(ip)

    def clean_iptables(self):
        for ip in self.block_list:
            log.info(f"Unblocking IP: {ip}")
            subprocess.call(["sudo" ,"iptables" ,"-D", "INPUT" ,"-s" ,ip ,"-j", "DROP"])
            subprocess.call(["sudo" ,"iptables" ,"-D", "OUTPUT" ,"-s" ,ip ,"-j", "DROP"])