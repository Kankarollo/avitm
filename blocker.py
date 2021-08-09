from os import path
import queue
from time import sleep
from queue import Queue
import subprocess
from packet import TransportLayerPacket
import logging
from analyzer import Analyzer

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
            transport_layer_pdu = None
            try:
                transport_layer_pdu : TransportLayerPacket = self.queue.get(timeout=5)
            except queue.Empty as e:
                print(str(e))
                self.stop()
                return

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
                tup = flip_tup
                self.session_database[tup].append(transport_layer_pdu)
            else:
                self.session_database[tup] = [transport_layer_pdu]
                log.info(f"NEW SESSION: {tup}")
            if len(self.session_database[tup]) >= 50:
                log.debug(f"ANALYZING SESSION: {tup}")
                # Don't accidentally block your own ip
                session_ip = src_ip if src_ip != self.host_ip else dst_ip
                if self.is_session_malicious(self.session_database[tup], session_ip):
                    self.block_ip(session_ip)
                    # Release resources
                del self.session_database[tup]

    def is_session_malicious(self, session, session_ip):
        payload = b''
        session_time = session[-1].get_timestamp() - session[0].get_timestamp()
        for pdu in session:
            payload += pdu.get_body()
        

        analyzer = Analyzer()
        # if analyzer.is_safe_protocol(session):
        #     return False
        if not analyzer.is_encrypted(payload):
            return False
        if analyzer.ai_analysis(session_time,session, session_ip):
            return True
        # if pdu.get_src_port() == 23 or pdu.get_dst_port() == 23:
        #     print(f"Session Payload: {payload}")

        # if b'dupa' in payload:
        #     return True

        return False

    def block_ip(self, ip):
        log.info(f"Blocked IP: {ip}")
        if self.validate_ip(ip):
            subprocess.call(["sudo" ,"iptables" ,"-A", "INPUT" ,"-s" ,ip ,"-j", "DROP"])
            subprocess.call(["sudo" ,"iptables" ,"-A", "OUTPUT" ,"-s" ,ip ,"-j", "DROP"])
            self.block_list.append(ip)
        else:
            log.warn(f"INVALID IP: {ip}")

    def clean_iptables(self):
        for ip in self.block_list:
            if self.validate_ip(ip):
                log.info(f"Unblocking IP: {ip}")
                subprocess.call(["sudo" ,"iptables" ,"-D", "INPUT" ,"-s" ,ip ,"-j", "DROP"])
                subprocess.call(["sudo" ,"iptables" ,"-D", "OUTPUT" ,"-s" ,ip ,"-j", "DROP"])
            else:
                log.warn(f"INVALID IP: {ip}")
        self.block_list = []
    
    def validate_ip(self,ip):
        flag = False
        def isIPv4(s):
            try: return str(int(s)) == s and 0 <= int(s) <= 255
            except: return False
        def isIPv6(s):
            if len(s) > 4:
                return False
            try : return int(s, 16) >= 0 and s[0] != '-'
            except:
                return False
        if ip.count(".") == 3 and all(isIPv4(el) < 255 for el in ip.split(".")):
            flag = True
        elif ip.count(":") == 7 and all(isIPv6(el) for el in ip.split(":")):
            flag = True

        return flag

    def stop(self):
        """ Clean after itself."""
        log.warn(f"[BLOCKER]: Cleaning iptables and stopping program")
        self.clean_iptables()