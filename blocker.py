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
        self.hedge = False
        self.whitelist_filename = None

    def __del__(self):
        self.clean_iptables()

    def init_queue(self, queue: Queue):
        self.queue = queue

    def set_hedge_flag(self,hedge):
        self.hedge = hedge

    def set_whitelist_file(self, whitelist):
        self.whitelist_filename=whitelist

    def init_whitelist(self, filename):
        whitelist_list = []
        try:
            with open(filename, 'r') as file:
                whitelist_list = [line.strip() for line in file.readlines() if self.validate_ip(line.strip())]
        except Exception as e:
            log.error(str(e))
            return []
        
        log.info(f"Whitelist Initialized: {whitelist_list}")
        return whitelist_list


    def run(self):
        whitelist = []
        if self.whitelist_filename:
            whitelist = self.init_whitelist(self.whitelist_filename)
        while True:
            transport_layer_pdu = None
            try:
                transport_layer_pdu: TransportLayerPacket = self.queue.get(
                    timeout=5)
            except queue.Empty as e:
                print(str(e))
                self.stop()
                return


            src_ip = transport_layer_pdu.get_src_ip()
            src_port = transport_layer_pdu.get_src_port()
            dst_ip = transport_layer_pdu.get_dst_ip()
            dst_port = transport_layer_pdu.get_dst_port()

            # Packets in two directions belong to the same session
            tup = (src_ip, src_port, dst_ip, dst_port)
            flip_tup = (dst_ip, dst_port, src_ip, src_port)
            if src_ip in whitelist or dst_ip in whitelist:
                continue
            if tup in self.session_database:
                self.session_database[tup].append(transport_layer_pdu)
            elif flip_tup in self.session_database:
                tup = flip_tup
                self.session_database[tup].append(transport_layer_pdu)
            else:
                self.session_database[tup] = [transport_layer_pdu]
                log.info(f"NEW SESSION: {tup}")
            if len(self.session_database[tup]) >= 50:
                log.info(f"ANALYZING SESSION: {tup}")
                # Don't accidentally block your own ip
                session_ip = src_ip if src_ip != self.host_ip else dst_ip
                session_port = src_port if src_ip != self.host_ip else dst_port
                if self.is_session_malicious(self.session_database[tup], session_ip, session_port):
                    self.block_ip(session_ip)
                    # Release resources
                del self.session_database[tup]

    def is_session_malicious(self, session, session_ip, session_port):
        payload = b''
        session_time = session[-1].get_timestamp() - session[0].get_timestamp()
        for pdu in session:
            payload += pdu.get_body()

        analyzer = Analyzer()
        if analyzer.is_safe_protocol(session):
            return False
        if not analyzer.is_encrypted(payload, hedge_flag=self.hedge):
            return False
        if analyzer.ai_analysis(session_time, session, session_ip, session_port, payload):
            return True

        return False

    def block_ip(self, ip):
        log.info(f"Blocked IP: {ip}")
        if self.validate_ip(ip):
            subprocess.call(["sudo", "iptables", "-A",
                            "INPUT", "-s", ip, "-j", "DROP"])
            subprocess.call(["sudo", "iptables", "-A",
                            "OUTPUT", "-s", ip, "-j", "DROP"])
            self.block_list.append(ip)
        else:
            log.warn(f"INVALID IP: {ip}")

    def clean_iptables(self):
        for ip in self.block_list:
            if self.validate_ip(ip):
                log.info(f"Unblocking IP: {ip}")
                subprocess.call(["sudo", "iptables", "-D",
                                "INPUT", "-s", ip, "-j", "DROP"])
                subprocess.call(["sudo", "iptables", "-D",
                                "OUTPUT", "-s", ip, "-j", "DROP"])
            else:
                log.warn(f"INVALID IP: {ip}")
        self.block_list = []

    def validate_ip(self, ip):
        flag = False

        def isIPv4(s):
            try:
                return str(int(s)) == s and 0 <= int(s) <= 255
            except:
                return False

        def isIPv6(s):
            if len(s) > 4:
                return False
            try:
                return int(s, 16) >= 0 and s[0] != '-'
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
