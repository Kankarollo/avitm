from ai_analyzer import AIanalyzer
import math
import socket
from protocol_classifier import ProtocolClassifier, TCP_APPLICATION_PROTOCOLS
from hedge import Hedge
import logging
import numpy as np
import pandas as pd

log = logging.getLogger("mylog")

class Analyzer():
    SAFE_PROTOCOLS = [TCP_APPLICATION_PROTOCOLS.TLS,TCP_APPLICATION_PROTOCOLS.SSH,TCP_APPLICATION_PROTOCOLS.OPENVPN, TCP_APPLICATION_PROTOCOLS.HTTP]

    def __init__(self):
        self.ai_analyzer = AIanalyzer()


    def is_safe_protocol(self, session):
        log.info(f"Checking protocol...")
        init_packet = session[0]
        protocol = ProtocolClassifier.check_protocol(init_packet)
        if protocol in self.SAFE_PROTOCOLS:
            log.info(f"Protocol is secure.")
            return True

        log.info(f"Protocol is NOT secure.")
        return False

    def is_encrypted(self, payload):
        log.info(f"Analyzing encryption level...")
        entropy = self.calculate_entropy(payload)
        if entropy > 5.0:
            log.info(f"Payload is encrypted.")
            # hedge = Hedge()
            # results = hedge.execute_tests(payload)
            # return hedge.is_encrypted(results)
            return True
        log.info(f"Payload is NOT encrypted.")
        log.info(f"[DEBUG]:Entropy level: {entropy}")
        return False

    def calculate_entropy(self, payload):
        '''
        Performs a Shannon entropy analysis on a given block of data.
        '''
        entropy = 0

        if payload:
            length = len(payload)

            seen = dict(((x, 0) for x in range(0, 256)))
            for byte in payload:
                seen[byte] += 1

            for x in range(0, 256):
                p_x = float(seen[x]) / length
                if p_x > 0:
                    entropy -= p_x * math.log(p_x, 2)

        return entropy

    def ai_analysis(self, session_time,session, session_ip, session_port):
        log.info("Analyzing payload with AI...")
        try:
            self.ai_analyzer.load_RandomForest_model("/home/epiflight/Desktop/avitm/recognizerAI/RandomForestTest/model_random_forest_classifier.joblib")
            # self.ai_analyzer.load_xgboost_model("/home/epiflight/Desktop/avitm/recognizerAI/xgBoostTest/model-xgboost.json")
        except Exception as e:
            log.error(f"AI analysis failed: {e}")
            return False

        prepared_data = self.prepare_session_data(session, session_time, session_ip, session_port)
        prediction = self.ai_analyzer.analyze_session_RandomForest(prepared_data)
        # prediction = self.ai_analyzer.analyze_session_xgboost(prepared_data)

        if prediction[0] =='1' or prediction[0] == 0:
            log.warning(f"Session with {session_ip} is NOT secure.")
            return True
        elif prediction[0] == '0' or prediction[0] == 1:
            log.info(f"Session with {session_ip} is secure.")
            return False
        else:
            raise ValueError('Wrong value returned from model')

    def prepare_session_data(self, session, session_time, session_ip, session_port):
        dataset = []
        addr_in_DNS = 1 if self.is_ip_addr_in_DNS(session_ip) else 0

        """TODO"""
        bytes_client_server = 0
        bytes_server_client = 0

        dataset.append([session_port,bytes_client_server, bytes_server_client, session_time, addr_in_DNS])
        df = pd.DataFrame(dataset, columns=["Server_port","Bytes_client_server", "Bytes_server_client", "Session_time", "Addr_in_DNS"])

        return df

    def is_ip_addr_in_DNS(self, ip_addr):
        flag = True
        try:
            socket.gethostbyaddr(ip_addr)
        except socket.herror:
            flag = False

        return flag