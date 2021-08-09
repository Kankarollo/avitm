import math
import re
import bitarray
from protocol_classifier import ProtocolClassifier, TCP_APPLICATION_PROTOCOLS
from hedge import Hedge

class Analyzer():
    SAFE_PROTOCOLS = [TCP_APPLICATION_PROTOCOLS.TLS,TCP_APPLICATION_PROTOCOLS.SSH,TCP_APPLICATION_PROTOCOLS.OPENVPN, TCP_APPLICATION_PROTOCOLS.HTTP]

    def __init__(self):
        pass

    def is_safe_protocol(self, session):
        init_packet = session[0]
        protocol = ProtocolClassifier.check_protocol(init_packet)
        if protocol in self.SAFE_PROTOCOLS:
            return True

        return False

    def is_encrypted(self, payload):
        entropy = self.calculate_entropy(payload)
        if entropy > 6.0:
            hedge = Hedge()
            results = hedge.execute_tests(payload)
            return hedge.is_encrypted(results)
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

    def ai_analysis(self, session_time,session, session_ip):
        print("Analyzing with AI...")

        return False