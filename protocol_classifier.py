from __future__ import print_function
from enum import Enum

class TCP_APPLICATION_PROTOCOLS(Enum):
    """
    Application protocols that we want to recognize inside TCP segments. 
    Numbers assigned to it represents typical ports that are used by these protocols.
    """
    TCP = 0
    SSH = 22
    TLS = 443
    OPENVPN = 1194
    TEST = 2137
    HTTP = 80
    NOT_RECOGNIZED = -1


class ProtocolClassifier:
    @staticmethod
    def check_protocol(tcp_packet):
        """
        Classify protocol based on data inside tcp_packet
        """
        protocol = TCP_APPLICATION_PROTOCOLS.NOT_RECOGNIZED
        if ProtocolClassifier.is_tls(tcp_packet):
            protocol = TCP_APPLICATION_PROTOCOLS.TLS
        elif ProtocolClassifier.is_ssh(tcp_packet):
            protocol = TCP_APPLICATION_PROTOCOLS.SSH
        elif ProtocolClassifier.is_openvpn(tcp_packet):
            protocol = TCP_APPLICATION_PROTOCOLS.OPENVPN
        elif ProtocolClassifier.is_http(tcp_packet):
            protocol = TCP_APPLICATION_PROTOCOLS.HTTP

        return protocol

    @staticmethod
    def is_tls(tcp_packet):
        """Checking is packet has TLS layer using scapy library."""
        return tcp_packet.get_src_port()==443 or tcp_packet.get_dst_port()==443

    @staticmethod
    def is_ssh(tcp_packet):
        """Check if packet is using SSH. Temporarily classifying based only on src and dst ports."""
        return tcp_packet.get_src_port()==22 or tcp_packet.get_dst_port()==22

    @staticmethod
    def is_openvpn(tcp_packet):
        """Check if packet is using OpenVPN. Temporarily classifying based only on src and dst ports."""
        return tcp_packet.get_src_port()==1194 or tcp_packet.get_dst_port()==1194
    
    @staticmethod
    def is_http(tcp_packet):
        """Check if packet is using OpenVPN. Temporarily classifying based only on src and dst ports."""
        return ((tcp_packet.get_src_port()==80 or tcp_packet.get_dst_port()==80) or 
            (tcp_packet.get_src_port()==8080 or tcp_packet.get_dst_port()==8080))


def main():
    print("[TEST]: Executing testing program. Check if classifier is working correctly.")
    # packets = rdpcap("test_pcap_files/tcp_packets_test.pcap")
    packets = rdpcap("utils/test_pcap_files/tlsPackets_test.pcap")
    for packet in packets:
        if packet.haslayer(TLS):
            print("[DEBUG]: TLS HERE!!!")
        else:
            print("[DEBUG]: TLS NOT FOUND!!!")

def test():
    print("[TEST]: This is test method for testing purpose.")

if __name__ == '__main__':
    # main()
    test()
