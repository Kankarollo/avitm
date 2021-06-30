"""Contains Python objects for IP and network layer datagrams/segments.

These generally take a buffer in their constructor, and parse the header fields
into class member fields so that we can access them easily.

"""

from struct import unpack
import socket
from abc import ABC, ABCMeta, abstractmethod
from time import time
from tabulate import tabulate

# A list of IP Protocol numbers, taken directly from IANA.
PROTO_NUMS = {
    0: 'HOPOPT',
    1: 'ICMP',
    2: 'IGMP',
    3: 'GGP',
    4: 'IPv4',
    5: 'ST',
    6: 'TCP',
    7: 'CBT',
    8: 'EGP',
    9: 'IGP',
    10: 'BBN-RCC-MON',
    11: 'NVP-II',
    12: 'PUP',
    13: 'ARGUS',
    14: 'EMCON',
    15: 'XNET',
    16: 'CHAOS',
    17: 'UDP',
    18: 'MUX',
    19: 'DCN-MEAS',
    20: 'HMP',
    21: 'PRM',
    22: 'XNS-IDP',
    23: 'TRUNK-1',
    24: 'TRUNK-2',
    25: 'LEAF-1',
    26: 'LEAF-2',
    27: 'RDP',
    28: 'IRTP',
    29: 'ISO-TP4',
    30: 'NETBLT',
    31: 'MFE-NSP',
    32: 'MERIT-INP',
    33: 'DCCP',
    34: '3PC',
    35: 'IDPR',
    36: 'XTP',
    37: 'DDP',
    38: 'IDPR-CMTP',
    39: 'TP++',
    40: 'IL',
    41: 'IPv6',
    42: 'SDRP',
    43: 'IPv6-Route',
    44: 'IPv6-Frag',
    45: 'IDRP',
    46: 'RSVP',
    47: 'GRE',
    48: 'DSR',
    49: 'BNA',
    50: 'ESP',
    51: 'AH',
    52: 'I-NLSP',
    53: 'SWIPE (deprecated)',
    54: 'NARP',
    55: 'MOBILE',
    56: 'TLSP',
    57: 'SKIP',
    58: 'IPv6-ICMP',
    59: 'IPv6-NoNxt',
    60: 'IPv6-Opts',
    62: 'CFTP',
    64: 'SAT-EXPAK',
    65: 'KRYPTOLAN',
    66: 'RVD',
    67: 'IPPC',
    69: 'SAT-MON',
    70: 'VISA',
    71: 'IPCV',
    72: 'CPNX',
    73: 'CPHB',
    74: 'WSN',
    75: 'PVP',
    76: 'BR-SAT-MON',
    77: 'SUN-ND',
    78: 'WB-MON',
    79: 'WB-EXPAK',
    80: 'ISO-IP',
    81: 'VMTP',
    82: 'SECURE-VMTP',
    83: 'VINES',
    84: 'IPTM',
    85: 'NSFNET-IGP',
    86: 'DGP',
    87: 'TCF',
    88: 'EIGRP',
    89: 'OSPFIGP',
    90: 'Sprite-RPC',
    91: 'LARP',
    92: 'MTP',
    93: 'AX.25',
    94: 'IPIP',
    95: 'MICP (deprecated)',
    96: 'SCC-SP',
    97: 'ETHERIP',
    98: 'ENCAP',
    100: 'GMTP',
    101: 'IFMP',
    102: 'PNNI',
    103: 'PIM',
    104: 'ARIS',
    105: 'SCPS',
    106: 'QNX',
    107: 'A/N',
    108: 'IPComp',
    109: 'SNP',
    110: 'Compaq-Peer',
    111: 'IPX-in-IP',
    112: 'VRRP',
    113: 'PGM',
    115: 'L2TP',
    116: 'DDX',
    117: 'IATP',
    118: 'STP',
    119: 'SRP',
    120: 'UTI',
    121: 'SMP',
    122: 'SM',
    123: 'PTP',
    124: 'ISIS over IPv4',
    125: 'FIRE',
    126: 'CRTP',
    127: 'CRUDP',
    128: 'SSCOPMCE',
    129: 'IPLT',
    130: 'SPS',
    131: 'PIPE',
    132: 'SCTP',
    133: 'FC',
    134: 'RSVP-E2E-IGNORE',
    135: 'Mobility Header',
    136: 'UDPLite',
    137: 'MPLS-in-IP',
    138: 'manet',
    139: 'HIP',
    140: 'Shim6',
    141: 'WESP',
    142: 'ROHC'
}


def to_tuple(ippacket, flip=False):
    """Create a tuple from a TCP packet.

    The flip argument flips the source and destination port, so that they will
    be consistent between ingress and egress.

    """
    payload = ippacket.get_payload()
    if type(payload) is TCPPacket and not flip:
        tup = (ippacket.get_src_ip(), payload.get_src_port(),  # remote
               ippacket.get_dst_ip(), payload.get_dst_port())  # local
        return tup
    elif type(payload) is TCPPacket and flip:
        tup = (ippacket.get_dst_ip(), payload.get_dst_port(),  # remote
               ippacket.get_src_ip(), payload.get_src_port())  # local
    else:
        tup = None
    return tup


class Packet(metaclass=ABCMeta):

    @abstractmethod
    def get_header_len(self):
        pass

    @abstractmethod
    def get_data_len(self):
        pass

    @abstractmethod
    def get_src_ip(self):
        pass

    @abstractmethod
    def get_dst_ip(self):
        pass

    @abstractmethod
    def get_timestamp(self):
        pass
class TransportLayerPacket(Packet):
    """Base class packets at the transport layer """
    __metaclass__ = ABCMeta

    @abstractmethod
    def get_body(self):
        pass

    @abstractmethod
    def get_data_len(self):
        pass

    @abstractmethod
    def get_src_port(self):
        pass

    @abstractmethod
    def get_dst_port(self):
        pass

    


class IPPacket(Packet):
    """Base class for all packets"""

    def __init__(self, buff,timestamp):
        """Create packet from raw data."""
        self.timestamp = timestamp
        self._buff = buff[:]
        ip_header = self._buff[0:20]
        self._iph = unpack('!BBHHHBBH4s4s', ip_header)
        # Internal Header Length, in bytes
        self._version = self._iph[0] >> 4
        self._iph_length = (self._iph[0] & 0xF) * 4
        self._ttl = self._iph[5]
        self._protocol = PROTO_NUMS.get(self._iph[6], 'UNKNOWN')
        self._src_ip = socket.inet_ntoa(self._iph[8])
        self._dst_ip = socket.inet_ntoa(self._iph[9])
        self._transport_layer_pdu = self.payload_builder(
            self._buff[self._iph_length:], self._protocol)

    def get_src_ip(self):
        return self._src_ip

    def get_dst_ip(self):
        return self._dst_ip

    def get_timestamp(self):
        return self.timestamp

    def get_protocol(self):
        """Return name of protocol of payload of packet."""
        return self._protocol

    def get_transport_layer_pdu(self):
        return self._transport_layer_pdu

    def get_header_len(self):
        return self._iph_length

    def get_data_len(self):
        return len(self._buff) - self._iph_length

    def payload_builder(self, payload_buff, protocol):
        """If `protocol` is supported, builds packet object from buff."""
        if protocol == PROTO_NUMS.get(socket.IPPROTO_TCP):
            return TCPPacket(payload_buff, self._src_ip, self._dst_ip, self.timestamp)
        elif protocol == PROTO_NUMS.get(socket.IPPROTO_UDP):
            return UDPPacket(payload_buff, self._src_ip, self._dst_ip, self.timestamp)
        else:
            return None

    # def __unicode__(self):
    #     return 'IP Packet %s => %s, proto=%s' % (self._src_ip, self._dst_ip,
    #                                              self._proto)


class TCPPacket(TransportLayerPacket):
    """TCP Packet object."""

    def __init__(self, buff, src_ip, dst_ip, timestamp):
        self._src_ip, self._dst_ip = src_ip, dst_ip
        self.timestamp = timestamp 
        self._buff = buff[:]
        self._tcph = unpack('!HHLLBBHHH', self._buff[:20])
        self._src_port, self._dst_port = self._tcph[0], self._tcph[1]
        self._seq_num, self._ack_num = self._tcph[2], self._tcph[3]
        flags = self._tcph[4]
        self._tcph_length = (self._tcph[4] >> 4) * 4
        self._data_offset = (flags & 0xF000) >> 12
        self.flag_ns = (flags & 0x0100) >> 8
        self.flag_cwr = (flags & 0x0080) >> 7
        self.flag_ece = (flags & 0x0040) >> 6
        self.flag_urg = (flags & 0x0020) >> 5
        self.flag_ack = (flags & 0x0010) >> 4
        self.flag_psh = (flags & 0x0008) >> 3
        self.flag_rst = (flags & 0x0004) >> 2
        self.flag_syn = (flags & 0x0002) >> 1
        self.flag_fin = (flags & 0x0001)
        self._total_length = len(buff)
        self._body = buff[self._tcph_length:]
        self._data_len = self._total_length - self._tcph_length

    def get_data_len(self):
        return self._data_len

    def get_raw_packet(self):
        return self._buff

    def get_header_len(self):
        return self._tcph_length

    def get_src_port(self):
        return self._src_port

    def get_timestamp(self):
        return self.timestamp

    def get_dst_port(self):
        return self._dst_port

    def get_body(self):
        return str(self._body)

    def get_src_ip(self):
        return self._src_ip

    def get_dst_ip(self):
        return self._dst_ip

    # def __unicode__(self):
    #     """Returns a printable version of the TCP header"""
    #     return u'TCP from %d to %d, protocol:%d' % (self._src_port, self._dst_port)


class UDPPacket(TransportLayerPacket):
    """UDP Packet object."""

    def __init__(self, buff, src_ip, dst_ip, timestamp):
        self._src_ip, self._dst_ip = src_ip, dst_ip
        self.timestamp = timestamp
        self._src_port, self._dst_port = unpack('!HH', buff[0:4])
        self._length, self._checksum = unpack('!HH', buff[4:8])
        self._total_length = len(buff)
        self._body = buff[self.get_header_len():]

    def get_header_len(self):
        return 8

    def get_timestamp(self):
        return self.timestamp

    def get_data_len(self):
        return self._total_length - self.get_header_len()

    def get_src_port(self):
        return self._src_port

    def get_dst_port(self):
        return self._dst_port

    def get_body(self):
        return str(self._body)

    def get_src_ip(self):
        return self._src_ip

    def get_dst_ip(self):
        return self._dst_ip

    # def __unicode__(self):
    #     """Returns a printable version of the UDP header"""
    #     return u'UDP from %d to %d' % (self._src_port, self._dst_port)
