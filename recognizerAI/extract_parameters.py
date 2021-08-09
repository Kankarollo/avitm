import json
import glob
import socket
import math

TEST_FILE = "/home/epiflight/Desktop/pywall/utils/recognizerAI/sessions_dataset/malwareDataset/jsonMalwareDataset/CTU2_session.pcap.json"
MALWARE_DIRECTORY = "/home/epiflight/Desktop/pywall/utils/recognizerAI/sessions_dataset/malwareDataset/jsonMalwareDataset"
BENIGN_DIRECTORY = "/home/epiflight/Desktop/pywall/utils/recognizerAI/sessions_dataset/benignDataset/benignJsonDataset"
SUMMARY_FILE = "summary.json"

MALWARE_SUMMARY_OUTPUT_FILE = "/home/epiflight/Desktop/pywall/utils/recognizerAI/malware_summary.json"
BENIGN_SUMMARY_OUTPUT_FILE = "/home/epiflight/Desktop/pywall/utils/recognizerAI/benign_summary.json"
STREAM_CHUNK = 50

def main():
    whole_json = []
    end_line = 0
    file_dataset = glob.glob(f"{MALWARE_DIRECTORY}/*.json")
    for index,filename in enumerate(file_dataset):
        print(f"Analysing malware json file:{index} out of {len(file_dataset)}.")
    # for index,filename in enumerate([TEST_FILE]):
        end_of_file = False
        file_data = {}
        json_pcap = ""
        with open(filename,'r') as file:
            json_pcap = file.read()
        json_pcap = json.loads(json_pcap)
        while not end_of_file:
            file_data["session_chunk"], end_of_file, end_line = gather_data(json_pcap, "malware", index, end_line)
            whole_json.append(file_data.copy())
        end_line = 0
    with open(MALWARE_SUMMARY_OUTPUT_FILE, 'w') as f:
        json.dump(whole_json, f, indent=4)

    whole_json = []
    end_line = 0
    file_dataset = glob.glob(f"{BENIGN_DIRECTORY}/*.json")
    for index,filename in enumerate(file_dataset):
        print(f"Analysing benign json file: {index} out of {len(file_dataset)}.")
    # for index,filename in enumerate([TEST_FILE]):
        end_of_file = False
        file_data = {}
        json_pcap = ""
        with open(filename,'r') as file:
            json_pcap = file.read()
        json_pcap = json.loads(json_pcap)
        while not end_of_file:
            file_data["session_chunk"], end_of_file, end_line = gather_data(json_pcap, "benign", index, end_line)
            whole_json.append(file_data.copy())
        end_line = 0
    with open(BENIGN_SUMMARY_OUTPUT_FILE, 'w') as f:
        json.dump(whole_json, f, indent=4)

    print("KONIEC")

def gather_data(json, traffic_type, session_id, start_line=0):
    """
    Gathering data about session from json object. TCP sessions packet number can vary, so decided to divide it to equall chunks - 50 packets.
    One session can be divided for many sessions, that's why there is session_id.
     """

    raport = {}
    raport["session_id"] = session_id
    raport["time_between_packets"] = []
    raport["time_between_packets_client_server"] = []
    raport["time_between_packets_server_client"] = []
    raport["packet_lengths_client_server"] = []
    raport["packet_lengths_server_client"] = []
    raport["packet_lengths"] = []
    raport["packet_byte_distribution"] = []
    raport["ip_address_server"] = ""
    raport["ip_addr_in_DNS"] = False
    raport["port_src"] = ""
    raport["port_dst"] = ""
    raport["class"]= traffic_type

    init_packet = json[0]
    raport["ip_address_server"] = init_packet["_source"]["layers"]["ip"]["ip.dst"]
    raport["ip_addr_in_DNS"] = is_ip_addr_in_DNS(raport["ip_address_server"])
    raport["port_src"] = init_packet["_source"]["layers"]["tcp"]["tcp.srcport"] 
    raport["port_dst"] = init_packet["_source"]["layers"]["tcp"]["tcp.dstport"]

    end_line = start_line
    end_of_file_flag = True
    for index, element in enumerate(json[start_line:]):
        # payload = init_packet["_source"]["layers"]["tcp"]["tcp.payload"]
        # raport["packet_byte_distribution"].append(calculate_byte_distribution(payload))
        if index > STREAM_CHUNK - 1:
            end_line += index
            end_of_file_flag = False
            break

        frame_length = element["_source"]["layers"]["frame"]["frame.len"]
        time_delta =element["_source"]["layers"]["frame"]["frame.time_delta"]
        if element["_source"]["layers"]["tcp"]["tcp.srcport"] == raport["port_src"]:
            raport["packet_lengths_client_server"].append(frame_length)
            raport["time_between_packets_client_server"].append(time_delta)
        elif element["_source"]["layers"]["tcp"]["tcp.srcport"] == raport["port_dst"]:
            raport["packet_lengths_server_client"].append(frame_length)
            raport["time_between_packets_server_client"].append(time_delta)
            frame_length = "-" +frame_length

        raport["packet_lengths"].append(frame_length)
        raport["time_between_packets"].append(time_delta)

    raport["number_of_packets"] = len(raport["packet_lengths"])
    raport["bytes_sent_client_server"] = sum([abs(int(value)) for value in raport["packet_lengths_client_server"]])
    raport["bytes_sent_server_client"] = sum([abs(int(value)) for value in raport["packet_lengths_server_client"]])
    raport["session_time"] = sum([float(value) for value in raport["time_between_packets"]])

    return raport, end_of_file_flag, end_line

def calculate_byte_distribution(payload):
    distribution = -1.0

    entropy = 0
    if payload:
        length = len(payload)

        seen = dict(((chr(x), 0) for x in range(0, 256)))
        for byte in payload:
            seen[chr(byte)] += 1

        for x in range(0, 256):
            p_x = float(seen[chr(x)]) / length
            if p_x > 0:
                entropy -= p_x * math.log(p_x, 2)

    return distribution

def is_ip_addr_in_DNS(ip_addr):
    flag = True
    try:
        socket.gethostbyaddr(ip_addr)
    except socket.herror:
        flag = False

    return flag

if __name__ == '__main__':
    main()
    