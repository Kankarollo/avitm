"""
File created to equalize size of benign to malware data, by choosing random elements from original BENIGN_JSON_FILE. 
"""

import json
import random

MALWARE_JSON_FILE = "/home/epiflight/Desktop/pywall/utils/recognizerAI/malware_summary.json"
BENIGN_JSON_FILE = "/home/epiflight/Desktop/pywall/utils/recognizerAI/benign_summary.json"

BENIGN_OUTPUT_FILE = "/home/epiflight/Desktop/pywall/utils/recognizerAI/benign_equalized_summary.json"

def main():
    desired_length = 0
    with open(MALWARE_JSON_FILE, 'r') as f:
        malware_json = json.load(f)
        desired_length = len(malware_json)

    print(f"MALWARE JSON LENGTH: {desired_length}")

    benign_json = {}
    with open(BENIGN_JSON_FILE, 'r') as f:
        benign_json = json.load(f)
    
    choosen_elements_index = random.sample(range(0,len(benign_json)),desired_length)
    print(f" CHOOSEN ELEMENTS: {choosen_elements_index}")

    final_json = []
    for index in choosen_elements_index:
        final_json.append(benign_json[index])
    with open(BENIGN_OUTPUT_FILE, 'w') as f:
        json.dump(final_json,f,indent=4)

if __name__ == '__main__':
    main()
    