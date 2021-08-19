import xgboost
import json
import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score

MODEL_FILENAME = "/home/epiflight/Desktop/avitm/recognizerAI/xgBoostTest/model-xgboost.json"
JSON_BENIGN_FILENAME = "/home/epiflight/Desktop/avitm/recognizerAI/benignSamples/benign_summary_v20.json"
JSON_MALWARE_FILENAME = "/home/epiflight/Desktop/avitm/recognizerAI/malwareSamples/malware_summary_v20.json"

def main():
    xgboost_model = xgboost.XGBClassifier()
    xgboost_model.load_model(MODEL_FILENAME)

    data_to_predict = {}
    with open(JSON_BENIGN_FILENAME,'r') as f:
        data_to_predict = json.load(f)

    prepared_data = prepare_data(data_to_predict)

    y_pred = xgboost_model.predict(prepared_data)
    predictions = [round(value) for value in y_pred]

    percent = float(len([x for x in predictions if x == 1]))/len(predictions)*100

    print("------------SUMMARY----------")
    print(predictions)
    print(f"Success rate:{percent}%")


def prepare_data(data):
    prepared_data = {}

    dataset = []
    for element in data:
        session = element["session_chunk"]
        server_port = session["port_dst"]
        bytes_client_server = session["bytes_sent_client_server"] 
        bytes_server_client = session["bytes_sent_server_client"] 
        session_time = session["session_time"]
        session_type = 0
        addr_in_DNS = 0
        if session["class"] == "malware":
            session_type = 1
        if session["ip_addr_in_DNS"]:
            addr_in_DNS = 1
        dataset.append([server_port,bytes_client_server, bytes_server_client, session_time, addr_in_DNS, session_type])
        # dataset.append([bytes_client_server, bytes_server_client, session_time, addr_in_DNS, session_type])

    dataset = np.array(dataset)
    df = pd.DataFrame(dataset, columns=["Server_port","Bytes_client_server", "Bytes_server_client", "Session_time", "Addr_in_DNS", "Session_type"])

    prepared_data = df.iloc[:,0:5]

    return prepared_data


if __name__ == '__main__':
    main()
    