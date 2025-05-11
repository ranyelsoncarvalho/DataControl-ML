import csv
import joblib
import numpy as np
import pandas as pd
from collections import defaultdict
from datetime import datetime
from sklearn.preprocessing import StandardScaler
from p4runtime_switch import P4RuntimeSwitchConnection
import argparse

parser = argparse.ArgumentParser(description="Run the local classifier on the P4 switch.")
parser.add_argument('--switch_id', required=True, help='Switch identifier (e.g., S1)')
parser.add_argument('--thrift_port', type=int, required=True, help='Thrift port of the switch (e.g., 9091)')
args = parser.parse_args()

CSV_OUTPUT = "clients_flows.csv"
TXT_OUTPUT = "classification_results.txt"
TRAINED_MODEL = "trained_rf_model.joblib"
PLATT_SCALER = "platt_scaler.joblib"

local_trust = defaultdict(lambda: 0.5)
last_update = dict()

ALPHA = 0.5
DECAY = 0.9
MONITORING_INTERVAL = 15

def classify_flows():
    conn = P4RuntimeSwitchConnection(name=args.switch_id, address=f"127.0.0.1:{args.thrift_port}", device_id=0)
    conn.master_arbitration_update()
    conn.set_forwarding_pipeline_config(p4info_path="build/p4info.txt", bmv2_json_path="build/switch.json")

    flows = []
    for index in range(1024):
        try:
            fwd_packets = conn.read_register("reg_total_fwd_packets", index)
            bwd_packets = conn.read_register("reg_total_bwd_packets", index)
            len_fwd = conn.read_register("reg_total_len_fwd", index)
            len_bwd = conn.read_register("reg_total_len_bwd", index)
            total_len = conn.read_register("reg_packet_total_len", index)
            pkt_count = conn.read_register("reg_packet_count", index)
            syn_count = conn.read_register("reg_syn_count", index)
            rst_count = conn.read_register("reg_rst_count", index)
            ack_count = conn.read_register("reg_ack_count", index)
            urg_count = conn.read_register("reg_urg_count", index)
            fwd_header = conn.read_register("reg_fwd_header_length", index)
            bwd_header = conn.read_register("reg_bwd_header_length", index)
            fwd_iat = conn.read_register("reg_fwd_iat_total", index)
            bwd_iat = conn.read_register("reg_bwd_iat_total", index)

            pkt_len_mean = total_len / pkt_count if pkt_count > 0 else 0
            fwd_pkt_s = fwd_packets / pkt_count if pkt_count > 0 else 0
            bwd_pkt_s = bwd_packets / pkt_count if pkt_count > 0 else 0
            fwd_iat_mean = fwd_iat / fwd_packets if fwd_packets > 0 else 0
            bwd_iat_mean = bwd_iat / bwd_packets if bwd_packets > 0 else 0
            protocolo = 6

            flow = [
                fwd_packets, bwd_packets, len_fwd, len_bwd,
                fwd_pkt_s + bwd_pkt_s, pkt_len_mean,
                fwd_iat, fwd_iat_mean, bwd_iat, bwd_iat_mean,
                fwd_header, bwd_header, fwd_pkt_s, bwd_pkt_s,
                pkt_len_mean, syn_count, rst_count, ack_count, urg_count,
                protocolo
            ]
            flows.append(flow)
        except:
            continue

    header = [
        "TotalFwdPackets", "TotalBwdPackets", "TotalLenFwd", "TotalLenBwd",
        "FlowPacketsPerSec", "PacketLengthMean", "FwdIATTotal", "FwdIATMean",
        "BwdIATTotal", "BwdIATMean", "FwdHeaderLen", "BwdHeaderLen",
        "FwdPacketsPerSec", "BwdPacketsPerSec", "PacketLengthMeanRe",
        "SYNCount", "RSTCount", "ACKCount", "URGCount", "Protocol"
    ]

    with open(CSV_OUTPUT, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(flows)

    model = joblib.load(TRAINED_MODEL)
    scaler = joblib.load(PLATT_SCALER)
    df = pd.read_csv(CSV_OUTPUT)

    normalizer = StandardScaler()
    X_norm = normalizer.fit_transform(df)

    predictions = model.predict(X_norm)
    confidences = scaler.predict_proba(X_norm)[:, 1]

    client_ips = [f"10.0.0.{i%10 + 1}" for i in range(len(predictions))]

    with open(TXT_OUTPUT, "w") as f:
        for i, (label, conf) in enumerate(zip(predictions, confidences)):
            tipo = "LEGITIMATE" if label == 1 else "MALICIOUS"
            f.write(f"Flow {i}: {tipo}, Trust = {conf:.4f}\n")
            if label == 0:
                print("[ALERT] Malicious traffic detected!")
                with open("malicious_ips.log", "a") as log:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log.write(f"[{timestamp}] Malicious flow detected from client {client_ips[i]} with confidence {conf:.4f}")
                try:
                    ip_parts = list(map(int, client_ips[i].split(".")))
                    ip_int = (ip_parts[0] << 24) + (ip_parts[1] << 16) + (ip_parts[2] << 8) + ip_parts[3]
                    conn.write_register("reg_classification", ip_int, 2)
                    print(f"[INFO] IP {client_ips[i]} blocked via reg_classification.")
                except Exception as e:
                    print(f"[ERROR] Failed to send block to the switch: {e}")

    client_flows = list(zip(client_ips, confidences))
    update_local_trust(client_flows)

def update_local_trust(client_flows):
    global local_trust, last_update

    now = datetime.now()
    legitimate_clients = []

    for ip, flow_trust in client_flows:
        previous = local_trust[ip]
        new_trust = ALPHA * flow_trust + (1 - ALPHA) * previous
        local_trust[ip] = new_trust
        last_update[ip] = now
        if new_trust > 0.5:
            legitimate_clients.append(new_trust)

    for ip in list(local_trust.keys()):
        if ip not in dict(client_flows):
            last = last_update.get(ip, now)
            if (now - last).total_seconds() > MONITORING_INTERVAL:
                local_trust[ip] *= DECAY
                last_update[ip] = now

    trust_threshold = sum(legitimate_clients) / len(legitimate_clients) if legitimate_clients else 0.5

    try:
        conn = P4RuntimeSwitchConnection(name=args.switch_id, address=f"127.0.0.1:{args.thrift_port}", device_id=0)
        conn.master_arbitration_update()
        conn.set_forwarding_pipeline_config(p4info_path="build/p4info.txt", bmv2_json_path="build/switch.json")

        for ip, value in local_trust.items():
            conn.write_register("reg_conf_local", ip, int(value * 1000))

        conn.write_register("reg_limiar_conf", 0, int(trust_threshold * 1000))
        print(f"[OK] Local trust values and threshold sent to switch.")
    except Exception as e:
        print(f"[ERROR] Failed to send to switch: {e}")

    return local_trust, trust_threshold

if __name__ == "__main__":
    classify_flows()
