from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.metrics import classification_report, accuracy_score
import time
import struct
import skfuzzy as fuzz
from skfuzzy import control as ctrl
import argparse


window_counter = 0  # packet counter for observation window
parser = argparse.ArgumentParser(description="Controller RYU.")
parser.add_argument('--controller_name', default='DataControl-ML', help='Controller RYU')
args = parser.parse_args()

class MLTrainingController(app_manager.RyuApp):  #training model for sending to switches
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MLTrainingController, self).__init__(*args, **kwargs)
        self.model_output_path = "trained_rf_model.joblib"
        self.dataset_path = "traffic_dataset.csv"
        self.train_model()

    def train_model(self):
        self.logger.info("Training model")

        feature_columns = [
            "Flow Duration", "Total Fwd Packets", "Total Bwd Packets", "Total Length of Fwd Packets",
            "Total Length of Bwd Packets", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
            "Fwd IAT Total", "Fwd IAT Mean", "Bwd IAT Total", "Bwd IAT Mean",
            "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
            "Packet Length Mean", "SYN Flag Count", "RST Flag Count", "ACK Flag Count",
            "URG Flag Count", "Idle Mean"
        ]

        try:
            df = pd.read_csv(self.dataset_path)
            X = df[feature_columns]
            y = df["Label"]

            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.3, random_state=42, stratify=y
            )

            param_dist = {
                "n_estimators": [10, 100, 200],
                "max_depth": [None, 6, 10, 20],
                "max_features": ["log2", "sqrt"],
                "min_samples_split": [2, 6, 10],
                "min_samples_leaf": [1, 2, 4],
                "bootstrap": [True, False]
            }

            rf = RandomForestClassifier(random_state=42)
            search = RandomizedSearchCV(rf, param_distributions=param_dist, n_iter=10, cv=5, verbose=1, n_jobs=-1)
            search.fit(X_train, y_train)

            best_model = search.best_estimator_
            y_pred = best_model.predict(X_test)

            self.logger.info("Model evaluation:")
            self.logger.info("\n" + classification_report(y_test, y_pred))
            self.logger.info(f"Accuracy: {accuracy_score(y_test, y_pred)}")

            joblib.dump(best_model, self.model_output_path)
            self.logger.info(f"Model saved in: {self.model_output_path}")
        except Exception as e:
            self.logger.error(f"Error during training: {e}")

@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
def _handle_packet_in(self, ev): #data extraction
    msg = ev.msg    
    datapath = msg.datapath
    ofp = datapath.ofproto
    parser = datapath.ofproto_parser
    self.client_trust_table = {}  
    self.global_calc_interval = 30  
    self.last_global_calc_time = time.time()

    pkt = packet.Packet(msg.data)
    ip = pkt.get_protocol(ipv4.ipv4)

    if ip:
        client_ip = ip.src
        trust_value = _extract_trust_from_payload(msg.data)

        if client_ip not in self.client_trust_table:
            self.client_trust_table[client_ip] = []

        self.client_trust_table[client_ip].append(trust_value)

        now = time.time()
        if now - self.last_global_calc_time >= self.global_calc_interval:
            self.logger.info("Add global trust calculation...")
            calculate_global_trust(self)
            self.last_global_calc_time = now

def _extract_trust_from_payload(raw_data): #Extract payload from report packet
    if len(raw_data) >= 4:
        return struct.unpack("!I", raw_data[-4:])[0] / 1000.0
    return 0.0

def calculate_global_trust(self): #calculate global confidence
    ip_result_list = []

    local_trust = ctrl.Antecedent(np.arange(0, 1.01, 0.01), 'local_trust')
    global_trust = ctrl.Consequent(np.arange(0, 1.01, 0.01), 'global_trust')

    local_trust['low'] = fuzz.trapmf(local_trust.universe, [0, 0, 0.2, 0.5])
    local_trust['middle'] = fuzz.trimf(local_trust.universe, [0.2, 0.5, 0.8])
    local_trust['high'] = fuzz.trapmf(local_trust.universe, [0.5, 0.8, 1, 1])

    global_trust['not_trustworthy'] = fuzz.trapmf(global_trust.universe, [0, 0, 0.2, 0.4])
    global_trust['partially_trusted'] = fuzz.trapmf(global_trust.universe, [0.2, 0.4, 0.6, 0.8])
    global_trust['trustworthy'] = fuzz.trapmf(global_trust.universe, [0.6, 0.8, 1, 1])

    rule1 = ctrl.Rule(local_trust['low'], global_trust['not_trustworthy'])
    rule2 = ctrl.Rule(local_trust['middle'], global_trust['partially_trusted'])
    rule3 = ctrl.Rule(local_trust['high'], global_trust['trustworthy'])

    system = ctrl.ControlSystem([rule1, rule2, rule3])
    simulation = ctrl.ControlSystemSimulation(system)

    for ip, values in self.client_trust_table.items(): #receives local trust values
        if values:
            media_local = sum(values) / len(values)
            simulation.input['local_trust'] = media_local
            simulation.compute()
            out = simulation.output['global_trust']

            if out < 0.4:
                classes = "not_trustworthy"
            elif out < 0.8:
                classes = "partially_trusted"
            else:
                classes = "trustworthy"

            ip_result_list.append((ip, round(out, 3), classes))
            self.logger.info(f"Client {ip} -> Global Trust: {out:.3f}, Class: {classes}")

    self.global_trust_result = pd.DataFrame(ip_result_list, columns=["IP", "Global Trust", "Classification"])
    disseminate_control_data(self)



def disseminate_control_data(self):
    try:
        for dp in self.dpset.get_all():
            datapath = dp.dp
            ofp = datapath.ofproto
            parser = datapath.ofproto_parser

            report = b''
            for _, row in self.global_trust_result.iterrows():
                ip_str = row["IP"]
                classification = row["Classification"]

                #control action
                if classification == "trustworthy":
                    action_code = 1
                elif classification == "partially_trusted":
                    action_code = 0
                else:
                    action_code = 2

                ip_bytes = bytes(map(int, ip_str.split(".")))
                report += ip_bytes + bytes([action_code])

            #dissemination packet
            pkt = packet.Packet()
            eth = ethernet.ethernet(dst="ff:ff:ff:ff:ff:ff", src="00:00:00:00:00:01", ethertype=0x0800)
            ipv4_pkt = ipv4.ipv4(dst="255.255.255.255", src="10.0.0.254", proto=253)
            pkt.add_protocol(eth)
            pkt.add_protocol(ipv4_pkt)
            pkt.serialize()

            data = pkt.data + report

            actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofp.OFP_NO_BUFFER,
                in_port=ofp.OFPP_CONTROLLER,
                actions=actions,
                data=data
            )
            datapath.send_msg(out)

        self.logger.info("Dissemination packet sent with all aggregated data.")
    except Exception as e:
        self.logger.error(f"Error disseminating aggregated packet: {e}")
