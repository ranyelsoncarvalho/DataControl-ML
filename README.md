# DataControl-ML

## Requisites (P4 Environment + ML + Fuzzy + Thrift + RYU Controller)
Run the script below on an [Ubuntu 16.04 LTS](https://ubuntu.com/16-04) system to prepare the environment:

```bash
wget https://github.com/ranyelsoncarvalho/DataControl-ML/raw/refs/heads/main/P4-environment/install.sh
chmod +x install.sh
./install.sh
```
## Script contents:
- Installation of:
- System libraries (g++, cmake, libtool, etc.)
- Python ML: `scikit-learn`, `scikit-fuzzy`, `crcmod`
- `protobuf`, `gRPC`, `Apache Thrift`
- `p4c` (P4 compiler)
- `behavioral-model` (BMv2 switch)
- `PI` (P4Runtime Interface)
- `Mininet`
- `tcpreplay` (to inject traffic from `.pcap`)
- `RYU Controller` (DataControl-ML main controller)

## Compile P4:
```bash
cd p4src
p4c-bm2-ss --arch v1model --target bmv2 -o build/ p4src/main.p4
```
## Run Mininet Topology:
```bash
sudo python3 topo.py
```

## Simulation Scenario: 
- The **DataControl-ML** engine is installed on switches **S1**, **S5**, and **S7**.
- Switch **S6** acts as an **ingress router**, receiving traffic from external hosts (`ext1` to `ext5`) and redirecting packets based on the destination IP address:
- `0.0.0.0/8` to `85.0.0.0/8` → **S1**
- `86.0.0.0/8` to `170.0.0.0/8` → **S7**
- `171.0.0.0/8` to `255.0.0.0/8` → **S5**
- Traffic can be legitimate or malicious, coming from external hosts via `.pcap` files played with `tcpreplay`.

## Run the P4 Switches:
For each switch, you must run the `simple_switch` command with the appropriate arguments:

### Example: Run switch S1
```bash
simple_switch --device-id 0 --thrift-port 9091 \
-i 1@eth1 -i 2@eth2 -i 3@eth3 \
build/main.json
```

### Example: Run switch S5
```bash
simple_switch --device-id 1 --thrift-port 9092 \
-i 1@eth4 -i 2@eth5 -i 3@eth6 \
build/main.json
```

### Example: Run switch S7
```bash
simple_switch --device-id 2 --thrift-port 9093 \
-i 1@eth7 -i 2@eth8 -i 3@eth9 \ 
build/main.json
```
> Adjust the `-i` interface names according to the order created by Mininet (use `ifconfig` or `ip link` to check).

### Important:
- The **S6** switch, responsible for IP-based routing, can also be a P4 switch. Start with:
```bash
simple_switch --device-id 3 --thrift-port 9096 \
-i 1@eth10 -i 2@eth11 -i 3@eth12 \
build/main.json
```
## Configure routes on S6

```bash
chmod +x configure_s6_routes.sh
./configure_s6_routes.sh
```
## Run the Classifier:
The `classification.py` code must be executed on **switches running the DataControl-ML engine**, that is, on switches **S1**, **S5** and **S7**.
### Example execution on a switch (e.g. S1):
```bash
python3 classification.py --switch_id S1 --thrift_port 9091
```

> Make sure to use distinct `thrift` ports for each switch, such as 9091, 9092, 9093.

## Run RYU Controller:
```bash
ryu-manager controller.py
```

## Inject traffic with `.pcap` files:
```bash
xterm ext1
tcpreplay --intf1=ext1-eth0 pcap/attack_s1.pcap
```

## Checks:
- `tcpdump` on target hosts
- RYU logs (global confidence, classification, dissemination)
- `classification_results.txt`
