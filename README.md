# DataControl-ML

## Requisites (P4 Environment + ML + Fuzzy + Thrift + RYU Controller)
Run the script below on an Ubuntu 16.04 LTS (or higher) system to prepare the environment:

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
