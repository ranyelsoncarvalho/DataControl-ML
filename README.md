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
