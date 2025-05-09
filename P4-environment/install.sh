#!/bin/bash
set -e

echo "=== Updating the system ==="
sudo apt update && sudo apt upgrade -y
sudo apt install -y git curl build-essential python3-pip python3-dev autoconf automake libtool cmake g++ unzip pkg-config libssl-dev default-jdk zip unzip flex bison

echo "=== Installing Python libraries (ML, Fuzzy, crcmod) ==="
pip3 install --upgrade pip
pip3 install scikit-learn scikit-fuzzy crcmod pandas joblib

echo "=== Installing Protobuf ==="
git clone https://github.com/protocolbuffers/protobuf.git
cd protobuf
git checkout v3.19.1
./autogen.sh
./configure
make -j$(nproc)
sudo make install
sudo ldconfig
cd ..

echo "=== Installing gRPC ==="
git clone --recurse-submodules -b v1.41.0 https://github.com/grpc/grpc
cd grpc
mkdir -p cmake/build
cd cmake/build
cmake ../..
make -j$(nproc)
sudo make install
sudo ldconfig
cd ../../../

echo "=== Installing Apache Thrift (version 0.13.0) ==="
sudo apt install -y libboost-all-dev
git clone https://github.com/apache/thrift.git
cd thrift
git checkout 0.13.0
./bootstrap.sh
./configure --with-python=python3
make -j$(nproc)
sudo make install
sudo ldconfig
cd ..

echo "=== Installing P4 compiler (p4c) ==="
git clone https://github.com/p4lang/p4c.git
cd p4c
mkdir build && cd build
cmake ..
make -j$(nproc)
sudo make install
cd ../..

echo "=== Installing BMv2 (P4 software switch) ==="
git clone https://github.com/p4lang/behavioral-model.git
cd behavioral-model
./install_deps.sh
./autogen.sh
./configure
make -j$(nproc)
sudo make install
cd ..

echo "=== Installing PI (P4Runtime Interface) ==="
git clone https://github.com/p4lang/PI.git
cd PI
git submodule update --init --recursive
./autogen.sh
./configure --with-proto
make -j$(nproc)
sudo make install
sudo ldconfig
cd ..

echo "=== Installing Mininet ==="
git clone https://github.com/mininet/mininet
cd mininet
sudo ./util/install.sh -a
cd ..

echo "=== Installing Tcpreplay (traffic replay tool) ==="
sudo apt install -y tcpreplay

echo "=== Installing RYU Controller ==="
git clone https://github.com/faucetsdn/ryu.git
cd ryu
sudo python3 setup.py install
cd ..

echo "=== Installation completed! P4 + RYU environment is ready ==="
