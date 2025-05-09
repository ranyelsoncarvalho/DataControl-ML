#!/bin/bash

# Script to configure routes on switch S6 via simple_switch_CLI

echo "Connecting to switch S6 (Thrift port 9096)..."

simple_switch_CLI --thrift-port 9096 << EOF

# Forward IPs from 0.0.0.0/8 to 85.0.0.0/8 to port 1 (Switch S1)
table_add ipv4_lpm ipv4_forward 0.0.0.0/8 => 1
table_add ipv4_lpm ipv4_forward 85.0.0.0/8 => 1

# Forward IPs from 86.0.0.0/8 to 170.0.0.0/8 to port 2 (Switch S7)
table_add ipv4_lpm ipv4_forward 86.0.0.0/8 => 2
table_add ipv4_lpm ipv4_forward 170.0.0.0/8 => 2

# Forward IPs from 171.0.0.0/8 to 255.0.0.0/8 to port 3 (Switch S5)
table_add ipv4_lpm ipv4_forward 171.0.0.0/8 => 3
table_add ipv4_lpm ipv4_forward 255.0.0.0/8 => 3

EOF

echo "Configuration completed."
