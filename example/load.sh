#!/usr/bin/env bash

set -e

OPT=""
if [[ "-v" == "$1" ]]
then
    OPT="verbose"
fi

./build.sh
sudo ip link set enp4s0 xdp off
sudo ip link set enp4s0 xdp object target/bpfel-unknown-none/debug/xdp-hello section xdp $OPT
sudo cat /sys/kernel/debug/tracing/trace_pipe
