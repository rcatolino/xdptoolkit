#!/usr/bin/env bash

set -e

sudo ip link set enp4s0 xdp off
#sudo ip link set enp4s0 xdp object target/bpfel-unknown-none/debug/xdp-hello section xdp verbose
#sudo cat /sys/kernel/debug/tracing/trace_pipe
