#!/bin/bash
SCRIPT_PATH="/opt/intel/oneapi/vtune/latest/sepdk/src"

echo 'Sourcing vars'

source /opt/intel/oneapi/setvars.sh
cd "$SCRIPT_PATH"

echo 'Building drivers'
. "build-driver" -ni

echo 'Setup kernel vars'
sudo sh -c "echo 0 > /proc/sys/kernel/kptr_restrict"
sudo sysctl -w kernel.perf_event_paranoid=0
sudo sh -c "echo 0 > /proc/sys/kernel/yama/ptrace_scope" 
