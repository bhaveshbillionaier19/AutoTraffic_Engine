# AutoTraffic_Engine

## Overview

This project implements a kernel-level network telemetry system using eBPF and Linux Traffic Control (TC) to monitor network traffic in real time. An eBPF program attached to TC ingress and egress captures packets, extracts flow-level information (IP, ports, protocol), and maintains per-flow statistics inside a pinned BPF map in the kernel. A user-space collector reads this telemetry periodically and computes real-time network state metrics such as active flows, protocol distribution, and traffic rates. These metrics represent the current network state and are intended to serve as input for an adaptive traffic control system. In the complete framework, a Reinforcement Learning (RL) controller will use this telemetry to dynamically optimize network traffic management.

## Setup and Run Telemetry
**1. Install Dependencies**
```bash
sudo apt update
sudo apt install clang llvm libbpf-dev gcc make iproute2 bpftool
```
Kernel 5.x or newer is recommended.

**2. Build the eBPF Program**

Navigate to the eBPF directory:
```bash
cd ebpf
```

Compile the telemetry program:
```bash
clang -O2 -g -target bpf -c telemetry.bpf.c -o telemetry.o
```

**3. Attach the eBPF Program**

Find your network interface:
```bash
ip a
```

Example interface:
```bash
wlp1s0
```
Remove any existing TC hook:
```bash
sudo tc qdisc del dev wlp1s0 clsact 2>/dev/null
```
Add TC hook:
```bash
sudo tc qdisc add dev wlp1s0 clsact
```
Attach the telemetry program.

Ingress:
```bash
sudo tc filter add dev wlp1s0 ingress \
bpf da obj telemetry.o sec classifier
```
Egress:
```bash
sudo tc filter add dev wlp1s0 egress \
bpf da obj telemetry.o sec classifier
```
Verify attachment:
```bash
tc filter show dev wlp1s0 ingress
tc filter show dev wlp1s0 egress
```
**4. Build the Collector**

Navigate to the collector directory:
```bash
cd ../collector
```
Compile the collector:
```bash
gcc collector.c -lbpf -o collector
```

**5. Run the Telemetry Collector**

Run with root privileges:
```bash
sudo ./collector
```
Example output:

<img width="266" height="248" alt="image" src="https://github.com/user-attachments/assets/ff552a5c-791a-40cf-8fc3-ca0cffc12766" />

**6. Generate Traffic for Testing**

Generate traffic using:
```bash
ping google.com
```
or
```bash
curl https://google.com
```
The collector output should update as traffic flows through the interface.

## Future Work

- **Reinforcement Learning Integration**  
  Integrate a reinforcement learning (RL) agent that consumes the real-time network state metrics produced by the collector and learns optimal traffic control policies.

- **Dynamic Traffic Control Policies**  
  Use the RL decisions to dynamically adjust Linux Traffic Control (TC) parameters such as queue disciplines, priorities, or rate limits.

- **Expanded Telemetry Features**  
  Extend the telemetry program to capture additional metrics such as latency indicators, flow duration, or queue statistics to provide richer state information.

- **Visualization and Monitoring**  
  Develop dashboards or visualization tools to monitor network state metrics and system behavior in real time.
