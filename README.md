This repository contains the implementation of Asynchronous Traffic Shaper (ATS) and Time-Aware Shaper (TAS) using eBPF, proving the possibility of traffic shaping using eBPF in Time-Sensitive Networking (TSN) scenarios.

## Content
- Custom modifications to the `bpf-next` kernel to support advanced TSN features.
- Implementation of ATS and TAS logic within the eBPF/qdisc layer.

## Repository Structure
- `bpf-progs/`: Core eBPF source code for ATS and TAS shapers.
- `kernel-patches/`: `.patch` files for the `bpf-next` Linux kernel.

## How to Apply
1. Clone and Patch Kernel:
   ```bash
   git clone [https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git](https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git)
   cd bpf-next
   git checkout 8efa26fcbf8a7f783fd1ce7dd2a409e9b7758df0
   git am ../kernel-patches/0001-bpf-net-Implement-eBPF-based-Asynchronous-Traffic-Sh.patch
   make, install and reboot with the new kernel
2. Compile, Register and attach eBPF programs:
   ```bash
   cd tools/testing/selftests/bpf/
   make
   sudo bpftool struct_ops register bpf_qdisc_ats.o /sys/fs/bpf
   sudo tc qdisc add dev eth0 root handle 1:0 bpf_ats
3. Remove and unregister:
   ```bash
   sudo tc qdisc delete dev eth0 root
   sudo bpftool struct_ops unregister name bpf_ats

## About the Author 
Zixi Cai Master's student at Lanzhou University, focusing on Linux kernel networking, eBPF, and Time-Sensitive Networking (TSN).
