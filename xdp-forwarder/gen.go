package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel forwarder ./bpf/forwarder.c -- -I/usr/include/x86_64-linux-gnu
