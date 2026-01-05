package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// Remove swappable memory lock for this BPF program
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}
	
	objs := forwarderObjects{}
	if err := loadForwarderObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load BPF objects: %v", err)
	}
	defer objs.Close()
	
	// Attach XDP program to veth1 and veth2
	veth1, err := net.InterfaceByName("veth1")
	if err != nil {
		log.Fatalf("Failed to get veth1: %v", err)
	}
	l1, err := link.AttachXDP(link.XDPOptions{
		Program: objs.XdpForwarder,
		Interface: veth1.Index,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP to veth1: %v", err)
	}
	defer l1.Close()
	
	veth2, err := net.InterfaceByName("veth2")
	if err != nil {
		log.Fatalf("Failed to get veth2: %v", err)
	}
	l2, err := link.AttachXDP(link.XDPOptions{
		Program: objs.XdpForwarder,
		Interface: veth2.Index,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP to veth2: %v", err)
	}
	defer l2.Close()
	
	log.Printf("Attached XDP program to both veth1 (Index: %d) and veth2 (Index: %d).\nXDP Forwarder running... Press Ctrl+C to exit.", veth1.Index, veth2.Index)
	
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	
	<-stopper
	log.Println("Detaching and exiting...")
}