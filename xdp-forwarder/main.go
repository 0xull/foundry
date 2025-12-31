package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	objs := forwarderObjects{}
	
	// loadForwarderObjects reads the .o file, parses the ELF sections,
	// and loads the "xdp_forwarder" program into the Kernel.
	if err := loadForwarderObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load BPF objects: %v", err)
	}
	defer objs.Close()

	veth1, err := net.InterfaceByName("veth1")
	if err != nil {
		log.Fatalf("Failed to get veth1: %v", err)
	}
	veth2, err := net.InterfaceByName("veth2")
	if err != nil {
		log.Fatalf("Failed to get veth2: %v", err)
	}
	
	// Attach to veth1
	l1, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpForwarder,
		Interface: veth1.Index,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP to veth1: %v", err)
	}
	defer l1.Close()
	log.Printf("Attached XDP program to veth1 (Index: %d)", veth1.Index)

	// Attach to veth2
	l2, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpForwarder,
		Interface: veth2.Index,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP to veth2: %v", err)
	}
	defer l2.Close()
	log.Printf("Attached XDP program to veth2 (Index: %d)", veth2.Index)

	log.Println("XDP Forwarder running... Press Ctrl+C to exit.")
	
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	
	<-stopper
	log.Println("Detaching and exiting...")
}