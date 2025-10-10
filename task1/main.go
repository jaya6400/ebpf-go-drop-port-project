package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: sudo go run main.go <network-interface>")
		fmt.Println("Example: sudo go run main.go eth0")
		os.Exit(1)
	}

	ifaceName := os.Args[1]

	// Load eBPF object
	spec, err := ebpf.LoadCollectionSpec("drop_4040.o")
	if err != nil {
		log.Fatalf("loading spec: %v", err)
	}

	objs := struct {
		XdpDrop *ebpf.Program `ebpf:"xdp_drop_4040"`
	}{}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.XdpDrop.Close()

	// Get network interface
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("get iface: %v", err)
	}

	// Attach XDP program
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpDrop,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("attach xdp: %v", err)
	}
	defer l.Close()

	fmt.Printf("✅ eBPF attached to %s — Dropping all packets\n", ifaceName)
	fmt.Println("Press Ctrl+C to stop...")
	select {}
}
