// main.go
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

	// Load compiled BPF object
	spec, err := ebpf.LoadCollectionSpec("drop_process.o")
	if err != nil {
		log.Fatalf("loading spec: %v", err)
	}

	objs := struct {
		XdpDropProcess *ebpf.Program `ebpf:"xdp_drop_process"`
	}{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.XdpDropProcess.Close()

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("get iface: %v", err)
	}

	// Attach XDP program
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpDropProcess,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("attach xdp: %v", err)
	}
	defer l.Close()

	fmt.Printf("✅ eBPF program attached to %s — Allowing only port 4040 for myprocess\n", ifaceName)
	fmt.Println("Press Ctrl+C to stop...")
	select {}
}
