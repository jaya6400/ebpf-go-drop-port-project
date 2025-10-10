package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// find PIDs by name
func findPIDsByName(name string) ([]int, error) {
	entries, err := ioutil.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}

		// check /proc/<pid>/comm
		commPath := filepath.Join("/proc", e.Name(), "comm")
		if b, err := ioutil.ReadFile(commPath); err == nil {
			comm := strings.TrimSpace(string(b))
			if comm == name {
				pids = append(pids, pid)
				continue
			}
		}

		// check /proc/<pid>/cmdline
		cmdPath := filepath.Join("/proc", e.Name(), "cmdline")
		if b, err := ioutil.ReadFile(cmdPath); err == nil && len(b) > 0 {
			parts := bytes.Split(b, []byte{0})
			for _, p := range parts {
				if len(p) == 0 {
					continue
				}
				if string(p) == name {
					pids = append(pids, pid)
					break
				}
			}
		}
	}
	if len(pids) == 0 {
		return nil, fmt.Errorf("no matching PIDs found")
	}
	return pids, nil
}

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: sudo go run main.go <network-interface> <process-name> <port>")
		os.Exit(1)
	}

	ifaceName := os.Args[1]
	processName := os.Args[2]
	port := os.Args[3]

	fmt.Printf("Looking for process name '%s' to populate the BPF map...\n", processName)
	pids, err := findPIDsByName(processName)
	if err != nil {
		log.Fatalf("finding PIDs for %s: %v", processName, err)
	}
	fmt.Printf("Found PIDs: %v\n", pids)

	// Load BPF object
	spec, err := ebpf.LoadCollectionSpec("drop_by_process_name.o")
	if err != nil {
		log.Fatalf("loading spec: %v", err)
	}

	objs := struct {
		XdpDropProcess *ebpf.Program `ebpf:"drop_by_process"`
		ProcessMap     *ebpf.Map     `ebpf:"process_map"`
	}{}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.XdpDropProcess.Close()
	defer objs.ProcessMap.Close()

	// Write PIDs to map
	for _, pid := range pids {
		k := uint32(pid)
		v := uint8(1)
		if err := objs.ProcessMap.Put(k, v); err != nil {
			log.Fatalf("failed to put pid %d into process_map: %v", pid, err)
		}
	}

	// Attach XDP
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("get iface: %v", err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpDropProcess,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("attach xdp: %v", err)
	}
	defer l.Close()

	fmt.Printf("✅ eBPF program attached to %s — Allowing only port %s for %s\n", ifaceName, port, processName)
	select {}
}
