package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const (
	maxBackends = 16
	ringSize    = 256
)

type Backend struct {
	IP     uint32
	Port   uint16
	Active uint16
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	objs := mainObjects{}
	if err := loadMainObjects(&objs, nil); err != nil {
		log.Fatal("Loading BPF objects:", err)
	}
	defer objs.Close()

	// Get interface
	ifaceName := "lo"
	if len(os.Args) > 1 {
		ifaceName = os.Args[1]
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Interface %s not found: %v", ifaceName, err)
	}

	// Set load balancer port
	var port uint32
	fmt.Print("Enter port to load balance (e.g., 8080): ")
	fmt.Scanln(&port)

	key := uint32(0)
	if err := objs.LbPort.Update(key, port, 0); err != nil {
		log.Fatal("Setting LB port:", err)
	}

	// Attach XDP program
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.LbMain,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer l.Close()

	fmt.Printf("\n=== L4 Load Balancer Started ===\n")
	fmt.Printf("Interface: %s | Port: %d\n\n", ifaceName, port)

	// Initialize hash ring (all point to backend 0 initially)
	initHashRing(&objs)

	// Command loop
	go commandLoop(&objs)

	// Stats ticker
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			printStats(&objs)
		case <-stop:
			fmt.Println("\nShutting down...")
			return
		}
	}
}

func initHashRing(objs *mainObjects) {
	// Initialize entire ring to backend 0
	for i := uint32(0); i < ringSize; i++ {
		objs.HashRing.Update(i, uint32(0), 0)
	}
}

func rebuildHashRing(objs *mainObjects) {
	// Collect active backends
	var activeBackends []uint32
	for i := uint32(0); i < maxBackends; i++ {
		var be Backend
		if err := objs.Backends.Lookup(i, &be); err == nil && be.Active == 1 && be.IP != 0 {
			activeBackends = append(activeBackends, i)
		}
	}

	if len(activeBackends) == 0 {
		fmt.Println("Warning: No active backends!")
		return
	}

	// Distribute ring positions evenly among active backends
	// This is a simple consistent hash - each backend gets ringSize/numBackends positions
	for i := uint32(0); i < ringSize; i++ {
		backendIdx := activeBackends[i%uint32(len(activeBackends))]
		objs.HashRing.Update(i, backendIdx, 0)
	}

	fmt.Printf("Hash ring rebuilt with %d backends\n", len(activeBackends))
}

func commandLoop(objs *mainObjects) {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("Commands: add <ip>, remove <idx>, list, help")

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		switch parts[0] {
		case "add":
			if len(parts) < 2 {
				fmt.Println("Usage: add <ip>")
				continue
			}
			addBackend(objs, parts[1])
		case "remove":
			if len(parts) < 2 {
				fmt.Println("Usage: remove <index>")
				continue
			}
			removeBackend(objs, parts[1])
		case "list":
			listBackends(objs)
		case "help":
			fmt.Println("Commands:")
			fmt.Println("  add <ip>      - Add a backend server")
			fmt.Println("  remove <idx>  - Remove backend by index")
			fmt.Println("  list          - List all backends")
		default:
			fmt.Println("Unknown command. Type 'help' for usage.")
		}
	}
}

func addBackend(objs *mainObjects, ipStr string) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		fmt.Println("Invalid IP address")
		return
	}
	ip4 := ip.To4()
	if ip4 == nil {
		fmt.Println("IPv4 only")
		return
	}

	// Find empty slot
	for i := uint32(0); i < maxBackends; i++ {
		var be Backend
		if err := objs.Backends.Lookup(i, &be); err == nil && be.Active == 0 {
			be.IP = binary.LittleEndian.Uint32(ip4)
			be.Port = 0
			be.Active = 1

			if err := objs.Backends.Update(i, be, 0); err != nil {
				fmt.Printf("Error adding backend: %v\n", err)
				return
			}
			fmt.Printf("Added backend[%d]: %s\n", i, ipStr)
			rebuildHashRing(objs)
			return
		}
	}
	fmt.Println("No empty slots available")
}

func removeBackend(objs *mainObjects, idxStr string) {
	idx, err := strconv.ParseUint(idxStr, 10, 32)
	if err != nil || idx >= maxBackends {
		fmt.Println("Invalid index")
		return
	}

	be := Backend{IP: 0, Port: 0, Active: 0}
	if err := objs.Backends.Update(uint32(idx), be, 0); err != nil {
		fmt.Printf("Error removing backend: %v\n", err)
		return
	}
	fmt.Printf("Removed backend[%d]\n", idx)
	rebuildHashRing(objs)
}

func listBackends(objs *mainObjects) {
	fmt.Println("\n--- Backends ---")
	for i := uint32(0); i < maxBackends; i++ {
		var be Backend
		if err := objs.Backends.Lookup(i, &be); err == nil && be.Active == 1 {
			ip := make(net.IP, 4)
			binary.LittleEndian.PutUint32(ip, be.IP)
			fmt.Printf("[%d] %s (active)\n", i, ip.String())
		}
	}
	fmt.Println("----------------")
}

func printStats(objs *mainObjects) {
	fmt.Println("\n--- Connection Stats ---")
	hasStats := false
	for i := uint32(0); i < maxBackends; i++ {
		var be Backend
		var count uint64
		if err := objs.Backends.Lookup(i, &be); err == nil && be.Active == 1 {
			objs.ConnCount.Lookup(i, &count)
			ip := make(net.IP, 4)
			binary.LittleEndian.PutUint32(ip, be.IP)
			fmt.Printf("[%d] %s: %d connections\n", i, ip.String(), count)
			hasStats = true
		}
	}
	if !hasStats {
		fmt.Println("No active backends")
	}
	fmt.Println("------------------------")
}
