package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	objs := mainObjects{}
	if err := loadMainObjects(&objs, nil); err != nil {
		log.Fatal("Loading main objects:", err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName("lo")
	if err != nil {
		log.Fatal("Failed to find lo interface : ", err)
	}

	var key uint32 = 0
	var port uint32
	fmt.Println("Enter port number to block: ")
	fmt.Scanln(&port)

	if err := objs.PortMap.Update(key, port, 0); err != nil {
		log.Fatal("Error updating PortMap: ", err)
	}
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.DropPacket,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Failed Attaching XDP: ", err)
	}
	defer l.Close()

	log.Printf("Blocking TCP packets on %d. CTRL+C to stop.\n", port)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
}
