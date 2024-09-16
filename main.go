package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/namsral/flag"

	// add profiler
	"net/http"
	_ "net/http/pprof"
)

type cfg struct {
	Iface          string
	Address        string
	DBType         string
	DSN            string
	Workers        int
	Retries        int
	MaxQueueLength int
}

func main() {
	var cfg cfg

	flag.StringVar(&cfg.Iface, "interface", "", "Interface to capture packets on")
	flag.StringVar(&cfg.Address, "address", "", "Address to discover interface to capture packets on. Takes precedence over interface")
	flag.StringVar(&cfg.DBType, "dbtype", "postgres", "Database type")
	flag.StringVar(&cfg.DSN, "dsn", "", "Database DSN")
	flag.IntVar(&cfg.Workers, "workers", 4, "Number of goroutines handling packets")
	flag.IntVar(&cfg.Retries, "retries", 30, "Retry count for sql operations")
	flag.IntVar(&cfg.MaxQueueLength, "max-queue-length", 1000, "Maximum number of dhcp packets to hold in queue")
	flag.Parse()

	if cfg.Iface == "" && cfg.Address == "" {
		panic(fmt.Errorf("no interface or address specified"))
	}

	if cfg.Address != "" {
		var err error
		cfg.Iface, err = findInterfaceByAddress(cfg.Address)
		if err != nil {
			panic(err)
		}
	}

	// start profiler
	go func() {
		log.Println(http.ListenAndServe("0.0.0.0:6060", nil))
	}()

	feeder, err := newFeeder(cfg.DBType, cfg.DSN, cfg.MaxQueueLength, cfg.Retries)
	if err != nil {
		panic(err)
	}

	feeder.Run(cfg.Workers)
	defer feeder.Close()

	handle, err := pcap.OpenLive(cfg.Iface, 1600, true, time.Second)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	// Filter for bootp reply packets
	if err := handle.SetBPFFilter("udp and (src port 67 or src port 68)"); err != nil {
		panic(err)
	}

	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	pchan := ps.Packets()

	termsig := make(chan os.Signal, 1)
	signal.Notify(termsig, syscall.SIGTERM, syscall.SIGINT)

LOOP:
	for {
		select {
		case raw := <-pchan:
			select {
			case feeder.queue <- raw:
			default:
				log.Println("queue overflow")
			}
		case <-termsig:
			break LOOP
		}
	}

	fmt.Println("exiting...")
}

func findInterfaceByAddress(ipAddress string) (string, error) {
	targetIP := net.ParseIP(ipAddress)
	if targetIP == nil {
		return "", fmt.Errorf("invalid IP address: %s", ipAddress)
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addresses {
			var ip net.IP

			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip.Equal(targetIP) {
				return iface.Name, nil
			}
		}
	}

	return "", fmt.Errorf("no interface found for IP address: %s", ipAddress)
}
