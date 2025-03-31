package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/google/gopacket"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/iana"
	_ "github.com/lib/pq"
)

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 125 || s[i] < 32 {
			return false
		}
	}
	return true
}

// Feeder parses & feeds received packets to SQL
type Feeder struct {
	db   *sql.DB
	stmt *sql.Stmt

	queue   chan gopacket.Packet
	workers sync.WaitGroup
	retries int
}

// hack to avoid json marshalling byte[] into base64 strings
type CustomDHCPPacket struct {
	OpCode         dhcpv4.OpcodeType
	HWType         iana.HWType
	HopCount       uint8
	TransactionID  dhcpv4.TransactionID
	NumSeconds     uint16
	Flags          uint16
	ClientIPAddr   net.IP
	YourIPAddr     net.IP
	ServerIPAddr   net.IP
	GatewayIPAddr  net.IP
	ClientHWAddr   string // stringified
	ServerHostName string
	BootFileName   string
	Options        map[uint8]string //stringified
}

func (c *CustomDHCPPacket) New(d *dhcpv4.DHCPv4) {
	c.OpCode = d.OpCode
	c.HWType = d.HWType
	c.HopCount = d.HopCount
	c.TransactionID = d.TransactionID
	c.NumSeconds = d.NumSeconds
	c.Flags = d.Flags
	c.ClientIPAddr = d.ClientIPAddr
	c.YourIPAddr = d.YourIPAddr
	c.ServerIPAddr = d.ServerIPAddr
	c.GatewayIPAddr = d.GatewayIPAddr
	c.ClientHWAddr = d.ClientHWAddr.String()
	c.ServerHostName = d.ServerHostName
	c.BootFileName = d.BootFileName
	c.Options = make(map[uint8]string)
	for i, option := range d.Options {
		strOption := string(option)
		if isASCII(strOption) {
			c.Options[i] = strOption
		} else {
			full := fmt.Sprint(option)
			c.Options[i] = full[1 : len(full)-1]
		}
	}
}

func (c *CustomDHCPPacket) ToBytes() ([]byte, error) {
	return json.Marshal(c)
}

// New instantiates a new Feeder
func newFeeder(dbType string, dsn string, maxQueueLength int, retries int) (*Feeder, error) {
	db, err := sql.Open(
		dbType,
		dsn,
	)

	if err != nil {
		return nil, err
	}

	// create table if it doesn't exist
	switch dbType {
	case "postgres":
		_, err = db.Exec(`
			CREATE TABLE IF NOT EXISTS dhcp_packets (
				id BIGSERIAL PRIMARY KEY,
				ts TIMESTAMPTZ DEFAULT current_timestamp,
				packet JSON
			)
		`)
	case "mysql":
		_, err = db.Exec(`CREATE TABLE IF NOT EXISTS dhcp_packets (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    ts TIMESTAMP DEFAULT current_timestamp(),
	packet JSON
	)`)
	default:
		return nil, fmt.Errorf("unknown database type: %s", dbType)
	}

	if err != nil {
		db.Close()
		return nil, err
	}

	// create index if it doesn't exist
	switch dbType {
	case "postgres":
		db.Exec("CREATE INDEX IF NOT EXISTS ON dhcp_packets(ts)")
	case "mysql":
		db.Exec("CREATE INDEX ON dhcp_packets(ts)")
	default:
		return nil, fmt.Errorf("unknown database type: %s", dbType)
	}

	var insert string
	switch dbType {
	case "postgres":
		insert = `INSERT INTO dhcp_packets (packet) VALUES ($1)`
	case "mysql":
		insert = `INSERT INTO dhcp_packets (packet) VALUES (?)`
	default:
		return nil, fmt.Errorf("unknown database type: %s", dbType)
	}

	stmt, err := db.Prepare(insert)
	if err != nil {
		db.Close()
		return nil, err
	}

	return &Feeder{
		db:      db,
		stmt:    stmt,
		queue:   make(chan gopacket.Packet, maxQueueLength),
		retries: retries,
	}, nil
}

// Close closes feeder
func (f *Feeder) Close() {
	close(f.queue)
	f.workers.Wait()
	f.stmt.Close()
	f.db.Close()
}

// Run starts the specified number of workers
func (f *Feeder) Run(workers int) {
	f.workers.Add(workers)
	for i := 0; i < workers; i++ {
		go f.worker()
	}
}

func (f *Feeder) worker() {
	defer f.workers.Done()

	for packet := range f.queue {
		f.processPacket(packet)
	}
}

func (f *Feeder) processPacket(packet gopacket.Packet) {
	dhcpPacket, err := dhcpv4.FromBytes(packet.TransportLayer().LayerPayload())
	if err != nil {
		fmt.Println("error parsing packet:", err)
		return
	}

	log.Println(dhcpPacket)

	customPacket := CustomDHCPPacket{}
	customPacket.New(dhcpPacket)
	buf, err := customPacket.ToBytes()
	if err != nil {
		fmt.Println("error marshalling packet:", err)
		return
	}

	i := 0
	for i < f.retries {
		_, err := f.stmt.Exec(buf)
		if err == nil {
			return
		} else {
			log.Println("error inserting packet:", err)
		}
		time.Sleep(time.Second)
		i++
	}
	log.Printf("max retries exhausted, dropping packet\n")
}
