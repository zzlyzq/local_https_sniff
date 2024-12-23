package main

import (
    "bufio"
    "crypto/tls"
    "fmt"
    "io"
    "log"
    "net"
    "os"
    "strconv"
    "strings"
    "time"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

var (
    snapshotLen int32         = 65536
    promiscuous bool          = false
    err         error
    timeout     time.Duration = 30 * time.Second
    handle      *pcap.Handle
    logger      *log.Logger
)

func main() {
    logFile, err := os.OpenFile("https_log.txt", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
    if err != nil {
        log.Fatal(err)
    }
    defer logFile.Close()

    logger = log.New(io.MultiWriter(os.Stdout, logFile), "", log.LstdFlags)
    logger.SetPrefix("\xEF\xBB\xBF")

    devices, err := pcap.FindAllDevs()
    if err != nil {
        logger.Fatal(err)
    }

    fmt.Println("Available network interfaces:")
    for i, device := range devices {
        fmt.Printf("%d. %s\n", i+1, device.Name)
    }

    fmt.Print("Enter the number of the interface to listen on: ")
    reader := bufio.NewReader(os.Stdin)
    input, _ := reader.ReadString('\n')
    input = strings.TrimSpace(input)

    index, err := strconv.Atoi(input)
    if err != nil || index < 1 || index > len(devices) {
        logger.Fatal("Invalid interface number")
    }

    device := devices[index-1]
    logger.Print("Starting packet capture:\n")

    handle, err = pcap.OpenLive(device.Name, snapshotLen, promiscuous, timeout)
    if err != nil {
        logger.Fatal(err)
    }
    defer handle.Close()

    err = handle.SetBPFFilter("tcp port 443")
    if err != nil {
        logger.Fatal(err)
    }

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
            tcp, _ := tcpLayer.(*layers.TCP)
            if tcp.SrcPort == 443 || tcp.DstPort == 443 {
                ipLayer := packet.Layer(layers.LayerTypeIPv4)
                ip, _ := ipLayer.(*layers.IPv4)
                
                // 创建TLS连接
                conn, err := tls.Dial("tcp", net.JoinHostPort(ip.DstIP.String(), strconv.Itoa(int(tcp.DstPort))), &tls.Config{
                    InsecureSkipVerify: true,
                })
                if err != nil {
                    continue
                }
                defer conn.Close()

                // 获取TLS连接状态
                state := conn.ConnectionState()

                logger.Printf("HTTPS Connection: %s:%d -> %s:%d\n", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)
                logger.Printf("TLS Version: %x\n", state.Version)
                logger.Printf("Cipher Suite: %s\n", tls.CipherSuiteName(state.CipherSuite))
                
                if len(state.PeerCertificates) > 0 {
                    cert := state.PeerCertificates[0]
                    logger.Printf("Server Name: %s\n", cert.Subject.CommonName)
                    logger.Printf("Issuer: %s\n", cert.Issuer.CommonName)
                    logger.Printf("Not Before: %s\n", cert.NotBefore)
                    logger.Printf("Not After: %s\n", cert.NotAfter)
                }

                logger.Println("--------------------")
            }
        }
    }
}
