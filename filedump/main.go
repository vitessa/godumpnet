package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

var (
	port         string
	SeqLocalAddr []net.IP
)

type tcpStream struct {
	network   gopacket.Flow
	transport gopacket.Flow
	r         tcpreader.ReaderStream
}

type tcpStreamFactory struct {
	MapConnect map[struct{ network, transport gopacket.Flow }]bool
	MtxConnect sync.Mutex
}

func (h *tcpStream) run() {
	reader := bufio.NewReader(&h.r)
	defer h.r.Close()

	// var buf bytes.Buffer
	md5 := md5.New()

	_, dst := h.transport.Endpoints()
	if dst.String() != port {
		io.Copy(io.Discard, reader)
		return
	}

	filename := fmt.Sprintf("%s.txt", time.Now().Format("2006-01-02-15-04-05"))
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		log.Fatal(err)
	}

	for {
		data := make([]byte, 20971520)
		var size int
		size, err := reader.Read(data[:1460])
		if size > 0 {
			// fmt.Println(hex.Dump(data[:size]))
			b, _ := hex.DecodeString(string(data[:size]))
			file.Write(b)
			md5.Write(data[:size])
		} else if err == io.EOF {
			log.Println("eof")
			break
		} else if err != nil {
			log.Fatalln(err)
		}
	}

	// fmt.Printf("len: %d\n", buf.Len())
	fmt.Printf("md5 %x\n", md5.Sum(nil))
	file.Close()
}

func (h *tcpStreamFactory) New(network, transport gopacket.Flow) tcpassembly.Stream {
	stream := &tcpStream{
		network:   network,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go stream.run()
	return &stream.r
}

func init() {
	ifs, err := net.Interfaces()
	if err != nil {
		return
	}

	for _, ifc := range ifs {
		// 判断是否启用
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}

		// 转换 IPv4 和 IPv6
		if addrs, err := ifc.Addrs(); err != nil {
			continue
		} else {
			for _, addr := range addrs {
				if ip, _, err := net.ParseCIDR(addr.String()); err == nil {
					SeqLocalAddr = append(SeqLocalAddr, ip)
				}
			}
		}
	}
}

func isLocalAddr(ip net.IP) bool {
	for _, addr := range SeqLocalAddr {
		if addr.Equal(ip) {
			return true
		}
	}
	return false
}

func openAllDevs() ([]*pcap.Handle, error) {

	ifs, err := pcap.FindAllDevs()
	if err != nil {
		return []*pcap.Handle{}, err
	} else if len(ifs) <= 0 {
		return []*pcap.Handle{}, errors.New("not find network device")
	}

	handles := []*pcap.Handle{}
	for _, ifc := range ifs {
		if len(ifc.Addresses) <= 0 {
			continue
		}

		inactive, err := pcap.NewInactiveHandle(ifc.Name)
		if err != nil {
			return []*pcap.Handle{}, err
		}
		defer inactive.CleanUp()

		// 配置
		if err := inactive.SetSnapLen(65535); err != nil {
			return []*pcap.Handle{}, err
		} else if err := inactive.SetPromisc(false); err != nil {
			return []*pcap.Handle{}, err
		} else if err := inactive.SetTimeout(pcap.BlockForever); err != nil {
			return []*pcap.Handle{}, err
		}

		// 激活
		handle, err := inactive.Activate() // after this, inactive is no longer valid
		if err != nil {
			return []*pcap.Handle{}, err
		}

		handles = append(handles, handle)
	}

	return handles, nil
}

func bpfFilter(srcAddr string, srcPort uint16, dstAddr string, dstPort uint16) (string, error) {
	dict := map[string]string{}
	dict["SrcAddr"] = srcAddr
	dict["SrcPort"] = strconv.Itoa(int(srcPort))
	dict["DstAddr"] = dstAddr
	dict["DstPort"] = strconv.Itoa(int(dstPort))

	// 模板
	tmpl, err := template.New("bpf").
		Parse("tcp and ((src host {{.SrcAddr}} and src port {{.SrcPort}} and dst host {{.DstAddr}} and dst port {{.DstPort}}) or (dst host {{.SrcAddr}} and dst port {{.SrcPort}} and src host {{.DstAddr}} and src port {{.DstPort}}))")
	if err != nil {
		return "", err
	}

	// 替换参数
	var b bytes.Buffer
	if err = tmpl.Execute(&b, dict); err != nil {
		log.Println(err.Error())
		return "", err
	}

	// BPF
	bpf := b.String()

	return bpf, nil
}

func sniffBpf(bpf string, out chan<- gopacket.Packet, done <-chan struct{}) error {
	// 打开所有设备
	handles, err := openAllDevs()
	if err != nil {
		return err
	}

	// 判断数量
	if len(handles) <= 0 {
		return errors.New("not find active network device")
	}

	for _, handle := range handles {
		if err := handle.SetBPFFilter(bpf); err != nil {
			return err
		}

		go func(handle *pcap.Handle) {
			defer func() {
				// 异常处理
				if err := recover(); err != nil {
					log.Println("panic:", err)
				}
				// 关闭所有设备
				for _, handle := range handles {
					handle.Close()
				}
			}()

			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			packets := packetSource.Packets()
			for {
				select {
				case <-done:
					return
				case packet, ok := <-packets:
					if !ok {
						return
					}
					select {
					case <-done:
						return
					case out <- packet:
					}
				}
			}
		}(handle)
	}

	return nil
}

func parsePacket(packet gopacket.Packet) (srcAddr net.IP, dstAddr net.IP, tcp layers.TCP, payload gopacket.Payload, err error) {
	var (
		eth layers.Ethernet
		lb  layers.Loopback
		ip4 layers.IPv4
		ip6 layers.IPv6
	)

	dlc := gopacket.DecodingLayerContainer(gopacket.DecodingLayerArray(nil)).
		Put(&eth).
		Put(&lb).
		Put(&ip4).
		Put(&ip6).
		Put(&tcp).
		Put(&payload)
	decoded := []gopacket.LayerType{}

	for _, firstLayer := range [...]gopacket.LayerType{layers.LayerTypeEthernet, layers.LayerTypeLoopback} {
		// 开始解码
		decoder := dlc.LayersDecoder(firstLayer, gopacket.NilDecodeFeedback)
		if lt, e := decoder(packet.Data(), &decoded); e != nil {
			continue
		} else if lt != gopacket.LayerTypeZero {
			continue
		} else if len(decoded) <= 1 {
			continue
		}
	}

	if len(decoded) <= 1 {
		err = errors.New("PrasePacket error: decode failed")
		return
	}

	// 取地址
	for _, layerType := range decoded {
		switch layerType {
		case layers.LayerTypeIPv6:
			tcp.SetNetworkLayerForChecksum(&ip6)
			src, dst := ip6.NetworkFlow().Endpoints()
			srcAddr = src.Raw()
			dstAddr = dst.Raw()
		case layers.LayerTypeIPv4:
			tcp.SetNetworkLayerForChecksum(&ip4)
			src, dst := ip4.NetworkFlow().Endpoints()
			srcAddr = net.IPv4(src.Raw()[0], src.Raw()[1], src.Raw()[2], src.Raw()[3])
			dstAddr = net.IPv4(dst.Raw()[0], dst.Raw()[1], dst.Raw()[2], dst.Raw()[3])
		}
	}

	return
}

func init() {
	flag.StringVar(&port, "p", "8000", "tcp port")
	flag.Parse()
}

func main() {
	bpf := fmt.Sprintf("%s %s", "tcp and port", port)

	packets := make(chan gopacket.Packet)
	done := make(chan struct{})

	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)

		// 等待中断信号
		<-sigint
		log.Println("shutdown...")
		close(done)
	}()

	if err := sniffBpf(bpf, packets, done); err != nil {
		log.Fatalln(err)
	}

	// 数据流处理
	streamFactory := tcpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(&streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	streamFactory.MapConnect = make(map[struct{ network, transport gopacket.Flow }]bool)

	for {
		select {
		case <-done:
			return
		case packet, ok := <-packets:
			if !ok {
				return
			}

			srcAddr, _, tcp, _, err := parsePacket(packet)
			if err != nil {
				continue
			}

			// 本地地址，手动计算ChkSum
			if isLocalAddr(srcAddr) {
				tcp.BaseLayer.Contents[16], tcp.BaseLayer.Contents[17] = 0, 0
				if cs, err := tcp.ComputeChecksum(); err != nil {
					// 程序错误
					panic(err)
				} else {
					tcp.Checksum = cs
					tcp.BaseLayer.Contents[16] = byte(cs >> 8)
					tcp.BaseLayer.Contents[17] = byte(cs)
				}
			}

			// 校验 TCP 的 Checksum 字段
			if cs, err := tcp.ComputeChecksum(); err != nil {
				// 程序错误
				panic(err)
			} else if cs != 0 {
				// TCP 校验失败
				log.Println("check sum failed")
				continue
			}

			key := struct{ network, transport gopacket.Flow }{
				network:   packet.NetworkLayer().NetworkFlow(),
				transport: packet.TransportLayer().TransportFlow(),
			}

			// 新连接
			streamFactory.MtxConnect.Lock()
			if _, ok := streamFactory.MapConnect[key]; !ok {
				// 真实的三次握手
				if tcp.SYN {
					streamFactory.MapConnect[key] = true
				}
				// 中途连接的包，虚构一个三次握手
				if !tcp.SYN && len(tcp.Payload) > 0 {
					pkt := tcp
					pkt.Seq -= 1
					pkt.SYN = true
					assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), &pkt, packet.Metadata().Timestamp)
					streamFactory.MapConnect[key] = true
				}
			}
			streamFactory.MtxConnect.Unlock()

			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), &tcp, packet.Metadata().Timestamp)
		}
	}
}
