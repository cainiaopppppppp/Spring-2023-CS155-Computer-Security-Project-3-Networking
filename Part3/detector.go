/*
 * Stanford CS155 Project 3
 * Part 3. Anomaly Detection
 *
 * detector.go
 *
* 完成后并编译后，该程序将：
 *
 *  - 打开作为命令行参数提供的.pcap文件，并分析TCP、IP、以太网和ARP层
 *
 *  - 打印以下IP地址：1) 发送的SYN数据包数量是接收的SYN+ACK数据包数量的3倍以上，且
 *    2) 总共发送了超过5个SYN数据包的IP地址
 *
 *  - 打印发送超过5个未经请求的ARP应答的MAC地址
 *
*/

package main

import (
	// 不能使用任何第三方库。

	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	if len(os.Args) != 2 {
		panic("Invalid command-line arguments")
	}
	pcapFile := os.Args[1]

	// 尝试打开文件
	if handle, err := pcap.OpenOffline(pcapFile); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		// Here, we provide some data structures that you may find useful.
		// Maps in Go are very similar to Python's dictionaries.
		// The Go syntax to declare an empty map is map[KEY_TYPE]VALUE_TYPE{}.
		// Key = IP address, value = array of 2 ints representing [syn, synack] counts
		// 存储每个IP地址发送的SYN数据包和接收到的SYN+ACK数据包的计数
		addresses := map[string][2]int{}
		// Key = IP address, value = map (this is a nested map!) whose key = MAC address,
		// and value = int. You can use this to track the number of requests and replies
		// for pairs of (IP address, MAC address).
		// 存储每个IP地址发送的ARP请求的计数
		arpRequests := map[string]map[string]int{}
		// Key = MAC address, value = int. Use this to store offending MAC addresses,
		// as well as how many times each one sent an unsolicited reply.
		// 存储发送未经请求的ARP应答的MAC地址及其计数
		arpMac := map[string]int{}

		// 遍历文件中的数据包
		// Recommendation: Encapsulate packet handling and/or output in separate functions!
		for packet := range packetSource.Packets() {
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			etherLayer := packet.Layer(layers.LayerTypeEthernet)
			arpLayer := packet.Layer(layers.LayerTypeARP)

			if tcpLayer != nil && ipLayer != nil && etherLayer != nil {

				/*
				   TODO: 使用ipLayer获取源和目标IP地址，
				   以及使用tcpLayer获取TCP标志。相应地更新变量addresses。
				   你需要有一个分支语句来区分SYN和SYN/ACK。
				   注意，SYN数据包的SYN标志设置为true，且ACK标志设置为false！
				*/
				ip, _ := ipLayer.(*layers.IPv4)
				tcp, _ := tcpLayer.(*layers.TCP)
				srcIP := ip.SrcIP.String()
				dstIP := ip.DstIP.String()

				if tcp.SYN && !tcp.ACK {
					addr := addresses[srcIP]
					addr[0]++
					addresses[srcIP] = addr
				} else if tcp.SYN && tcp.ACK {
					addr := addresses[dstIP]
					addr[1]++
					addresses[dstIP] = addr
				}

			} else if arpLayer != nil {

				/*
				   TODO: 使用arp变量获取源和目标的（IP地址，MAC地址）对。
				   完成下面的if-else if语句。arp.Operation的值为1表示
				   ARP数据包是请求，为2表示是应答。相应地更新变量arpRequests。
				   如果发现未经请求的应答，则更新arpMac。
				*/

				arp, _ := arpLayer.(*layers.ARP)
				srcIP := parseIP(arp.SourceProtAddress)
				srcMAC := parseMAC(arp.SourceHwAddress)
				dstIP := parseIP(arp.DstProtAddress)
				dstMAC := parseMAC(arp.DstHwAddress)
				// 解析arp以获取额外信息
				if arp.Operation == 1 {
					// 处理ARP请求
					if _, exists := arpRequests[srcIP]; !exists {
						arpRequests[srcIP] = make(map[string]int)
					}
					arpRequests[srcIP][dstMAC]++
				} else if arp.Operation == 2 {
					// 处理ARP应答
					if _, exists := arpRequests[dstIP]; exists {
						if arpRequests[dstIP][srcMAC] > 0 {
							arpRequests[dstIP][srcMAC]--
						} else {
							arpMac[srcMAC]++
						}
					} else {
						arpMac[srcMAC]++
					}
				}
			}
		}
		fmt.Println("Unauthorized SYN scanners:")
		for ip, addr := range addresses {
			// TODO: 打印SYN扫描器
			if addr[0] > 5 && addr[0] > 3*addr[1] {
				fmt.Println(ip)
			}

		}

		fmt.Println("Unauthorized ARP spoofers:")
		for mac, count := range arpMac {
			// TODO: 打印ARP欺骗者
			if count > 5 {
				fmt.Println(mac)
			}
		}
	}
}

// parseIP 将 []byte 转换为字符串格式的 IP 地址
func parseIP(ip []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

// parseMAC 将 []byte 转换为字符串格式的 MAC 地址
func parseMAC(mac []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

/*
Hints and Links to Documentation:

To access the member variables of each Layer,
you will need to type-cast it to the correct struct. For example,
tcpData, _ := tcpLayer.(*layers.TCP)

Here are some links to useful pages of Gopacket documentation, or
source code of layer objects in Gopacket. The names of the
struct member variables are self-explanatory.

https://github.com/google/gopacket/blob/master/layers/tcp.go Lines 20-35
https://github.com/google/gopacket/blob/master/layers/ip4.go Lines 43-59
https://github.com/google/gopacket/blob/master/layers/arp.go Lines 18-36
In arp.go, HwAddress is the MAC address, and
ProtAddress is the IP address in this case. Both are []byte variables.

https://golang.org/pkg/net/#IP and HardwareAddr (scroll up!) are
new type definitions for a []byte. Read more about type definitions at:
https://stackoverflow.com/questions/49402138/what-is-the-meaning-of-this-type-declaration
Hint: you can type-cast a []byte to a net.IP or net.HardwareAddr object.

https://golang.org/pkg/net/#IP.String - How to stringify IP addresses
https://golang.org/pkg/net/#HardwareAddr.String - How to stringify MAC addresses
*/
