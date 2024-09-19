package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	quic "github.com/123131513/newquic"
)

func main() {
	serverAddr := "localhost:4242" // 绑定到 10.0.7.1 的端口 4242
	// serverAddr := "10.0.7.1:4242" // 目标服务器地址
	localAddr := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"), // 绑定到本机 10.0.0.2
		Port: 0,                        // 自动选择可用端口
	}
	// localAddr := &net.UDPAddr{
	// 	IP:   net.ParseIP("10.0.0.2"), // 绑定到本机 10.0.0.2
	// 	Port: 0,                       // 自动选择可用端口
	// }

	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	os.Setenv("PROJECT_HOME_DIR", dir)
	// Dial server endpoint
	cfgServer := &quic.Config{
		KeepAlive:   true,
		CreatePaths: true,
		// Scheduler:   "round_robin", // Or any of the above mentioned scheduler
		// Scheduler: "low_latency",
		// Scheduler: "random",
		// Scheduler: "ecf",
		Scheduler: "blest",
		// Scheduler:   "arrive_time",
		WeightsFile:     dir,
		Training:        false,
		EnableDatagrams: true,
	}

	// 使用自定义的 UDP 连接绑定本地地址
	udpConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer udpConn.Close()

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-datagram-example"},
	}
	fmt.Println("clientAddr:", udpConn.LocalAddr())
	session, err := quic.DialAddr(serverAddr, tlsConf, cfgServer) //&quic.Config{KeepAlive: true})
	// 使用自定义的 UDP 连接来拨号 QUIC
	// conn, err := quic.Dial(udpConn, udpConn.LocalAddr(), serverAddr, tlsConf, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Connected to server")

	// 发送大量数据
	for i := 0; i < 1000; i++ {
		message := fmt.Sprintf("Datagram message #%d", i)
		err = session.SendMessage([]byte(message))
		if err != nil {
			fmt.Println("Error sending datagram:", err)
			break
		}
		fmt.Printf("Sent: %s\n", message)
		time.Sleep(500 * time.Millisecond)
	}

	// 关闭连接
	err = session.Close(errors.New("client done"))
	if err != nil {
		log.Fatal(err)
	}
}
