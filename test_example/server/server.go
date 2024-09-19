package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"

	quic "github.com/123131513/newquic"
)

func main() {
	addr := "localhost:4242" // 绑定到 10.0.7.1 的端口 4242
	//addr := "10.0.7.1:4242" // 绑定到 10.0.7.1 的端口 4242

	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	os.Setenv("PROJECT_HOME_DIR", dir)
	// Listen a quic(UDP) socket.
	cfgServer := &quic.Config{
		KeepAlive:   true,
		CreatePaths: true,
		// Scheduler:   "round_robin", // Or any of the above mentioned scheduler
		//Scheduler:   "arrive_time",
		WeightsFile:     dir,
		Training:        false,
		EnableDatagrams: true,
	}

	listener, err := quic.ListenAddr(addr, generateTLSConfig(), cfgServer)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	fmt.Printf("Server listening on %s\n", addr)

	for {
		sess, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Accepted a new session")

		go func() {
			for {
				dgram, err := sess.ReceiveMessage()
				if err != nil {
					fmt.Println("Error receiving datagram:", err)
					break
				}
				fmt.Printf("Received datagram: %s\n", string(dgram))
			}
		}()
	}
}

func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-datagram-example"},
	}
}
