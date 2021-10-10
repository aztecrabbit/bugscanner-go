package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var sniCmd = &cobra.Command{
	Use:   "sni",
	Short: "Scan server name indication list from file",
	Run:   runSNI,
}

var (
	sslFlagFilename string
	sslFlagThreads  int
	sslFlagDeep     int
	sslFlagTimeout  int
)

func init() {
	scanCmd.AddCommand(sniCmd)

	sniCmd.Flags().StringVarP(&sslFlagFilename, "filename", "f", "", "domain list filename")
	sniCmd.Flags().IntVarP(&sslFlagThreads, "threads", "t", 64, "total threads to use")
	sniCmd.Flags().IntVarP(&sslFlagDeep, "deep", "d", 0, "deep subdomain")
	sniCmd.Flags().IntVar(&sslFlagTimeout, "timeout", 10, "handshake timeout")

	sniCmd.MarkFlagFilename("filename")
	sniCmd.MarkFlagRequired("filename")
}

var (
	colorG1 = color.New(color.FgGreen, color.Bold)
	mx      sync.Mutex
)

func printSNITableHeader() {
	fmt.Println("status  server name indication")
	fmt.Println("------  ----------------------")
}

func printSNIResult(status bool, domain string) {
	mx.Lock()
	defer mx.Unlock()

	f := "%-6s  %s\n"
	if status {
		colorG1.Printf(f, "True", domain)
	} else {
		fmt.Printf(f, "", domain)
	}
}

func scanSNI(domain string) {
	conn, err := net.DialTimeout("tcp", "93.184.216.34:443", 10*time.Second)
	if err != nil {
		if e, ok := err.(net.Error); ok && e.Timeout() {
			return
		}
		fmt.Println(err.Error())
		return
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true,
	})
	defer tlsConn.Close()

	ctxTimeout, _ := context.WithTimeout(context.Background(), time.Duration(sslFlagTimeout)*time.Second)
	err = tlsConn.HandshakeContext(ctxTimeout)
	if err != nil {
		printSNIResult(false, domain)
		return
	}
	printSNIResult(true, domain)
}

func workerSNI(wg *sync.WaitGroup, queue <-chan string) {
	wg.Add(1)
	defer wg.Done()

	for {
		domain, ok := <-queue
		if !ok {
			break
		}

		scanSNI(domain)
	}
}

func runSNI(cmd *cobra.Command, args []string) {
	domainListFile, err := os.Open(sslFlagFilename)
	if err != nil {
		fmt.Printf("Opening file \"%s\" error: %s\n", sslFlagFilename, err.Error())
		os.Exit(1)
	}
	defer domainListFile.Close()

	mapDomainList := make(map[string]bool)
	scanner := bufio.NewScanner(domainListFile)
	for scanner.Scan() {
		domain := scanner.Text()
		if sslFlagDeep > 0 {
			domainSplit := strings.Split(domain, ".")
			if len(domainSplit) >= sslFlagDeep {
				domain = strings.Join(domainSplit[len(domainSplit)-sslFlagDeep:], ".")
			}
		}
		mapDomainList[domain] = true
	}

	//

	printSNITableHeader()

	queue := make(chan string)
	wg := &sync.WaitGroup{}

	for i := 0; i < sslFlagThreads; i++ {
		go workerSNI(wg, queue)
	}

	for domain := range mapDomainList {
		queue <- domain
	}
	close(queue)

	wg.Wait()
}
