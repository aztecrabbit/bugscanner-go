package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/aztecrabbit/bugscanner-go/pkg/queue_scanner"
)

var sniCmd = &cobra.Command{
	Use:   "sni",
	Short: "Scan server name indication list from file",
	Run:   runScanSNI,
}

var (
	sniFlagFilename string
	sniFlagDeep     int
	sniFlagTimeout  int
)

func init() {
	scanCmd.AddCommand(sniCmd)

	sniCmd.Flags().StringVarP(&sniFlagFilename, "filename", "f", "", "domain list filename")
	sniCmd.Flags().IntVarP(&sniFlagDeep, "deep", "d", 0, "deep subdomain")
	sniCmd.Flags().IntVar(&sniFlagTimeout, "timeout", 10, "handshake timeout")

	sniCmd.MarkFlagFilename("filename")
	sniCmd.MarkFlagRequired("filename")
}

func scanSNI(c *queue_scanner.Ctx, a interface{}) {
	domain := a.(string)

	//

	conn, err := net.DialTimeout("tcp", "93.184.216.34:443", 10*time.Second)
	if err != nil {
		if e, ok := err.(net.Error); ok && e.Timeout() {
			return
		}
		c.Log(err.Error())
		return
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true,
	})
	defer tlsConn.Close()

	ctxTimeout, _ := context.WithTimeout(context.Background(), time.Duration(sniFlagTimeout)*time.Second)
	err = tlsConn.HandshakeContext(ctxTimeout)
	if err != nil {
		c.ScanFailed(domain, nil)
		return
	}
	c.ScanSuccess(domain, func() {
		c.Log(colorG1.Sprint(domain))
	})
}

func runScanSNI(cmd *cobra.Command, args []string) {
	domainListFile, err := os.Open(sniFlagFilename)
	if err != nil {
		fmt.Printf("Opening file \"%s\" error: %s\n", sniFlagFilename, err.Error())
		os.Exit(1)
	}
	defer domainListFile.Close()

	mapDomainList := make(map[string]bool)
	scanner := bufio.NewScanner(domainListFile)
	for scanner.Scan() {
		domain := scanner.Text()
		if sniFlagDeep > 0 {
			domainSplit := strings.Split(domain, ".")
			if len(domainSplit) >= sniFlagDeep {
				domain = strings.Join(domainSplit[len(domainSplit)-sniFlagDeep:], ".")
			}
		}
		mapDomainList[domain] = true
	}

	//

	queueScanner := queue_scanner.NewQueueScanner(scanFlagThreads, scanSNI, nil)
	for domain := range mapDomainList {
		queueScanner.Add(domain)
	}
	queueScanner.Start()
}
