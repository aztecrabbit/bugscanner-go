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

	"github.com/aztecrabbit/bugscanner-go/pkg/queue_scanner"
	"github.com/spf13/cobra"
)

var cdnSsl = &cobra.Command{
	Use:   "cdn-ssl",
	Short: "Scan cdn ssl proxy -> payload -> ssl target",
	Run:   runScanCdnSsl,
}

var (
	cdnSslFlagProxyCidr         string
	cdnSslFlagProxyHostFilename string
	cdnSslFlagProxyPort         int
	cdnSslFlagMethod            string
	cdnSslFlagTarget            string

	cdnSslFlagPath     string
	cdnSslFlagScheme   string
	cdnSslFlagProtocol string
	cdnSslFlagPayload  string
	cdnSslFlagTimeout  int
)

func init() {
	scanCmd.AddCommand(cdnSsl)

	cdnSsl.Flags().StringVar(&cdnSslFlagProxyHostFilename, "proxy-filename", "", "cdn proxy filename without port")
	cdnSsl.Flags().StringVarP(&cdnSslFlagProxyCidr, "cidr", "c", "", "cidr cdn proxy to scan e.g. 127.0.0.1/32")
	cdnSsl.Flags().IntVarP(&cdnSslFlagProxyPort, "port", "p", 443, "proxy port")
	cdnSsl.Flags().StringVarP(&cdnSslFlagMethod, "method", "M", "HEAD", "request method")
	cdnSsl.Flags().StringVarP(&cdnSslFlagTarget, "target", "T", "", "target domain cdn")
	cdnSsl.Flags().StringVar(&cdnSslFlagPath, "path", "[scheme][target]", "request path")
	cdnSsl.Flags().StringVar(&cdnSslFlagScheme, "scheme", "ws://", "request scheme")
	cdnSsl.Flags().StringVar(&cdnSslFlagProtocol, "protocol", "HTTP/1.1", "request protocol")
	cdnSsl.Flags().StringVar(
		&cdnSslFlagPayload, "payload", "[method] [path] [protocol]\r\nHost: [target]\r\nUpgrade: websocket\r\n\r\n", "request payload for sending throught cdn proxy",
	)
	cdnSsl.Flags().IntVar(&cdnSslFlagTimeout, "timeout", 3, "handshake timeout")

	cdnSsl.MarkFlagFilename("proxy-filename")
	cdnSsl.MarkFlagRequired("target")

	cdnSslFlagMethod = strings.ToUpper(cdnSslFlagMethod)
}

func ipInc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func ipListFromCidr(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); ipInc(ip) {
		ipString := ip.String()
		ips = append(ips, ipString)
	}
	if len(ips) <= 1 {
		return ips, nil
	}

	return ips[1 : len(ips)-1], nil
}

type scanCdnSslParams struct {
	ProxyHost string
	ProxyPort int
	Method    string
	Target    string
	Payload   string
}

func scanCdnSsl(c *queue_scanner.Ctx, p *queue_scanner.QueueScannerScanParams) {
	args, ok := p.Data.(*scanCdnSslParams)
	if !ok {
		return
	}

	//

	proxyHostPort := fmt.Sprintf("%s:%d", args.ProxyHost, args.ProxyPort)

	var conn net.Conn
	var err error

	dialCount := 0
	for {
		dialCount++
		if dialCount > 3 {
			return
		}
		conn, err = net.DialTimeout("tcp", proxyHostPort, 3*time.Second)
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Timeout() {
				c.LogReplace(p.Name, "-", "Dial Timeout")
				continue
			}
			c.Logf("Dial error: %s", err.Error())
			return
		}
		defer conn.Close()
		break
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         args.Target,
		InsecureSkipVerify: true,
	})
	ctxHandshake, ctxHandshakeCancel := context.WithTimeout(context.Background(), time.Duration(cdnSslFlagTimeout)*time.Second)
	defer ctxHandshakeCancel()
	err = tlsConn.HandshakeContext(ctxHandshake)
	if err != nil {
		c.ScanFailed(args, nil)
		return
	}

	//

	ctxResultTimeout, ctxResultTimeoutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer ctxResultTimeoutCancel()

	chanResult := make(chan bool)

	go func() {
		_, err = tlsConn.Write([]byte(args.Payload))
		if err != nil {
			return
		}

		scanner := bufio.NewScanner(tlsConn)
		lineList := make([]string, 0)
		isPrefix := true
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				break
			}
			if isPrefix || strings.HasPrefix(line, "Location") || strings.HasPrefix(line, "Server") {
				isPrefix = false
				lineList = append(lineList, line)
			}
		}

		if len(lineList) == 0 {
			c.Log(colorG2.Sprintf("%-21s  %s", proxyHostPort, args.Target))
			return
		}

		c.ScanSuccess(args, func() {
			c.Log(colorG1.Sprintf("%-21s  %s -- %s", proxyHostPort, args.Target, strings.Join(lineList, " -- ")))
		})

		chanResult <- true
	}()

	select {
	case <-chanResult:
		return
	case <-ctxResultTimeout.Done():
		return
	}
}

func runScanCdnSsl(cmd *cobra.Command, args []string) {
	proxyHostList := make(map[string]bool)

	if cdnSslFlagProxyHostFilename != "" {
		proxyHostFile, err := os.Open(cdnSslFlagProxyHostFilename)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		defer proxyHostFile.Close()

		scanner := bufio.NewScanner(proxyHostFile)
		for scanner.Scan() {
			proxyHost := scanner.Text()
			proxyHostList[proxyHost] = true
		}
	}

	if cdnSslFlagProxyCidr != "" {
		proxyHostListFromCidr, err := ipListFromCidr(cdnSslFlagProxyCidr)
		if err != nil {
			fmt.Printf("Converting ip list from cidr error: %s", err.Error())
			os.Exit(1)
		}

		for _, proxyHost := range proxyHostListFromCidr {
			proxyHostList[proxyHost] = true
		}
	}

	//

	queueScanner := queue_scanner.NewQueueScanner(scanFlagThreads, scanCdnSsl, nil)

	for proxyHost := range proxyHostList {
		payload := cdnSslFlagPayload
		payload = strings.ReplaceAll(payload, "[method]", cdnSslFlagMethod)
		payload = strings.ReplaceAll(payload, "[path]", cdnSslFlagPath)
		payload = strings.ReplaceAll(payload, "[scheme]", cdnSslFlagScheme)
		payload = strings.ReplaceAll(payload, "[target]", cdnSslFlagTarget)
		payload = strings.ReplaceAll(payload, "[protocol]", cdnSslFlagProtocol)

		queueScanner.Add(&queue_scanner.QueueScannerScanParams{
			Name: fmt.Sprintf("%s:%d - %s", proxyHost, cdnSslFlagProxyPort, cdnSslFlagTarget),
			Data: &scanCdnSslParams{
				ProxyHost: proxyHost,
				ProxyPort: cdnSslFlagProxyPort,
				Method:    cdnSslFlagMethod,
				Target:    cdnSslFlagTarget,
				Payload:   payload,
			},
		})
	}

	// exitChan := make(chan os.Signal)
	// signal.Notify(exitChan, os.Interrupt, syscall.SIGTERM)
	// go func() {
	// 	<-exitChan

	// 	os.Exit(0)
	// }()

	queueScanner.Start()
}
