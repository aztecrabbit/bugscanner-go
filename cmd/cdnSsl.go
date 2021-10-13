package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
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
	cdnSslFlagPath              string
	cdnSslFlagScheme            string
	cdnSslFlagProtocol          string
	cdnSslFlagPayload           string
	cdnSslFlagTimeout           int
	cdnSslFlagOutput            string
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
		&cdnSslFlagPayload, "payload", "[method] [path] [protocol][crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]", "request payload for sending throught cdn proxy",
	)
	cdnSsl.Flags().IntVar(&cdnSslFlagTimeout, "timeout", 3, "handshake timeout")
	cdnSsl.Flags().StringVarP(&cdnSslFlagOutput, "output", "o", "", "output result")

	cdnSsl.MarkFlagFilename("proxy-filename")
	cdnSsl.MarkFlagFilename("output")
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

type scanCdnSslRequest struct {
	ProxyHostPort string
	Method        string
	Target        string
	Payload       string
}

type scanCdnSslResponse struct {
	Request      *scanCdnSslRequest
	ResponseLine []string
}

func scanCdnSsl(c *queue_scanner.Ctx, p *queue_scanner.QueueScannerScanParams) {
	req, ok := p.Data.(*scanCdnSslRequest)
	if !ok {
		return
	}

	//

	var conn net.Conn
	var err error

	dialCount := 0
	for {
		dialCount++
		if dialCount > 3 {
			return
		}
		conn, err = net.DialTimeout("tcp", req.ProxyHostPort, 3*time.Second)
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Timeout() {
				c.LogReplace(p.Name, "-", "Dial Timeout")
				continue
			}
			if opError, ok := err.(*net.OpError); ok {
				if syscalErr, ok := opError.Err.(*os.SyscallError); ok {
					if syscalErr.Err.Error() == "network is unreachable" {
						return
					}
				}
			}
			c.Log(err.Error())
			return
		}
		defer conn.Close()
		break
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         req.Target,
		InsecureSkipVerify: true,
	})
	ctxHandshake, ctxHandshakeCancel := context.WithTimeout(context.Background(), time.Duration(cdnSslFlagTimeout)*time.Second)
	defer ctxHandshakeCancel()
	err = tlsConn.HandshakeContext(ctxHandshake)
	if err != nil {
		c.ScanFailed(req, nil)
		return
	}

	//

	ctxResultTimeout, ctxResultTimeoutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer ctxResultTimeoutCancel()

	chanResult := make(chan bool)

	go func() {
		payload := req.Payload
		payload = strings.ReplaceAll(payload, "[host]", req.Target)
		payload = strings.ReplaceAll(payload, "[crlf]", "[cr][lf]")
		payload = strings.ReplaceAll(payload, "[cr]", "\r")
		payload = strings.ReplaceAll(payload, "[lf]", "\n")

		_, err = tlsConn.Write([]byte(payload))
		if err != nil {
			return
		}

		res := &scanCdnSslResponse{
			Request:      req,
			ResponseLine: make([]string, 0),
		}

		scanner := bufio.NewScanner(tlsConn)
		isPrefix := true
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				break
			}
			if isPrefix || strings.HasPrefix(line, "Location") || strings.HasPrefix(line, "Server") {
				isPrefix = false
				res.ResponseLine = append(res.ResponseLine, line)
			}
		}

		if len(res.ResponseLine) == 0 {
			c.Log(colorG2.Sprintf("%-21s  %s", req.ProxyHostPort, req.Target))
			return
		}

		c.ScanSuccess(res, func() {
			c.Log(colorG1.Sprintf("%-21s  %s -- %s", req.ProxyHostPort, req.Target, strings.Join(res.ResponseLine, " -- ")))
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

func getScanCdnSslPayloadDecoded(target ...string) string {
	payload := cdnSslFlagPayload
	payload = strings.ReplaceAll(payload, "[method]", cdnSslFlagMethod)
	payload = strings.ReplaceAll(payload, "[path]", cdnSslFlagPath)
	payload = strings.ReplaceAll(payload, "[scheme]", cdnSslFlagScheme)
	payload = strings.ReplaceAll(payload, "[protocol]", cdnSslFlagProtocol)
	if len(target) > 0 {
		payload = strings.ReplaceAll(payload, "[target]", target[0])
	}
	return payload
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

	queueScanner := queue_scanner.NewQueueScanner(scanFlagThreads, scanCdnSsl)

	for proxyHost := range proxyHostList {
		queueScanner.Add(&queue_scanner.QueueScannerScanParams{
			Name: fmt.Sprintf("%s:%d - %s", proxyHost, cdnSslFlagProxyPort, cdnSslFlagTarget),
			Data: &scanCdnSslRequest{
				ProxyHostPort: fmt.Sprintf("%s:%d", proxyHost, cdnSslFlagProxyPort),
				Method:        cdnSslFlagMethod,
				Target:        cdnSslFlagTarget,
				Payload:       getScanCdnSslPayloadDecoded(cdnSslFlagTarget),
			},
		})
	}

	// exitChan := make(chan os.Signal)
	// signal.Notify(exitChan, os.Interrupt, syscall.SIGTERM)
	// go func() {
	// 	<-exitChan

	// 	os.Exit(0)
	// }()

	fmt.Printf("%s\n\n", getScanCdnSslPayloadDecoded())

	queueScanner.Start(func(c *queue_scanner.Ctx) {
		if len(c.ScanSuccessList) == 0 {
			return
		}

		c.Logf("\n#\n#\n")

		jsonBytes, err := json.MarshalIndent(c.ScanSuccessList, "", "  ")
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		fmt.Println(string(jsonBytes))

		if cdnSslFlagOutput != "" {
			err := os.WriteFile(cdnSslFlagOutput, jsonBytes, os.ModePerm)
			if err != nil {
				fmt.Println(err.Error())
				os.Exit(1)
			}
		}
	})
}
