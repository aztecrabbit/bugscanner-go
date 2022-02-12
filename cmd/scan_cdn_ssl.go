package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aztecrabbit/bugscanner-go/pkg/queuescanner"
	"github.com/spf13/cobra"
)

var scanCdnSslCmd = &cobra.Command{
	Use:   "cdn-ssl",
	Short: "Scan cdn ssl proxy -> payload -> ssl target",
	Run:   runScanCdnSsl,
}

var (
	cdnSslFlagProxyCidr         string
	cdnSslFlagProxyHost         string
	cdnSslFlagProxyHostFilename string
	cdnSslFlagProxyPort         int
	cdnSslFlagBug               string
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
	scanCmd.AddCommand(scanCdnSslCmd)

	scanCdnSslCmd.Flags().StringVarP(&cdnSslFlagProxyCidr, "cidr", "c", "", "cidr cdn proxy to scan e.g. 127.0.0.1/32")
	scanCdnSslCmd.Flags().StringVar(&cdnSslFlagProxyHost, "proxy", "", "cdn proxy without port")
	scanCdnSslCmd.Flags().StringVar(&cdnSslFlagProxyHostFilename, "proxy-filename", "", "cdn proxy filename without port")
	scanCdnSslCmd.Flags().IntVarP(&cdnSslFlagProxyPort, "port", "p", 443, "proxy port")
	scanCdnSslCmd.Flags().StringVarP(&cdnSslFlagBug, "bug", "B", "", "bug to use when proxy is ip instead of domain")
	scanCdnSslCmd.Flags().StringVarP(&cdnSslFlagMethod, "method", "M", "HEAD", "request method")
	scanCdnSslCmd.Flags().StringVar(&cdnSslFlagTarget, "target", "", "target domain cdn")
	scanCdnSslCmd.Flags().StringVar(&cdnSslFlagPath, "path", "[scheme][bug]", "request path")
	scanCdnSslCmd.Flags().StringVar(&cdnSslFlagScheme, "scheme", "ws://", "request scheme")
	scanCdnSslCmd.Flags().StringVar(&cdnSslFlagProtocol, "protocol", "HTTP/1.1", "request protocol")
	scanCdnSslCmd.Flags().StringVar(
		&cdnSslFlagPayload, "payload", "[method] [path] [protocol][crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]", "request payload for sending throught cdn proxy",
	)
	scanCdnSslCmd.Flags().IntVar(&cdnSslFlagTimeout, "timeout", 3, "handshake timeout")
	scanCdnSslCmd.Flags().StringVarP(&cdnSslFlagOutput, "output", "o", "", "output result")

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
	ProxyHost string
	ProxyPort int
	Bug       string
	Method    string
	Target    string
	Payload   string
}

type scanCdnSslResponse struct {
	Request      *scanCdnSslRequest
	ResponseLine []string
}

func scanCdnSsl(c *queuescanner.Ctx, p *queuescanner.QueueScannerScanParams) {
	req, ok := p.Data.(*scanCdnSslRequest)
	if !ok {
		return
	}

	//

	var conn net.Conn
	var err error

	proxyHostPort := fmt.Sprintf("%s:%d", req.ProxyHost, req.ProxyPort)
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
			if opError, ok := err.(*net.OpError); ok {
				if syscalErr, ok := opError.Err.(*os.SyscallError); ok {
					if syscalErr.Err.Error() == "network is unreachable" {
						return
					}
				}
			}
			return
		}
		defer conn.Close()
		break
	}

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         req.Bug,
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

		if len(res.ResponseLine) == 0 || !strings.Contains(res.ResponseLine[0], " 101 ") {
			c.Logf("%-32s  %s", proxyHostPort, strings.Join(res.ResponseLine, " -- "))
			return
		}

		c.ScanSuccess(res, func() {
			c.Log(colorG1.Sprintf("%-32s  %s", proxyHostPort, strings.Join(res.ResponseLine, " -- ")))
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

func getScanCdnSslPayloadDecoded(bug ...string) string {
	payload := cdnSslFlagPayload
	payload = strings.ReplaceAll(payload, "[method]", cdnSslFlagMethod)
	payload = strings.ReplaceAll(payload, "[path]", cdnSslFlagPath)
	payload = strings.ReplaceAll(payload, "[scheme]", cdnSslFlagScheme)
	payload = strings.ReplaceAll(payload, "[protocol]", cdnSslFlagProtocol)
	if len(bug) > 0 {
		payload = strings.ReplaceAll(payload, "[bug]", bug[0])
	}
	return payload
}

func runScanCdnSsl(cmd *cobra.Command, args []string) {
	proxyHostList := make(map[string]bool)

	if cdnSslFlagProxyHost != "" {
		proxyHostList[cdnSslFlagProxyHost] = true
	}

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

	queueScanner := queuescanner.NewQueueScanner(scanFlagThreads, scanCdnSsl)
	regexpIsIP := regexp.MustCompile(`\d+$`)

	for proxyHost := range proxyHostList {
		bug := cdnSslFlagBug

		if bug == "" {
			if regexpIsIP.MatchString(proxyHost) {
				bug = cdnSslFlagTarget
			} else {
				bug = proxyHost
			}
		}

		if cdnSslFlagPath == "/" {
			bug = cdnSslFlagTarget
		}

		queueScanner.Add(&queuescanner.QueueScannerScanParams{
			Name: fmt.Sprintf("%s:%d - %s", proxyHost, cdnSslFlagProxyPort, cdnSslFlagTarget),
			Data: &scanCdnSslRequest{
				ProxyHost: proxyHost,
				ProxyPort: cdnSslFlagProxyPort,
				Bug:       bug,
				Method:    cdnSslFlagMethod,
				Target:    cdnSslFlagTarget,
				Payload:   getScanCdnSslPayloadDecoded(bug),
			},
		})
	}

	fmt.Printf("%s\n\n", getScanCdnSslPayloadDecoded())

	queueScanner.Start(func(c *queuescanner.Ctx) {
		if len(c.ScanSuccessList) == 0 {
			return
		}

		c.Logf("")

		jsonBytes, err := json.MarshalIndent(c.ScanSuccessList, "", "  ")
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		fmt.Println(string(jsonBytes))

		if cdnSslFlagOutput != "" {
			err := os.WriteFile(cdnSslFlagOutput, jsonBytes, 0644)
			if err != nil {
				fmt.Println(err.Error())
				os.Exit(1)
			}
		}
	})
}
