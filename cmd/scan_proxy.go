package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aztecrabbit/bugscanner-go/pkg/queuescanner"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var scanProxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Scan proxy -> payload -> target",
	Run:   runScanProxy,
}

var (
	scanProxyFlagProxyCidr         string
	scanProxyFlagProxyHost         string
	scanProxyFlagProxyHostFilename string
	scanProxyFlagProxyPort         int
	scanProxyFlagBug               string
	scanProxyFlagMethod            string
	scanProxyFlagTarget            string
	scanProxyFlagPath              string
	scanProxyFlagProtocol          string
	scanProxyFlagPayload           string
	scanProxyFlagTimeout           int
	scanProxyFlagOutput            string
)

func init() {
	scanCmd.AddCommand(scanProxyCmd)

	scanProxyCmd.Flags().StringVarP(&scanProxyFlagProxyCidr, "cidr", "c", "", "cidr proxy to scan e.g. 127.0.0.1/32")
	scanProxyCmd.Flags().StringVar(&scanProxyFlagProxyHost, "proxy", "", "proxy without port")
	scanProxyCmd.Flags().StringVarP(&scanProxyFlagProxyHostFilename, "filename", "f", "", "proxy filename without port")
	scanProxyCmd.Flags().IntVarP(&scanProxyFlagProxyPort, "port", "p", 80, "proxy port")
	scanProxyCmd.Flags().StringVarP(&scanProxyFlagBug, "bug", "B", "", "bug to use when proxy is ip instead of domain")
	scanProxyCmd.Flags().StringVarP(&scanProxyFlagMethod, "method", "M", "GET", "request method")
	scanProxyCmd.Flags().StringVar(&scanProxyFlagTarget, "target", "", "target server (response must be 101)")
	scanProxyCmd.Flags().StringVar(&scanProxyFlagPath, "path", "/", "request path")
	scanProxyCmd.Flags().StringVar(&scanProxyFlagProtocol, "protocol", "HTTP/1.1", "request protocol")
	scanProxyCmd.Flags().StringVar(
		&scanProxyFlagPayload, "payload", "[method] [path] [protocol][crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]", "request payload for sending throught proxy",
	)
	scanProxyCmd.Flags().IntVar(&scanProxyFlagTimeout, "timeout", 3, "handshake timeout")
	scanProxyCmd.Flags().StringVarP(&scanProxyFlagOutput, "output", "o", "", "output result")

	scanProxyFlagMethod = strings.ToUpper(scanProxyFlagMethod)
}

type scanProxyRequest struct {
	ProxyHost string
	ProxyPort int
	Bug       string
	Method    string
	Target    string
	Payload   string
}

type scanProxyResponse struct {
	Request      *scanProxyRequest
	ResponseLine []string
}

func scanProxy(c *queuescanner.Ctx, p *queuescanner.QueueScannerScanParams) {
	req, ok := p.Data.(*scanProxyRequest)
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

		_, err = conn.Write([]byte(payload))
		if err != nil {
			return
		}

		res := &scanProxyResponse{
			Request:      req,
			ResponseLine: make([]string, 0),
		}

		scanner := bufio.NewScanner(conn)
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

		resColor := color.New()

		if len(res.ResponseLine) > 0 && strings.Contains(res.ResponseLine[0], " 101 ") {
			resColor = colorG1
			c.ScanSuccess(res, nil)
		} else {
			if len(res.ResponseLine) == 0 {
				resColor = colorB1
			}
		}

		c.Log(resColor.Sprintf("%-32s  %s", proxyHostPort, strings.Join(res.ResponseLine, " -- ")))

		chanResult <- true
	}()

	select {
	case <-chanResult:
		return
	case <-ctxResultTimeout.Done():
		return
	}
}

func getScanProxyPayloadDecoded(bug ...string) string {
	payload := scanProxyFlagPayload
	payload = strings.ReplaceAll(payload, "[method]", scanProxyFlagMethod)
	payload = strings.ReplaceAll(payload, "[path]", scanProxyFlagPath)
	payload = strings.ReplaceAll(payload, "[protocol]", scanProxyFlagProtocol)
	if len(bug) > 0 {
		payload = strings.ReplaceAll(payload, "[bug]", bug[0])
	}
	return payload
}

func runScanProxy(cmd *cobra.Command, args []string) {
	proxyHostList := make(map[string]bool)

	if scanProxyFlagProxyHost != "" {
		proxyHostList[scanProxyFlagProxyHost] = true
	}

	if scanProxyFlagProxyHostFilename != "" {
		proxyHostFile, err := os.Open(scanProxyFlagProxyHostFilename)
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

	if scanProxyFlagProxyCidr != "" {
		proxyHostListFromCidr, err := ipListFromCidr(scanProxyFlagProxyCidr)
		if err != nil {
			fmt.Printf("Converting ip list from cidr error: %s", err.Error())
			os.Exit(1)
		}

		for _, proxyHost := range proxyHostListFromCidr {
			proxyHostList[proxyHost] = true
		}
	}

	//

	queueScanner := queuescanner.NewQueueScanner(scanFlagThreads, scanProxy)
	regexpIsIP := regexp.MustCompile(`\d+$`)

	for proxyHost := range proxyHostList {
		bug := scanProxyFlagBug

		if bug == "" {
			if regexpIsIP.MatchString(proxyHost) {
				bug = scanProxyFlagTarget
			} else {
				bug = proxyHost
			}
		}

		if scanProxyFlagPath == "/" {
			bug = scanProxyFlagTarget
		}

		queueScanner.Add(&queuescanner.QueueScannerScanParams{
			Name: fmt.Sprintf("%s:%d - %s", proxyHost, scanProxyFlagProxyPort, scanProxyFlagTarget),
			Data: &scanProxyRequest{
				ProxyHost: proxyHost,
				ProxyPort: scanProxyFlagProxyPort,
				Bug:       bug,
				Method:    scanProxyFlagMethod,
				Target:    scanProxyFlagTarget,
				Payload:   getScanProxyPayloadDecoded(bug),
			},
		})
	}

	fmt.Printf("%s\n\n", getScanProxyPayloadDecoded())

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

		if scanProxyFlagOutput != "" {
			err := os.WriteFile(scanProxyFlagOutput, jsonBytes, 0644)
			if err != nil {
				fmt.Println(err.Error())
				os.Exit(1)
			}
		}
	})
}
