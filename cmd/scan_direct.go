package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aztecrabbit/bugscanner-go/pkg/queuescanner"
	"github.com/spf13/cobra"
)

// scanDirectCmd represents the scanDirect command
var scanDirectCmd = &cobra.Command{
	Use:   "direct",
	Short: "Scan using direct connection",
	Run:   scanDirectRun,
}

var (
	scanDirectFlagFilename string
	scanDirectFlagTimeout  int
	scanDirectFlagOutput   string
)

func init() {
	scanCmd.AddCommand(scanDirectCmd)

	scanDirectCmd.Flags().StringVarP(&scanDirectFlagFilename, "filename", "f", "", "domain list filename")
	scanDirectCmd.Flags().IntVar(&scanDirectFlagTimeout, "timeout", 3, "connect timeout")
	scanDirectCmd.Flags().StringVarP(&scanDirectFlagOutput, "output", "o", "", "output result")

	scanDirectCmd.MarkFlagFilename("filename")
	scanDirectCmd.MarkFlagRequired("filename")
}

type scanDirectRequest struct {
	Domain string
	Server string
}

type scanDirectResponse struct {
	Request    *scanDirectRequest
	NetIPList  []net.IP
	StatusCode int
	Server     string
	Location   string
}

var httpClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	},
	Timeout: 10 * time.Second,
}

var ctxBackground = context.Background()

func scanDirect(c *queuescanner.Ctx, p *queuescanner.QueueScannerScanParams) {
	req := p.Data.(*scanDirectRequest)

	//

	ctxTimeout, cancel := context.WithTimeout(ctxBackground, 3*time.Second)
	defer cancel()
	netIPList, err := net.DefaultResolver.LookupIP(ctxTimeout, "ip4", req.Domain)
	if err != nil {
		return
	}
	ip := netIPList[0].String()

	//

	httpReq, err := http.NewRequest("HEAD", fmt.Sprintf("https://%s", req.Domain), nil)
	if err != nil {
		return
	}

	httpRes, err := httpClient.Do(httpReq)
	if err != nil {
		return
	}

	hServer := httpRes.Header.Get("Server")
	hRedirect := httpRes.Header.Get("Location")
	if hRedirect != "" {
		hRedirect = fmt.Sprintf(" -> %s", hRedirect)
	}

	s := fmt.Sprintf(
		"%-15s  %-3d  %-16s    %s%s",
		ip,
		httpRes.StatusCode,
		hServer,
		req.Domain,
		hRedirect,
	)

	if hServer == req.Server {
		s = colorG1.Sprint(s)
		res := &scanDirectResponse{
			Request:    req,
			NetIPList:  netIPList,
			StatusCode: httpRes.StatusCode,
			Server:     httpRes.Header.Get("Server"),
			Location:   httpRes.Header.Get("Location"),
		}
		c.ScanSuccess(res, nil)
	}

	c.Log(s)
}

func scanDirectRun(cmd *cobra.Command, args []string) {
	domainList := make(map[string]bool)

	domainListFile, err := os.Open(scanDirectFlagFilename)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	defer domainListFile.Close()

	scanner := bufio.NewScanner(domainListFile)
	for scanner.Scan() {
		domain := scanner.Text()
		domainList[domain] = true
	}

	//

	queueScanner := queuescanner.NewQueueScanner(scanFlagThreads, scanDirect)
	for domain := range domainList {
		queueScanner.Add(&queuescanner.QueueScannerScanParams{
			Name: domain,
			Data: &scanDirectRequest{
				Domain: domain,
				Server: "cloudflare",
			},
		})
	}
	queueScanner.Start(func(c *queuescanner.Ctx) {
		if len(c.ScanSuccessList) == 0 {
			return
		}

		c.Log("")

		mapIPList := make(map[string]bool)
		mapDomainList := make(map[string]bool)

		for _, data := range c.ScanSuccessList {
			res, ok := data.(*scanDirectResponse)
			if !ok {
				continue
			}

			for _, netIP := range res.NetIPList {
				ip := netIP.String()
				mapIPList[ip] = true
			}

			mapDomainList[res.Request.Domain] = true
		}

		ipList := make([]string, 0)

		for ip := range mapIPList {
			ipList = append(ipList, ip)
			c.Log(colorG1.Sprint(ip))
		}

		c.Log("")

		domainList := make([]string, 0)

		for doamin := range mapDomainList {
			domainList = append(domainList, doamin)
			c.Log(colorG1.Sprint(doamin))
		}

		outputList := make([]string, 0)
		outputList = append(outputList, ipList...)
		outputList = append(outputList, domainList...)

		if scanDirectFlagOutput != "" {
			err := os.WriteFile(scanDirectFlagOutput, []byte(strings.Join(outputList, "\n")), 0644)
			if err != nil {
				fmt.Println(err.Error())
				os.Exit(1)
			}
		}
	})
}
