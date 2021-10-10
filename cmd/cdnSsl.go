package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

var cdnSsl = &cobra.Command{
	Use:   "cdn-ssl",
	Short: "Scan cdn ssl proxy -> payload -> ssl target",
	Run:   runCdnSsl,
}

var (
	cdnSslFlagCidr   string
	cdnSslFlagMethod string
	cdnSslFlagTarget string

	cdnSslFlagPath     string
	cdnSslFlagScheme   string
	cdnSslFlagProtocol string
	cdnSslFlagPayload  string
)

func init() {
	scanCmd.AddCommand(cdnSsl)

	cdnSsl.Flags().StringVarP(&cdnSslFlagCidr, "cidr", "c", "", "cidr cdn proxy to scan e.g. 127.0.0.1/32")
	cdnSsl.Flags().StringVarP(&cdnSslFlagMethod, "method", "M", "HEAD", "request method")
	cdnSsl.Flags().StringVarP(&cdnSslFlagTarget, "target", "T", "", "target domain cdn")

	cdnSsl.Flags().StringVar(&cdnSslFlagPath, "path", "[scheme][target]", "request path")
	cdnSsl.Flags().StringVar(&cdnSslFlagScheme, "scheme", "ws://", "request scheme")
	cdnSsl.Flags().StringVar(&cdnSslFlagProtocol, "protocol", "HTTP/1.1", "request protocol")
	cdnSsl.Flags().StringVar(
		&cdnSslFlagPayload, "payload", "[method] [path] [protocol]\r\nHost: [target]\r\nUpgrade: websocket\r\n\r\n", "request payload for sending throught cdn proxy",
	)

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
		LogReplace(fmt.Sprintf("Adding %s", ipString))
		ips = append(ips, ipString)
	}
	if len(ips) <= 1 {
		return ips, nil
	}

	return ips[1 : len(ips)-1], nil
}

var cdnSslResultSuccessList []string

func printCdnSslResult(status bool, proxyHostPort string, target string, response string) {
	mx.Lock()
	defer mx.Unlock()

	if !status {
		Log(fmt.Sprintf("%-21s  %s", proxyHostPort, target))
		return
	}

	s := colorG1.Sprintf("%-21s  %s -- %s", proxyHostPort, target, response)
	cdnSslResultSuccessList = append(cdnSslResultSuccessList, s)
	Log(s)
}

type scanCdnSslParams struct {
	ProxyHost string
	ProxyPort int
	Method    string
	Target    string
	Payload   string
}

func scanCdnSsl(args *scanCdnSslParams) {
	proxyHostPort := fmt.Sprintf("%s:%d", args.ProxyHost, args.ProxyPort)
	conn, err := net.Dial("tcp", proxyHostPort)
	if err != nil {
		Log(fmt.Sprint("Dial error: ", err.Error()))
		return
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         args.Target,
		InsecureSkipVerify: true,
	})
	ctx, _ := context.WithTimeout(context.Background(), 3*time.Second)
	err = tlsConn.HandshakeContext(ctx)
	if err != nil {
		printCdnSslResult(false, proxyHostPort, args.Target, "")
		return
	}

	//

	tlsConn.Write([]byte(args.Payload))

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

	printCdnSslResult(true, proxyHostPort, args.Target, strings.Join(lineList, " -- "))
}

func Log(a string) {
	fmt.Printf("\r\033[2K%s\n", a)
}

func LogReplace(a ...string) {
	fmt.Print("\r\033[2K", strings.Join(a, " "), "\r")
}

func workerCdnSsl(wg *sync.WaitGroup, queue <-chan *scanCdnSslParams) {
	wg.Add(1)
	defer wg.Done()

	for {
		args, ok := <-queue
		if !ok {
			break
		}

		LogReplace("Requesting", fmt.Sprintf("%s:%d", args.ProxyHost, args.ProxyPort), args.Target)
		scanCdnSsl(args)
	}
}

func runCdnSsl(cmd *cobra.Command, args []string) {
	ipList, err := ipListFromCidr(cdnSslFlagCidr)
	if err != nil {
		fmt.Printf("Converting ip list from cidr error: %s", err.Error())
		os.Exit(1)
	}

	//

	queue := make(chan *scanCdnSslParams)
	wg := &sync.WaitGroup{}

	for i := 0; i < scanFlagThreads; i++ {
		go workerCdnSsl(wg, queue)
	}

	payload := cdnSslFlagPayload
	payload = strings.ReplaceAll(payload, "[method]", cdnSslFlagMethod)
	payload = strings.ReplaceAll(payload, "[path]", cdnSslFlagPath)
	payload = strings.ReplaceAll(payload, "[scheme]", cdnSslFlagScheme)
	payload = strings.ReplaceAll(payload, "[target]", cdnSslFlagTarget)
	payload = strings.ReplaceAll(payload, "[protocol]", cdnSslFlagProtocol)

	payloadStringEncoded := strings.ReplaceAll(strings.ReplaceAll(payload, "\r", "\\r"), "\n", "\\n")

	Log(fmt.Sprintf("%s\n", payloadStringEncoded))

	doneFunc := func() {
		Log("\n#\n#\n")

		for _, s := range cdnSslResultSuccessList {
			fmt.Println(s)
		}

		fmt.Printf("\n%s\n", payloadStringEncoded)
	}

	exitChan := make(chan os.Signal)
	signal.Notify(exitChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-exitChan

		doneFunc()

		os.Exit(0)
	}()

	for _, ip := range ipList {
		queue <- &scanCdnSslParams{
			ProxyHost: ip,
			ProxyPort: 443,
			Method:    cdnSslFlagMethod,
			Target:    cdnSslFlagTarget,
			Payload:   payload,
		}
	}
	close(queue)

	wg.Wait()

	doneFunc()
}
