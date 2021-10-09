/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
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

	"github.com/spf13/cobra"
)

// sslCmd represents the ssl command
var sslCmd = &cobra.Command{
	Use:   "ssl",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: run,
}

var (
	deep int
)

func init() {
	scanCmd.AddCommand(sslCmd)

	sslCmd.Flags().IntVarP(&deep, "deep", "d", 0, "deep subdomain")
}

var (
	ctxTimeout, _ = context.WithTimeout(context.Background(), 7*time.Second)
)

func printResult(status string, domain string) {
	fmt.Printf("%-5s  %s\n", status, domain)
}

func scan(wg *sync.WaitGroup, queue <-chan string) {
	wg.Add(1)
	defer wg.Done()

	for {
		domain, ok := <-queue
		if !ok {
			break
		}

		conn, err := net.DialTimeout("tcp", "httpbin.org:443", 7*time.Second)
		if err != nil {
			fmt.Println(err.Error())
			continue
		}
		defer conn.Close()

		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         domain,
			InsecureSkipVerify: true,
		})
		err = tlsConn.HandshakeContext(ctxTimeout)
		if err != nil {
			printResult("False", domain)
			continue
		}
		printResult("True", domain)
	}
}

func run(cmd *cobra.Command, args []string) {
	domainListFile, err := os.Open(scanFlagFilename)
	if err != nil {
		panic(err)
	}
	defer domainListFile.Close()

	queue := make(chan string)
	wg := &sync.WaitGroup{}

	for i := 0; i < scanFlagThreads; i++ {
		go scan(wg, queue)
	}

	mapDomainList := make(map[string]bool)
	scanner := bufio.NewScanner(domainListFile)
	for scanner.Scan() {
		domain := scanner.Text()
		if deep > 0 {
			domainSplit := strings.Split(domain, ".")
			if len(domainSplit) >= deep {
				domain = strings.Join(domainSplit[len(domainSplit)-deep:], ".")
			}
		}
		mapDomainList[domain] = true
	}

	for domain := range mapDomainList {
		queue <- domain
	}
	close(queue)

	wg.Wait()
}
