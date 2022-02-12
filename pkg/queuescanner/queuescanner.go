package queuescanner

import (
	"context"
	"fmt"
	"strings"
	"sync"

	terminal "github.com/wayneashleyberry/terminal-dimensions"
)

type Ctx struct {
	ScanSuccessList []interface{}
	ScanFailedList  []interface{}
	ScanComplete    int

	dataList []*QueueScannerScanParams

	mx sync.Mutex
	context.Context
}

func (c *Ctx) Log(a ...interface{}) {
	fmt.Printf("\r\033[2K%s\n", fmt.Sprint(a...))
}

func (c *Ctx) Logf(f string, a ...interface{}) {
	c.Log(fmt.Sprintf(f, a...))
}

func (c *Ctx) LogReplace(a ...string) {
	scanSuccess := len(c.ScanSuccessList)
	scanFailed := len(c.ScanFailedList)
	scanCompletePercentage := float64(c.ScanComplete) / float64(len(c.dataList)) * 100
	s := fmt.Sprintf(
		"  %.2f%% - C: %d / %d - S: %d - F: %d - %s", scanCompletePercentage, c.ScanComplete, len(c.dataList), scanSuccess, scanFailed, strings.Join(a, " "),
	)

	termWidth, _, err := terminal.Dimensions()
	if err == nil {
		w := int(termWidth) - 3
		if len(s) >= w {
			s = s[:w] + "..."
		}
	}

	fmt.Print("\r\033[2K", s, "\r")
}

func (c *Ctx) LogReplacef(f string, a ...interface{}) {
	c.LogReplace(fmt.Sprintf(f, a...))
}

func (c *Ctx) ScanSuccess(a interface{}, fn func()) {
	c.mx.Lock()
	defer c.mx.Unlock()

	if fn != nil {
		fn()
	}

	c.ScanSuccessList = append(c.ScanSuccessList, a)
}

func (c *Ctx) ScanFailed(a interface{}, fn func()) {
	c.mx.Lock()
	defer c.mx.Unlock()

	if fn != nil {
		fn()
	}

	c.ScanFailedList = append(c.ScanFailedList, a)
}

type QueueScannerScanParams struct {
	Name string
	Data interface{}
}
type QueueScannerScanFunc func(c *Ctx, a *QueueScannerScanParams)
type QueueScannerDoneFunc func(c *Ctx)

type QueueScanner struct {
	threads  int
	scanFunc QueueScannerScanFunc
	queue    chan *QueueScannerScanParams
	wg       sync.WaitGroup

	ctx *Ctx
}

func NewQueueScanner(threads int, scanFunc QueueScannerScanFunc) *QueueScanner {
	t := &QueueScanner{
		threads:  threads,
		scanFunc: scanFunc,
		queue:    make(chan *QueueScannerScanParams),
		ctx:      &Ctx{},
	}

	for i := 0; i < t.threads; i++ {
		go t.run()
	}

	return t
}

func (s *QueueScanner) run() {
	s.wg.Add(1)
	defer s.wg.Done()

	for {
		a, ok := <-s.queue
		if !ok {
			break
		}

		s.ctx.LogReplace(a.Name)

		s.scanFunc(s.ctx, a)

		s.ctx.mx.Lock()
		s.ctx.ScanComplete++
		s.ctx.mx.Unlock()

		s.ctx.LogReplace(a.Name)
	}
}

func (s *QueueScanner) Add(dataList ...*QueueScannerScanParams) {
	s.ctx.dataList = append(s.ctx.dataList, dataList...)
}

func (s *QueueScanner) Start(doneFunc QueueScannerDoneFunc) {
	for _, data := range s.ctx.dataList {
		s.queue <- data
	}
	close(s.queue)

	s.wg.Wait()

	if doneFunc != nil {
		doneFunc(s.ctx)
	}
}
