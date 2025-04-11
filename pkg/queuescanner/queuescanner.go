package queuescanner

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	terminal "github.com/wayneashleyberry/terminal-dimensions"
)

type Ctx struct {
	ScanSuccessList []interface{}
	ScanComplete    atomic.Int64

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
	scanComplete := c.ScanComplete.Load()
	scanCompletePercentage := float64(scanComplete) / float64(len(c.dataList)) * 100
	s := fmt.Sprintf(
		"  %.3f%% - C: %d / %d - S: %d - %s",
		scanCompletePercentage,
		scanComplete,
		len(c.dataList),
		scanSuccess,
		strings.Join(a, " "),
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
	ctx      *Ctx
}

func NewQueueScanner(threads int, scanFunc QueueScannerScanFunc) *QueueScanner {
	t := &QueueScanner{
		threads:  threads,
		scanFunc: scanFunc,
		queue:    make(chan *QueueScannerScanParams, threads*2),
		ctx:      &Ctx{},
	}

	t.wg.Add(threads)
	for i := 0; i < t.threads; i++ {
		go t.worker()
	}

	return t
}

func (s *QueueScanner) worker() {
	defer s.wg.Done()

	for item := range s.queue {
		s.ctx.LogReplace(item.Name)

		s.scanFunc(s.ctx, item)

		s.ctx.ScanComplete.Add(1)
		s.ctx.LogReplace(item.Name)
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
