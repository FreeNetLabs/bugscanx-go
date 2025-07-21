package queuescanner

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/term"
)

type Ctx struct {
	ScanComplete     int64
	ScanSuccessCount int64
	dataList         []*QueueScannerScanParams
	mx               sync.Mutex
	OutputFile       string
}

func (c *Ctx) Log(a ...any) {
	fmt.Printf("\r\033[2K%s\n", fmt.Sprint(a...))
}

func (c *Ctx) Logf(f string, a ...any) {
	c.Log(fmt.Sprintf(f, a...))
}

func (c *Ctx) LogReplace(a ...string) {
	scanSuccess := atomic.LoadInt64(&c.ScanSuccessCount)
	scanComplete := atomic.LoadInt64(&c.ScanComplete)
	scanCompletePercentage := float64(scanComplete) / float64(len(c.dataList)) * 100
	s := fmt.Sprintf(
		"%.2f%% - C: %d / %d - S: %d - %s", scanCompletePercentage, scanComplete, len(c.dataList), scanSuccess, strings.Join(a, " "),
	)

	if termWidth, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
		w := termWidth - 3
		if len(s) >= w {
			s = s[:w] + "..."
		}
	}

	fmt.Print("\r\033[2K", s, "\r")
}

func (c *Ctx) LogReplacef(f string, a ...any) {
	c.LogReplace(fmt.Sprintf(f, a...))
}

func (c *Ctx) ScanSuccess(a any) {
	if s, ok := a.(string); ok && c.OutputFile != "" {
		c.mx.Lock()
		f, err := os.OpenFile(c.OutputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			f.WriteString(s + "\n")
			f.Close()
		}
		c.mx.Unlock()
	}

	atomic.AddInt64(&c.ScanSuccessCount, 1)
}

type QueueScannerScanParams struct {
	Name string
	Data any
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
		queue:    make(chan *QueueScannerScanParams, threads*2),
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
		s.scanFunc(s.ctx, a)

		atomic.AddInt64(&s.ctx.ScanComplete, 1)
		s.ctx.LogReplace(a.Name)
	}
}

func (s *QueueScanner) Add(dataList ...*QueueScannerScanParams) {
	s.ctx.dataList = append(s.ctx.dataList, dataList...)
}

func (s *QueueScanner) Start() {
	hideCursor()
	defer showCursor()

	for _, data := range s.ctx.dataList {
		s.queue <- data
	}
	close(s.queue)

	s.wg.Wait()
}

func hideCursor() {
	fmt.Print("\033[?25l")
}

func showCursor() {
	fmt.Print("\033[?25h")
}

func (s *QueueScanner) SetOutputFile(filename string) {
	s.ctx.OutputFile = filename
}
