package queuescanner

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/term"
)

type Ctx struct {
	ScanComplete     int64
	ScanSuccessCount int64
	dataList         []string
	mx               sync.Mutex
	OutputFile       string
	startTime        int64
}

type QueueScannerScanFunc func(c *Ctx, host string)

type QueueScanner struct {
	threads  int
	scanFunc QueueScannerScanFunc
	queue    chan string
	wg       sync.WaitGroup
	ctx      *Ctx
}

func nowNano() int64 {
	return time.Now().UnixNano()
}

func formatSeconds(sec int) string {
	h := sec / 3600
	m := (sec % 3600) / 60
	s := sec % 60
	if h > 0 {
		return fmt.Sprintf("%d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%d:%02d", m, s)
}

func hideCursor() {
	fmt.Print("\033[?25l")
}

func showCursor() {
	fmt.Print("\033[?25h")
}

func (c *Ctx) Log(a ...any) {
	fmt.Printf("\r\033[2K%s\n", fmt.Sprint(a...))
}

func (c *Ctx) Logf(f string, a ...any) {
	c.Log(fmt.Sprintf(f, a...))
}

func (c *Ctx) LogReplace(currentItem any) {
	scanSuccess := atomic.LoadInt64(&c.ScanSuccessCount)
	scanComplete := atomic.LoadInt64(&c.ScanComplete)
	scanCompletePercentage := float64(scanComplete) / float64(len(c.dataList)) * 100

	etaStr := "--"
	if scanComplete > 0 && len(c.dataList) > 0 {
		elapsed := float64(nowNano()-c.startTime) / 1e9 // seconds
		avgPerItem := elapsed / float64(scanComplete)
		remaining := float64(len(c.dataList) - int(scanComplete))
		eta := avgPerItem * remaining
		etaStr = formatSeconds(int(eta))
	}
	s := fmt.Sprintf(
		"%.2f%% - C: %d / %d - S: %d - ETA: %s",
		scanCompletePercentage,
		scanComplete,
		len(c.dataList),
		scanSuccess,
		etaStr,
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

func NewQueueScanner(threads int, scanFunc QueueScannerScanFunc) *QueueScanner {
	t := &QueueScanner{
		threads:  threads,
		scanFunc: scanFunc,
		queue:    make(chan string, threads*2),
		ctx:      &Ctx{},
	}

	for i := 0; i < t.threads; i++ {
		go t.run()
	}

	return t
}

func (s *QueueScanner) SetOutputFile(filename string) {
	s.ctx.OutputFile = filename
}

func (s *QueueScanner) Add(dataList []string) {
	s.ctx.dataList = dataList
}

func (s *QueueScanner) Start() {
	s.ctx.startTime = nowNano()
	hideCursor()
	defer showCursor()

	for _, data := range s.ctx.dataList {
		s.queue <- data
	}
	close(s.queue)

	s.wg.Wait()
}

func (s *QueueScanner) run() {
	s.wg.Add(1)
	defer s.wg.Done()

	for {
		data, ok := <-s.queue
		if !ok {
			break
		}

		s.scanFunc(s.ctx, data)

		atomic.AddInt64(&s.ctx.ScanComplete, 1)
		s.ctx.LogReplace(data)
	}
}
