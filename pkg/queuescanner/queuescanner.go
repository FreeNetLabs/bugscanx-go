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
	ScanComplete int64
	SuccessCount int64
	hostList     []string
	mu           sync.Mutex
	OutputFile   string
	startTime    int64
	lastStatTime int64
	statInterval int64 // in nanoseconds
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

func formatETA(seconds float64) string {
	d := time.Duration(seconds * float64(time.Second))
	if d < 0 {
		return "--"
	}
	return d.Truncate(time.Second).String()
}

func hideCursor() {
	fmt.Print("\033[?25l")
}

func showCursor() {
	fmt.Print("\033[?25h")
}

func (ctx *Ctx) Log(a ...any) {
	fmt.Printf("\r\033[2K%s\n", fmt.Sprint(a...))
}

func (ctx *Ctx) LogStat() {
	if ctx.statInterval > 0 {
		now := nowNano()
		if now-atomic.LoadInt64(&ctx.lastStatTime) < ctx.statInterval {
			return
		}
		atomic.StoreInt64(&ctx.lastStatTime, now)
	}

	scanSuccess := atomic.LoadInt64(&ctx.SuccessCount)
	scanComplete := atomic.LoadInt64(&ctx.ScanComplete)
	scanCompletePercentage := float64(scanComplete) / float64(len(ctx.hostList)) * 100

	eta := "--"
	if scanComplete > 0 && len(ctx.hostList) > 0 {
		elapsed := float64(nowNano()-ctx.startTime) / 1e9 // seconds
		avgPerItem := elapsed / float64(scanComplete)
		remaining := float64(len(ctx.hostList) - int(scanComplete))
		etaSec := avgPerItem * remaining
		eta = formatETA(etaSec)
	}
	status := fmt.Sprintf(
		"%.2f%% - C: %d / %d - S: %d - ETA: %s",
		scanCompletePercentage,
		scanComplete,
		len(ctx.hostList),
		scanSuccess,
		eta,
	)

	if termWidth, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
		width := termWidth - 3
		if len(status) >= width {
			status = status[:width] + "..."
		}
	}

	fmt.Print("\r\033[2K", status, "\r")
}

func (ctx *Ctx) ScanSuccess(result any) {
	if str, ok := result.(string); ok && ctx.OutputFile != "" {
		ctx.mu.Lock()
		file, err := os.OpenFile(ctx.OutputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			file.WriteString(str + "\n")
			file.Close()
		}
		ctx.mu.Unlock()
	}

	atomic.AddInt64(&ctx.SuccessCount, 1)
}

func New(threads int, scanFunc QueueScannerScanFunc) *QueueScanner {
	scanner := &QueueScanner{
		threads:  threads,
		scanFunc: scanFunc,
		queue:    make(chan string, threads*2),
		ctx:      &Ctx{},
	}

	for i := 0; i < scanner.threads; i++ {
		scanner.wg.Add(1)
		go scanner.run()
	}

	return scanner
}

func (qs *QueueScanner) SetOptions(hostList []string, outputFile string, statInterval float64) {
	qs.ctx.hostList = hostList
	qs.ctx.OutputFile = outputFile
	qs.ctx.statInterval = int64(statInterval * 1e9)
}

func (qs *QueueScanner) Start() {
	qs.ctx.startTime = nowNano()
	hideCursor()
	defer showCursor()

	for _, host := range qs.ctx.hostList {
		qs.queue <- host
	}
	close(qs.queue)

	qs.wg.Wait()

	atomic.StoreInt64(&qs.ctx.lastStatTime, 0)
	qs.ctx.LogStat()
	fmt.Println()
}

func (qs *QueueScanner) run() {
	defer qs.wg.Done()

	for {
		host, ok := <-qs.queue
		if !ok {
			break
		}

		qs.scanFunc(qs.ctx, host)

		atomic.AddInt64(&qs.ctx.ScanComplete, 1)
		qs.ctx.LogStat()
	}
}
