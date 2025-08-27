// Package queuescanner provides concurrent task execution with progress tracking.
package queuescanner

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/term"
)

// Ctx provides execution context for queue scanner operations.
type Ctx struct {
	ScanComplete     int64                     // Total completed scans (atomic)
	ScanSuccessCount int64                     // Successful scans (atomic)
	dataList         []*QueueScannerScanParams // Scan parameters to process
	mx               sync.Mutex                // Thread-safe access to shared resources
	OutputFile       string                    // Output file path for results
}

// Log prints a message with proper line clearing.
func (c *Ctx) Log(a ...any) {
	fmt.Printf("\r\033[2K%s\n", fmt.Sprint(a...))
}

// Logf prints a formatted message with line clearing.
func (c *Ctx) Logf(f string, a ...any) {
	c.Log(fmt.Sprintf(f, a...))
}

// LogReplace displays real-time progress updates without newlines.
func (c *Ctx) LogReplace(a ...string) {
	scanSuccess := atomic.LoadInt64(&c.ScanSuccessCount)
	scanComplete := atomic.LoadInt64(&c.ScanComplete)
	scanCompletePercentage := float64(scanComplete) / float64(len(c.dataList)) * 100

	s := fmt.Sprintf(
		"%.2f%% - C: %d / %d - S: %d - %s",
		scanCompletePercentage,
		scanComplete,
		len(c.dataList),
		scanSuccess,
		strings.Join(a, " "),
	)

	// Handle terminal width to prevent wrapping
	if termWidth, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
		w := termWidth - 3
		if len(s) >= w {
			s = s[:w] + "..."
		}
	}

	// Print progress update without newline
	fmt.Print("\r\033[2K", s, "\r")
}

// LogReplacef displays formatted real-time progress updates.
func (c *Ctx) LogReplacef(f string, a ...any) {
	c.LogReplace(fmt.Sprintf(f, a...))
}

// ScanSuccess records a successful scan and saves to file if configured.
func (c *Ctx) ScanSuccess(a any) {
	// Save to file if result is a string and output file is configured
	if s, ok := a.(string); ok && c.OutputFile != "" {
		c.mx.Lock()
		f, err := os.OpenFile(c.OutputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			f.WriteString(s + "\n")
			f.Close()
		}
		c.mx.Unlock()
	}

	// Increment success counter atomically
	atomic.AddInt64(&c.ScanSuccessCount, 1)
}

// QueueScannerScanParams contains parameters for a single scan operation.
type QueueScannerScanParams struct {
	Name string // Human-readable identifier for progress display
	Data any    // Payload data for the scan function
}

// QueueScannerScanFunc defines the signature for scan worker functions.
type QueueScannerScanFunc func(c *Ctx, a *QueueScannerScanParams)

// QueueScannerDoneFunc defines the signature for completion callbacks.
type QueueScannerDoneFunc func(c *Ctx)

// QueueScanner manages concurrent task execution with progress tracking.
type QueueScanner struct {
	threads  int                          // Number of worker goroutines
	scanFunc QueueScannerScanFunc         // Function called for each scan task
	queue    chan *QueueScannerScanParams // Buffered channel for pending tasks
	wg       sync.WaitGroup               // Coordinates worker lifecycle
	ctx      *Ctx                         // Shared execution context
}

// NewQueueScanner creates a new scanner with the specified thread count and scan function.
func NewQueueScanner(threads int, scanFunc QueueScannerScanFunc) *QueueScanner {
	t := &QueueScanner{
		threads:  threads,
		scanFunc: scanFunc,
		queue:    make(chan *QueueScannerScanParams, threads*2),
		ctx:      &Ctx{},
	}

	// Start worker goroutines
	for i := 0; i < t.threads; i++ {
		go t.run()
	}

	return t
}

// run implements the worker goroutine logic for processing scan tasks.
func (s *QueueScanner) run() {
	s.wg.Add(1)
	defer s.wg.Done()

	for {
		// Receive next task from queue
		a, ok := <-s.queue
		if !ok {
			break // Queue closed, exit worker
		}

		// Execute scan function
		s.scanFunc(s.ctx, a)

		// Update progress counters and display
		atomic.AddInt64(&s.ctx.ScanComplete, 1)
		s.ctx.LogReplace(a.Name)
	}
}

// Add enqueues scan tasks for processing.
func (s *QueueScanner) Add(dataList ...*QueueScannerScanParams) {
	s.ctx.dataList = append(s.ctx.dataList, dataList...)
}

// Start begins scanning and blocks until all tasks complete.
func (s *QueueScanner) Start() {
	hideCursor()
	defer showCursor()

	// Feed all tasks to the queue
	for _, data := range s.ctx.dataList {
		s.queue <- data
	}
	close(s.queue)

	// Wait for all workers to complete
	s.wg.Wait()
}

// hideCursor hides the terminal cursor for cleaner progress display.
func hideCursor() {
	fmt.Print("\033[?25l")
}

// showCursor restores the terminal cursor.
func showCursor() {
	fmt.Print("\033[?25h")
}

// SetOutputFile configures where successful results are saved.
func (s *QueueScanner) SetOutputFile(filename string) {
	s.ctx.OutputFile = filename
}
