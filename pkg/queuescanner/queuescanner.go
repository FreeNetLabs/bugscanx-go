// Package queuescanner provides a concurrent task execution framework
// with progress tracking and result management capabilities.
//
// This package implements a thread-pool pattern for executing scanning
// operations concurrently while providing real-time progress updates,
// result logging, and file output management. It's designed specifically
// for network scanning applications where hundreds or thousands of targets
// need to be processed efficiently.
//
// The package features:
//   - Configurable thread pool size for optimal resource utilization
//   - Real-time progress tracking with percentage completion
//   - Automatic result logging and file output management
//   - Terminal cursor management for clean progress display
//   - Thread-safe operations with proper synchronization
//
// Example usage:
//
//	scanner := queuescanner.NewQueueScanner(64, myScanFunction)
//	scanner.Add(&QueueScannerScanParams{Name: "target1", Data: "example.com"})
//	scanner.Add(&QueueScannerScanParams{Name: "target2", Data: "google.com"})
//	scanner.SetOutputFile("results.txt")
//	scanner.Start()
package queuescanner

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/term"
)

// Ctx represents the execution context for queue scanner operations.
// It maintains the scanning state, progress counters, and provides
// methods for logging and result reporting. This context is passed
// to all scanning functions to enable consistent reporting and
// progress tracking across concurrent operations.
type Ctx struct {
	// ScanComplete tracks the total number of completed scan operations (atomic)
	ScanComplete int64

	// ScanSuccessCount tracks the number of successful scan operations (atomic)
	ScanSuccessCount int64

	// dataList contains all scan parameters that will be processed
	dataList []*QueueScannerScanParams

	// mx provides thread-safe access to shared resources like file operations
	mx sync.Mutex

	// OutputFile specifies the path where successful results should be saved
	OutputFile string
}

// Log prints a message to stdout with proper line clearing and formatting.
// This method ensures clean output by clearing the current line before
// printing the new message, preventing interference with progress displays.
//
// Parameters:
//   - a: Variable number of arguments to be printed (similar to fmt.Print)
func (c *Ctx) Log(a ...any) {
	fmt.Printf("\r\033[2K%s\n", fmt.Sprint(a...))
}

// Logf prints a formatted message to stdout with proper line clearing.
// This method combines formatting with clean output display, ensuring
// that formatted messages don't interfere with progress indicators.
//
// Parameters:
//   - f: Format string (similar to fmt.Printf)
//   - a: Variable number of arguments for the format string
func (c *Ctx) Logf(f string, a ...any) {
	c.Log(fmt.Sprintf(f, a...))
}

// LogReplace displays a real-time progress update without creating new lines.
// This method shows scanning progress with completion percentage, counters,
// and current target information. It automatically handles terminal width
// to prevent line wrapping and maintains a clean progress display.
//
// The progress format includes:
//   - Completion percentage
//   - Completed vs total scan count
//   - Successful scan count
//   - Current target information
//
// Parameters:
//   - a: Variable number of strings to be joined and displayed as current status
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

// LogReplacef displays a formatted real-time progress update.
// This method combines formatting capabilities with progress display,
// allowing for complex status messages while maintaining clean output.
//
// Parameters:
//   - f: Format string for the status message
//   - a: Variable number of arguments for the format string
func (c *Ctx) LogReplacef(f string, a ...any) {
	c.LogReplace(fmt.Sprintf(f, a...))
}

// ScanSuccess records a successful scan result and optionally saves it to file.
// This method handles both in-memory success counting and persistent file
// storage of results. File operations are thread-safe through mutex locking.
//
// The method performs the following operations:
//   - Increments the success counter atomically
//   - Writes the result to the output file if configured
//   - Handles file creation and appending automatically
//
// Parameters:
//   - a: The result data (typically a string) to be recorded and saved
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

// QueueScannerScanParams represents the parameters for a single scan operation.
// This struct encapsulates all the information needed to perform one scan task,
// including identification and payload data.
type QueueScannerScanParams struct {
	// Name is a human-readable identifier for the scan target (used in progress display)
	Name string

	// Data contains the actual payload/parameters needed by the scan function
	Data any
}

// QueueScannerScanFunc defines the signature for scan worker functions.
// All scanning operations must implement this interface to be compatible
// with the queue scanner framework.
//
// Parameters:
//   - c: Execution context for logging and result reporting
//   - a: Scan parameters containing target information and payload data
type QueueScannerScanFunc func(c *Ctx, a *QueueScannerScanParams)

// QueueScannerDoneFunc defines the signature for completion callback functions.
// This function type can be used to perform cleanup or final processing
// after all scanning operations have completed.
//
// Parameters:
//   - c: Execution context with final statistics and state information
type QueueScannerDoneFunc func(c *Ctx)

// QueueScanner implements a concurrent task execution engine with progress tracking.
// It manages a pool of worker goroutines that process scan tasks from a queue,
// providing real-time progress updates and result management.
//
// The scanner uses a buffered channel as a task queue and spawns a configurable
// number of worker goroutines to process tasks concurrently. It provides
// thread-safe progress tracking and result reporting throughout the execution.
type QueueScanner struct {
	// threads specifies the number of worker goroutines to spawn
	threads int

	// scanFunc is the function that will be called for each scan task
	scanFunc QueueScannerScanFunc

	// queue is the buffered channel that holds pending scan tasks
	queue chan *QueueScannerScanParams

	// wg coordinates the lifecycle of worker goroutines
	wg sync.WaitGroup

	// ctx provides the execution context shared among all workers
	ctx *Ctx
}

// NewQueueScanner creates and initializes a new queue scanner instance.
// This function sets up the thread pool, initializes the task queue,
// and starts all worker goroutines ready to process tasks.
//
// The queue buffer size is set to twice the thread count to ensure
// optimal throughput and prevent blocking when adding tasks.
//
// Parameters:
//   - threads: Number of worker goroutines to spawn for concurrent processing
//   - scanFunc: The function that will be executed for each scan task
//
// Returns:
//   - *QueueScanner: Fully initialized and ready-to-use scanner instance
//
// Example:
//
//	scanner := NewQueueScanner(32, func(ctx *Ctx, params *QueueScannerScanParams) {
//		// Perform scanning logic here
//		target := params.Data.(string)
//		// ... scan target ...
//		ctx.ScanSuccess(fmt.Sprintf("Result: %s", target))
//	})
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
// This method runs in each worker goroutine and continuously processes
// tasks from the queue until the queue is closed. It handles task
// execution, progress updates, and proper cleanup.
//
// The worker performs the following operations:
//   - Receives tasks from the queue channel
//   - Executes the scan function with proper context
//   - Updates progress counters atomically
//   - Displays real-time progress information
//   - Handles graceful shutdown when queue is closed
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

// Add enqueues one or more scan tasks for processing.
// This method adds tasks to the internal data list that will be
// processed when Start() is called. Tasks can be added individually
// or in batches for convenience.
//
// Parameters:
//   - dataList: Variable number of scan parameters to be queued for processing
//
// Example:
//
//	scanner.Add(&QueueScannerScanParams{Name: "target1", Data: "example.com"})
//	scanner.Add(
//		&QueueScannerScanParams{Name: "target2", Data: "google.com"},
//		&QueueScannerScanParams{Name: "target3", Data: "github.com"},
//	)
func (s *QueueScanner) Add(dataList ...*QueueScannerScanParams) {
	s.ctx.dataList = append(s.ctx.dataList, dataList...)
}

// Start begins the scanning process and blocks until all tasks are completed.
// This method feeds all queued tasks to the worker goroutines, manages
// the task queue lifecycle, and handles terminal display for clean output.
//
// The process includes:
//   - Hiding the terminal cursor for clean progress display
//   - Feeding all tasks to worker goroutines via the queue channel
//   - Closing the queue to signal completion to workers
//   - Waiting for all workers to finish processing
//   - Restoring the terminal cursor
//
// This method blocks until all scanning operations are complete.
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

// hideCursor sends ANSI escape code to hide the terminal cursor.
// This provides cleaner progress display by preventing cursor flicker
// during real-time updates.
func hideCursor() {
	fmt.Print("\033[?25l")
}

// showCursor sends ANSI escape code to restore the terminal cursor.
// This restores normal cursor visibility after scanning operations
// are completed.
func showCursor() {
	fmt.Print("\033[?25h")
}

// SetOutputFile configures the file path where successful scan results will be saved.
// Results are automatically appended to this file as they are generated,
// with each result on a separate line. The file is created if it doesn't exist.
//
// Parameters:
//   - filename: Path to the output file where results should be saved
//
// Example:
//
//	scanner.SetOutputFile("scan_results.txt")
func (s *QueueScanner) SetOutputFile(filename string) {
	s.ctx.OutputFile = filename
}
