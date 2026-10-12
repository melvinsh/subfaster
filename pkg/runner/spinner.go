package runner

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/term"
)

// ANSI escapes — hand-rolled to keep this dependency-free.
const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiCyan   = "\033[36m"
	ansiYellow = "\033[33m"
	ansiGreen  = "\033[32m"
)

// spinFrames is a braille spinner; the tight cycle reads as "fast".
var spinFrames = []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")

const cometTrack = 18

// cometPos bounces a position back and forth across a track of the given width,
// so the comet sweeps left→right→left forever. Pure so it can be tested.
func cometPos(frame, track int) int {
	period := 2*track - 2
	p := frame % period
	if p >= track {
		p = period - p
	}
	return p
}

// speedometer draws a live single-line animation on stderr while enumeration
// runs, leading with throughput (subdomains/sec) to convey speed. It writes to
// stderr so piped stdout stays clean, and is a no-op when stderr is not a TTY.
// One meter covers a whole batch of domains; all methods are nil-safe.
type speedometer struct {
	label func() string
	count atomic.Int64
	stop  chan struct{}
	done  chan struct{}

	mu    sync.Mutex // serializes drawing with Print
	drawn bool       // a frame is on screen and must be cleared before other output
}

func newSpeedometer(label func() string) *speedometer {
	return &speedometer{label: label, stop: make(chan struct{}), done: make(chan struct{})}
}

// Add counts newly found subdomains.
func (s *speedometer) Add(n int64) {
	if s != nil {
		s.count.Add(n)
	}
}

// Print runs fn with the meter line cleared, so output written to the terminal
// by fn doesn't land on top of the animation. The next tick redraws it.
func (s *speedometer) Print(fn func()) {
	if s == nil {
		fn()
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.drawn {
		fmt.Fprint(os.Stderr, "\r\033[K")
		s.drawn = false
	}
	fn()
}

func (s *speedometer) start() {
	if !term.IsTerminal(int(os.Stderr.Fd())) {
		close(s.done)
		return
	}
	go s.run()
}

func (s *speedometer) run() {
	defer close(s.done)
	fmt.Fprint(os.Stderr, "\033[?25l") // hide cursor
	start := time.Now()
	ticker := time.NewTicker(60 * time.Millisecond)
	defer ticker.Stop()

	track := make([]rune, cometTrack)
	for frame := 0; ; frame++ {
		select {
		case <-s.stop:
			s.mu.Lock()
			fmt.Fprint(os.Stderr, "\r\033[K\033[?25h") // clear line, show cursor
			s.mu.Unlock()
			return
		case <-ticker.C:
			elapsed := time.Since(start).Seconds()
			n := s.count.Load()
			var rate float64
			if elapsed > 0 {
				rate = float64(n) / elapsed
			}

			for i := range track {
				track[i] = '·'
			}
			track[cometPos(frame, cometTrack)] = '⚡'

			s.mu.Lock()
			fmt.Fprintf(os.Stderr,
				"\r%s%c%s %s%s%s [%s%s%s] %s%d%s found  %s%.0f/s%s  %s%.1fs%s",
				ansiYellow, spinFrames[frame%len(spinFrames)], ansiReset,
				ansiBold, s.label(), ansiReset,
				ansiCyan, string(track), ansiReset,
				ansiBold+ansiGreen, n, ansiReset,
				ansiBold+ansiYellow, rate, ansiReset,
				ansiDim, elapsed, ansiReset,
			)
			s.drawn = true
			s.mu.Unlock()
		}
	}
}

// stop ends the animation and clears the line. Safe even if start() was a no-op.
func (s *speedometer) Stop() {
	if s == nil {
		return
	}
	select {
	case <-s.done: // never started (not a TTY)
	default:
		close(s.stop)
		<-s.done
	}
}
