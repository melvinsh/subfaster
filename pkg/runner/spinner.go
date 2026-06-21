package runner

import (
	"fmt"
	"os"
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
type speedometer struct {
	domain string
	count  *atomic.Int64
	stop   chan struct{}
	done   chan struct{}
}

func newSpeedometer(domain string, count *atomic.Int64) *speedometer {
	return &speedometer{domain: domain, count: count, stop: make(chan struct{}), done: make(chan struct{})}
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
			fmt.Fprint(os.Stderr, "\r\033[K\033[?25h") // clear line, show cursor
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

			fmt.Fprintf(os.Stderr,
				"\r%s%c%s %s%s%s [%s%s%s] %s%d%s found  %s%.0f/s%s  %s%.1fs%s",
				ansiYellow, spinFrames[frame%len(spinFrames)], ansiReset,
				ansiBold, s.domain, ansiReset,
				ansiCyan, string(track), ansiReset,
				ansiBold+ansiGreen, n, ansiReset,
				ansiBold+ansiYellow, rate, ansiReset,
				ansiDim, elapsed, ansiReset,
			)
		}
	}
}

// stop ends the animation and clears the line. Safe even if start() was a no-op.
func (s *speedometer) Stop() {
	select {
	case <-s.done: // never started (not a TTY)
	default:
		close(s.stop)
		<-s.done
	}
}
