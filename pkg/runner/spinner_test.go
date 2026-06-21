package runner

import "testing"

func TestCometPos(t *testing.T) {
	// track=4 -> period=6, sweep should be 0,1,2,3,2,1 then repeat.
	want := []int{0, 1, 2, 3, 2, 1, 0, 1}
	for frame, exp := range want {
		if got := cometPos(frame, 4); got != exp {
			t.Errorf("cometPos(%d,4) = %d, want %d", frame, got, exp)
		}
	}
	// Never leaves the track for any frame.
	for frame := 0; frame < 1000; frame++ {
		if p := cometPos(frame, cometTrack); p < 0 || p >= cometTrack {
			t.Fatalf("cometPos(%d,%d) = %d out of range", frame, cometTrack, p)
		}
	}
}
