package array

import (
	"context"
	"net/http"
	"testing"
)

// Protocol-2 POST /api/parity/action semantics (upstream parity.service.ts /
// webGUI ArrayOperation.page form fields).
func TestParityActionV2(t *testing.T) {
	cases := []struct {
		action, varIni string
		correct        bool
		wantField      string
		wantCorrect    bool
		wantStatus     int
	}{
		{"start", varIdle, false, "cmdCheck", false, 0},
		{"start", varIdle, true, "cmdCheck", true, 0},
		{"start", varRunning, false, "", false, http.StatusConflict},
		{"start", varStopped, false, "", false, http.StatusConflict},
		{"pause", varRunning, false, "cmdCheckPause", false, 0},
		{"pause", varPaused, false, "", false, http.StatusConflict},
		{"pause", varIdle, false, "", false, http.StatusConflict},
		{"resume", varPaused, false, "cmdCheckResume", false, 0},
		{"resume", varRunning, false, "", false, http.StatusConflict},
		{"cancel", varRunning, false, "cmdCheckCancel", false, 0},
		{"cancel", varPaused, false, "cmdCheckCancel", false, 0},
		{"cancel", varIdle, false, "", false, http.StatusConflict},
		{"restart", varIdle, false, "", false, http.StatusBadRequest},
	}
	for _, c := range cases {
		f := withFixtures(t, c.varIni)
		err := ParityAction(context.Background(), c.action, c.correct)
		if c.wantStatus != 0 {
			if StatusOf(err) != c.wantStatus || len(f.calls) != 0 {
				t.Errorf("%s: err=%v calls=%v, want %d", c.action, err, f.calls, c.wantStatus)
			}
			continue
		}
		if err != nil || len(f.calls) != 1 {
			t.Fatalf("%s: err=%v calls=%v", c.action, err, f.calls)
		}
		p := f.calls[0]
		if _, ok := p[c.wantField]; !ok {
			t.Errorf("%s: missing %s in %v", c.action, c.wantField, p)
		}
		if (p.Get("optionCorrect") == "correct") != c.wantCorrect {
			t.Errorf("%s: optionCorrect=%q", c.action, p.Get("optionCorrect"))
		}
	}
}
