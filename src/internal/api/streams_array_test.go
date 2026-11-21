package api

import (
	"encoding/json"
	"testing"

	"github.com/routecore/raidman-plugin/src/internal/domain"
)

func TestArrayStatusMessageShape(t *testing.T) {
	action := "recon D1"
	st := &domain.ArrayStatus{
		State:             "STARTED",
		ParityCheckStatus: &domain.ParityCheckStatus{Status: "RUNNING_CHECK", Running: true, Action: action},
		Health:            &domain.ArrayHealth{ResyncAction: &action, NumDisabled: 1},
	}
	var msg map[string]map[string]any
	b, _ := json.Marshal(arrayStatusMessage(st))
	if err := json.Unmarshal(b, &msg); err != nil {
		t.Fatal(err)
	}
	if msg["health"]["resyncAction"] != action || msg["health"]["numDisabled"] != float64(1) {
		t.Fatalf("top-level health missing: %s", b)
	}
	pcs, _ := msg["array"]["parityCheckStatus"].(map[string]any)
	if pcs["action"] != action {
		t.Fatalf("parityCheckStatus.action missing: %s", b)
	}
	if _, nested := msg["array"]["health"]; nested {
		t.Fatalf("health must sit next to array, not inside it: %s", b)
	}

	st.Health = nil
	st.ParityCheckStatus = &domain.ParityCheckStatus{Status: "IDLE"}
	b, _ = json.Marshal(arrayStatusMessage(st))
	var idle map[string]map[string]any
	_ = json.Unmarshal(b, &idle)
	if _, ok := idle["health"]; ok {
		t.Fatalf("nil health must be omitted: %s", b)
	}
	if _, ok := idle["array"]["parityCheckStatus"].(map[string]any)["action"]; ok {
		t.Fatalf("idle action must be omitted: %s", b)
	}
}
