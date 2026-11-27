package httperr

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
)

func TestNotFound(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", NotFound("disk %q not found", "disk9"))
	if StatusOf(err) != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want 422 (never 404)", StatusOf(err))
	}
	if CodeOf(err) != CodeNotFound {
		t.Errorf("code = %q", CodeOf(err))
	}
	if NotFound("x %d", 1).Error() != "x 1" {
		t.Error("message not formatted")
	}
}

func TestCodeOfOther(t *testing.T) {
	if CodeOf(New(http.StatusConflict, "busy")) != "" || CodeOf(errors.New("plain")) != "" || CodeOf(nil) != "" {
		t.Error("unexpected code")
	}
	if StatusOf(errors.New("plain")) != http.StatusInternalServerError {
		t.Error("plain errors must map to 500")
	}
}
