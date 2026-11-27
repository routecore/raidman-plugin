package docker

import (
	"encoding/json"
	"testing"
)

func TestStripEnvOnlyTouchesCopy(t *testing.T) {
	raw := []byte(`{"Id":"abc","Name":"/plex","Config":{"Image":"plex","Env":["PLEX_CLAIM=secret"]}}`)
	var a, b map[string]any
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	StripEnv(a)
	if _, ok := a["Config"].(map[string]any)["Env"]; ok {
		t.Fatal("Env not stripped")
	}
	if a["Config"].(map[string]any)["Image"] != "plex" {
		t.Fatal("other Config fields must stay")
	}
	if _, ok := b["Config"].(map[string]any)["Env"]; !ok {
		t.Fatal("independently decoded map must be unaffected")
	}
	StripEnv(map[string]any{"Config": nil}) // must not panic
}
