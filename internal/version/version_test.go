package version

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"
)

func TestPrint(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		gitCommit string
		buildDate string
	}{
		{
			name:      "default values",
			version:   "dev",
			gitCommit: "unknown",
			buildDate: "unknown",
		},
		{
			name:      "release values",
			version:   "v0.0.1",
			gitCommit: "abc1234",
			buildDate: "2026-04-23T00:00:00Z",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore original values.
			origVersion, origCommit, origDate := Version, GitCommit, BuildDate
			t.Cleanup(func() {
				Version, GitCommit, BuildDate = origVersion, origCommit, origDate
			})

			Version = tt.version
			GitCommit = tt.gitCommit
			BuildDate = tt.buildDate

			// Capture stdout.
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			origStdout := os.Stdout
			os.Stdout = w

			Print()

			w.Close()
			os.Stdout = origStdout

			var buf bytes.Buffer
			if _, err := io.Copy(&buf, r); err != nil {
				t.Fatal(err)
			}

			var got map[string]string
			if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
				t.Fatalf("failed to parse JSON output: %v\noutput: %s", err, buf.String())
			}

			if got["version"] != tt.version {
				t.Errorf("version = %q, want %q", got["version"], tt.version)
			}
			if got["gitCommit"] != tt.gitCommit {
				t.Errorf("gitCommit = %q, want %q", got["gitCommit"], tt.gitCommit)
			}
			if got["buildDate"] != tt.buildDate {
				t.Errorf("buildDate = %q, want %q", got["buildDate"], tt.buildDate)
			}
		})
	}
}
