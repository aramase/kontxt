package tts

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsScopeSubset(t *testing.T) {
	tests := []struct {
		name      string
		requested string
		existing  string
		want      bool
	}{
		{"exact match", "read:data", "read:data", true},
		{"subset", "read:data", "read:data write:reports execute:analysis", true},
		{"not subset", "admin:all", "read:data write:reports", false},
		{"partial overlap", "read:data admin:all", "read:data write:reports", false},
		{"empty requested", "", "read:data", true},
		{"empty existing", "read:data", "", false},
		{"both empty", "", "", true},
		{"multiple subset", "read:data write:reports", "read:data write:reports execute:analysis", true},
		{"same scopes different order", "write:reports read:data", "read:data write:reports", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isScopeSubset(tt.requested, tt.existing)
			assert.Equal(t, tt.want, got)
		})
	}
}
