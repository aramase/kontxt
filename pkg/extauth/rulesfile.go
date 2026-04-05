package extauth

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"

	"github.com/aramase/kontxt/internal/controller"
)

// RulesLoader loads generation or verification rules from a JSON file
// and watches for changes (e.g., from Kubernetes ConfigMap volume mounts).
type RulesLoader struct {
	path string
	mode string // "generate" or "verify"

	mu              sync.Mutex
	genServer       *GenerationServer
	verifyServer    *Server
	onReloadForTest func() // test hook, called after each reload
}

// NewRulesLoader creates a RulesLoader that reads rules from the given file path.
// mode must be "generate" or "verify".
func NewRulesLoader(path, mode string) *RulesLoader {
	return &RulesLoader{
		path: path,
		mode: mode,
	}
}

// SetGenerationServer sets the generation server to push rules to.
func (r *RulesLoader) SetGenerationServer(s *GenerationServer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.genServer = s
}

// SetVerifyServer sets the verification server to push rules to.
func (r *RulesLoader) SetVerifyServer(s *Server) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.verifyServer = s
}

// LoadOnce reads the rules file and pushes rules to the appropriate server.
// Returns an error if the file cannot be read or parsed.
func (r *RulesLoader) LoadOnce() error {
	data, err := os.ReadFile(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist yet — not an error, ConfigMap may not be populated.
			log.Printf("Rules file %s does not exist yet, starting with empty rules", r.path)
			return nil
		}
		return fmt.Errorf("reading rules file %s: %w", r.path, err)
	}
	return r.applyRules(string(data))
}

func (r *RulesLoader) applyRules(data string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	switch r.mode {
	case "generate":
		rules, err := controller.UnmarshalGenerationRules(data)
		if err != nil {
			return fmt.Errorf("parsing generation rules: %w", err)
		}
		if r.genServer != nil {
			r.genServer.SetGenerationRules(rules)
		}
		log.Printf("Loaded %d generation rules from %s", len(rules), r.path)

	case "verify":
		rules, err := controller.UnmarshalVerificationRules(data)
		if err != nil {
			return fmt.Errorf("parsing verification rules: %w", err)
		}
		if r.verifyServer != nil {
			r.verifyServer.SetVerificationRules(rules)
		}
		log.Printf("Loaded %d verification rules from %s", len(rules), r.path)

	default:
		return fmt.Errorf("unknown mode: %s", r.mode)
	}

	if r.onReloadForTest != nil {
		r.onReloadForTest()
	}
	return nil
}

// WatchAndReload watches the rules file for changes and reloads when updated.
// Kubernetes ConfigMap volume mounts update via symlink swaps, so we watch
// the parent directory for Create events on the target filename.
// This function blocks until the done channel is closed.
func (r *RulesLoader) WatchAndReload(done <-chan struct{}) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("creating fsnotify watcher: %w", err)
	}
	defer watcher.Close()

	// Watch the parent directory — ConfigMap mounts use symlink swaps
	// which appear as Create events in the parent dir.
	dir := filepath.Dir(r.path)
	if err := watcher.Add(dir); err != nil {
		return fmt.Errorf("watching directory %s: %w", dir, err)
	}

	log.Printf("Watching %s for rule updates", dir)

	for {
		select {
		case <-done:
			return nil
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			// ConfigMap symlink swaps generate Create events on the data directory.
			// We reload on any write or create event since the underlying file changed.
			if event.Op&(fsnotify.Create|fsnotify.Write) != 0 {
				if err := r.LoadOnce(); err != nil {
					log.Printf("Error reloading rules: %v", err)
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			log.Printf("Watcher error: %v", err)
		}
	}
}
