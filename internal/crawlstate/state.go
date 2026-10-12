// Package crawlstate persists just enough about a scan — which URLs have
// already been visited and which response bodies have already been seen —
// to make two features work: resume (skip work a previous run already
// completed, so an interrupted long scan can be picked up again) and
// duplicate-content suppression during crawling (never re-crawl a page
// whose body is byte-identical to one already fetched, however many
// different URLs serve it).
//
// State is stored as a small JSON file so it survives a process restart
// and is easy to inspect by hand; nothing here is security-sensitive.
package crawlstate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// stateVersion lets a future format change refuse to misread old files.
const stateVersion = 1

// persisted is the on-disk shape of the state file.
type persisted struct {
	Version     int               `json:"version"`
	Target      string            `json:"target"`
	UpdatedAt   time.Time         `json:"updated_at"`
	VisitedURLs []string          `json:"visited_urls"`
	ContentHash map[string]string `json:"content_hashes"` // hash -> first URL that produced it
}

// State tracks visited URLs and seen content hashes for one scan target,
// and can persist/reload them.
type State struct {
	mu          sync.Mutex
	target      string
	path        string
	dirty       bool
	visited     map[string]bool
	contentHash map[string]string
}

// New returns an empty in-memory State for target (the -url seed), with no
// backing file. Save() on it is a no-op, which keeps callers simple when
// resume isn't enabled.
func New(target string) *State {
	return &State{
		target:      target,
		visited:     map[string]bool{},
		contentHash: map[string]string{},
	}
}

// Load reads a previously saved state file. A missing file is not an
// error: it just means there is nothing to resume from yet, so an empty
// State is returned. A file for a *different* target is ignored the same
// way, so reusing a state path across scans can't silently skip pages.
func Load(path, target string) (*State, error) {
	st := New(target)
	st.path = path
	if path == "" {
		return st, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return st, nil
		}
		return nil, fmt.Errorf("read scan state: %w", err)
	}
	var p persisted
	if err := json.Unmarshal(b, &p); err != nil {
		// A corrupt/foreign file shouldn't abort the scan; start clean.
		return st, nil
	}
	if p.Version != stateVersion || (p.Target != "" && p.Target != target) {
		return st, nil
	}
	for _, u := range p.VisitedURLs {
		st.visited[u] = true
	}
	for h, u := range p.ContentHash {
		st.contentHash[h] = u
	}
	return st, nil
}

// Visited reports whether url was already crawled (in this run or a
// previous one that was resumed).
func (s *State) Visited(url string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.visited[url]
}

// MarkVisited records url as crawled.
func (s *State) MarkVisited(url string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	if !s.visited[url] {
		s.visited[url] = true
		s.dirty = true
	}
	s.mu.Unlock()
}

// VisitedCount returns how many URLs are marked visited.
func (s *State) VisitedCount() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.visited)
}

// DuplicateContent reports whether body has exactly the same hash as a
// response already seen under a different URL, i.e. this URL serves
// duplicate content that doesn't need crawling again (pagination that
// clamps, an SPA returning the same shell for every route, etc). The first
// sighting of any content is stored and never counts as a duplicate.
func (s *State) DuplicateContent(url, body string) bool {
	if s == nil || body == "" {
		return false
	}
	h := ContentHash(body)
	s.mu.Lock()
	defer s.mu.Unlock()
	if first, ok := s.contentHash[h]; ok && first != url {
		return true
	}
	if _, ok := s.contentHash[h]; !ok {
		s.contentHash[h] = url
		s.dirty = true
	}
	return false
}

// MarkDirty forces the next Save to write, even if nothing changed. Used
// by the periodic autosave so a long stretch with no new content still
// refreshes the file's timestamp.
func (s *State) MarkDirty() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.dirty = true
	s.mu.Unlock()
}

// Save writes the state to disk if a path was configured and there are
// changes since the last save. It's safe to call repeatedly (e.g. from a
// periodic autosave ticker).
func (s *State) Save() error {
	if s == nil || s.path == "" {
		return nil
	}
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	p := persisted{
		Version:     stateVersion,
		Target:      s.target,
		UpdatedAt:   time.Now(),
		VisitedURLs: make([]string, 0, len(s.visited)),
		ContentHash: make(map[string]string, len(s.contentHash)),
	}
	for u := range s.visited {
		p.VisitedURLs = append(p.VisitedURLs, u)
	}
	for h, u := range s.contentHash {
		p.ContentHash[h] = u
	}
	s.dirty = false
	s.mu.Unlock()

	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("encode scan state: %w", err)
	}
	if dir := filepath.Dir(s.path); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o755)
	}
	// Write to a temp file then rename, so an interrupted save can never
	// leave a half-written state file behind.
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return fmt.Errorf("write scan state: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("finalize scan state: %w", err)
	}
	return nil
}

// ContentHash returns a stable hex digest of a response body, used as the
// duplicate-content key. Empty bodies get a distinctive sentinel hash so
// they never collide with real content.
func ContentHash(body string) string {
	if body == "" {
		return "empty"
	}
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}
