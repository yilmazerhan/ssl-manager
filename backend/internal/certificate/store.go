package certificate

import (
	"fmt"
	"sort"
	"sync"
)

type Store interface {
	List() []Certificate
	Get(id string) (Certificate, bool)
	Put(c Certificate)
	Versions(certificateID string) []Version
	AddVersion(v Version)
}

// MemoryStore is a placeholder for the PostgreSQL-backed store described in
// the plan (docs/plan.html, section 03). It exists so the API layer and the
// renewal/order logic have a real interface to depend on before persistence
// is wired up.
type MemoryStore struct {
	mu       sync.RWMutex
	certs    map[string]Certificate
	versions map[string][]Version
	seq      int
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		certs:    make(map[string]Certificate),
		versions: make(map[string][]Version),
	}
}

func (s *MemoryStore) List() []Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Certificate, 0, len(s.certs))
	for _, c := range s.certs {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CommonName < out[j].CommonName })
	return out
}

func (s *MemoryStore) Get(id string) (Certificate, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.certs[id]
	return c, ok
}

func (s *MemoryStore) Put(c Certificate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.certs[c.ID] = c
}

func (s *MemoryStore) Versions(certificateID string) []Version {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Version(nil), s.versions[certificateID]...)
}

func (s *MemoryStore) AddVersion(v Version) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.versions[v.CertificateID] = append(s.versions[v.CertificateID], v)
}

func (s *MemoryStore) NextID(prefix string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	return fmt.Sprintf("%s_%04d", prefix, s.seq)
}
