package tests

import (
	"sync"
	"time"

	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/utils/gg"
)

func CreateMockAppPasswordRepo() *MockedAppPasswordRepo {
	return &MockedAppPasswordRepo{
		Data: map[string]*model.AppPassword{},
	}
}

type MockedAppPasswordRepo struct {
	mu    sync.Mutex
	Error error
	// Data maps app password ID to the stored entity. Stored entities use
	// the same plaintext for Password and NewPassword (no encryption in
	// the mock) so tests can compare directly.
	Data map[string]*model.AppPassword
}

func (m *MockedAppPasswordRepo) Put(ap *model.AppPassword) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Error != nil {
		return m.Error
	}
	if ap.ID == "" {
		ap.ID = ap.UserID + ":" + ap.Name
	}
	if ap.CreatedAt.IsZero() {
		ap.CreatedAt = time.Now()
	}
	plain := ap.NewPassword
	stored := *ap
	stored.Password = plain
	stored.NewPassword = ""
	m.Data[ap.ID] = &stored
	ap.Password = plain
	ap.NewPassword = ""
	return nil
}

func (m *MockedAppPasswordRepo) Get(id string) (*model.AppPassword, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Error != nil {
		return nil, m.Error
	}
	ap, ok := m.Data[id]
	if !ok {
		return nil, model.ErrNotFound
	}
	cp := *ap
	cp.Password = ""
	return &cp, nil
}

func (m *MockedAppPasswordRepo) List(userID string) (model.AppPasswords, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Error != nil {
		return nil, m.Error
	}
	var out model.AppPasswords
	for _, ap := range m.Data {
		if ap.UserID != userID {
			continue
		}
		cp := *ap
		cp.Password = ""
		out = append(out, cp)
	}
	return out, nil
}

func (m *MockedAppPasswordRepo) FindActiveByUser(userID string) (model.AppPasswords, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Error != nil {
		return nil, m.Error
	}
	var out model.AppPasswords
	for _, ap := range m.Data {
		if ap.UserID != userID || ap.RevokedAt != nil {
			continue
		}
		out = append(out, *ap)
	}
	return out, nil
}

func (m *MockedAppPasswordRepo) Revoke(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Error != nil {
		return m.Error
	}
	ap, ok := m.Data[id]
	if !ok {
		return model.ErrNotFound
	}
	if ap.RevokedAt != nil {
		return model.ErrNotFound
	}
	ap.RevokedAt = gg.P(time.Now())
	return nil
}

func (m *MockedAppPasswordRepo) RevokeAllForUser(userID string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Error != nil {
		return 0, m.Error
	}
	var n int64
	for _, ap := range m.Data {
		if ap.UserID == userID && ap.RevokedAt == nil {
			ap.RevokedAt = gg.P(time.Now())
			n++
		}
	}
	return n, nil
}

func (m *MockedAppPasswordRepo) Touch(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Error != nil {
		return m.Error
	}
	ap, ok := m.Data[id]
	if !ok {
		return model.ErrNotFound
	}
	if ap.RevokedAt != nil {
		// Mirror the real repo: don't bump last_used_at on revoked rows.
		return nil
	}
	ap.LastUsedAt = gg.P(time.Now())
	return nil
}
