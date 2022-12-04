package adapter

import (
	"context"
	"errors"

	"github.com/w-woong/auth/entity"
	"github.com/w-woong/common"
)

type MapAuthRequest struct {
	m map[string]entity.AuthRequest
	// l sync.RWMutex
}

func NewMapAuthRequest() *MapAuthRequest {
	return &MapAuthRequest{
		m: make(map[string]entity.AuthRequest),
	}
}
func (a *MapAuthRequest) Create(ctx context.Context, tx common.TxController, authRequest entity.AuthRequest) (int64, error) {
	// a.l.Lock()
	// defer a.l.Unlock()

	a.m[authRequest.ID] = authRequest

	return 1, nil
}
func (a *MapAuthRequest) Read(ctx context.Context, tx common.TxController, id string) (entity.AuthRequest, error) {
	// a.l.RLock()
	// defer a.l.RUnlock()

	if authRequest, ok := a.m[id]; ok {
		return authRequest, nil
	}

	return entity.NilAuthRequest, errors.New("cannot find auth request")
}
func (a *MapAuthRequest) ReadNoTx(ctx context.Context, id string) (entity.AuthRequest, error) {
	// a.l.RLock()
	// defer a.l.RUnlock()

	if authRequest, ok := a.m[id]; ok {
		return authRequest, nil
	}

	return entity.NilAuthRequest, errors.New("cannot find auth request")
}
func (a *MapAuthRequest) Delete(ctx context.Context, tx common.TxController, id string) (int64, error) {
	// a.l.Lock()
	// defer a.l.Unlock()

	delete(a.m, id)

	return 1, nil
}
