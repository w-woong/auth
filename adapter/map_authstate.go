package adapter

import (
	"context"
	"errors"

	"github.com/w-woong/auth/entity"
	"github.com/w-woong/common"
)

type MapAuthState struct {
	m map[string]entity.AuthState
}

func NewMapAuthState() *MapAuthState {
	return &MapAuthState{
		m: make(map[string]entity.AuthState),
	}
}
func (a *MapAuthState) Create(ctx context.Context, tx common.TxController, authState entity.AuthState) (int64, error) {
	a.m[authState.State] = authState
	return 1, nil
}
func (a *MapAuthState) ReadByState(ctx context.Context, tx common.TxController, state string) (entity.AuthState, error) {
	if authState, ok := a.m[state]; ok {
		return authState, nil
	}
	return entity.NilAuthState, errors.New("cannot find state")
}
func (a *MapAuthState) DeleteByState(ctx context.Context, tx common.TxController, state string) (int64, error) {
	delete(a.m, state)
	return 1, nil
}
