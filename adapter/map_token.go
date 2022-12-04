package adapter

import (
	"context"

	"github.com/w-woong/auth/entity"
	"github.com/w-woong/common"
)

type MapToken struct {
	m map[string]entity.Token
}

func NewMapToken() *MapToken {
	return &MapToken{
		m: make(map[string]entity.Token),
	}
}

func (a *MapToken) Create(ctx context.Context, tx common.TxController, token entity.Token) (int64, error) {
	a.m[token.ID] = token
	return 1, nil
}

func (a *MapToken) Read(ctx context.Context, tx common.TxController, id string) (entity.Token, error) {
	if token, ok := a.m[id]; ok {
		return token, nil
	}
	return entity.NilToken, common.ErrRecordNotFound
}

func (a *MapToken) ReadNoTx(ctx context.Context, id string) (entity.Token, error) {
	if token, ok := a.m[id]; ok {
		return token, nil
	}
	return entity.NilToken, common.ErrRecordNotFound
}

func (a *MapToken) Delete(ctx context.Context, tx common.TxController, id string) (int64, error) {
	delete(a.m, id)
	return 1, nil
}
