package port

import (
	"context"

	"github.com/w-woong/auth/entity"
	"github.com/w-woong/common"
)

type TokenRepo interface {
	// Create save token to a repository.
	Create(ctx context.Context, tx common.TxController, token entity.Token) (int64, error)

	// Read reads token by id.
	Read(ctx context.Context, tx common.TxController, id string) (entity.Token, error)
	ReadNoTx(ctx context.Context, id string) (entity.Token, error)

	// Delete deletes a token from a repository.
	Delete(ctx context.Context, tx common.TxController, id string) (int64, error)
}
