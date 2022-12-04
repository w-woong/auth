package port

import (
	"context"

	"github.com/w-woong/auth/entity"
	"github.com/w-woong/common"
)

type AuthRequestRepo interface {
	Create(ctx context.Context, tx common.TxController, authRequest entity.AuthRequest) (int64, error)
	Read(ctx context.Context, tx common.TxController, id string) (entity.AuthRequest, error)
	ReadNoTx(ctx context.Context, id string) (entity.AuthRequest, error)
	Delete(ctx context.Context, tx common.TxController, id string) (int64, error)
}
