package port

import (
	"context"
	"net/http"

	"github.com/w-woong/auth/entity"
	"github.com/w-woong/common"
)

type AuthStateRepo interface {
	Create(ctx context.Context, tx common.TxController, authState entity.AuthState) (int64, error)
	// Read(id string) (entity.AuthState, error)
	ReadByState(ctx context.Context, tx common.TxController, state string) (entity.AuthState, error)
	// Delete(id string) (int64, error)
	DeleteByState(ctx context.Context, tx common.TxController, state string) (int64, error)
}

type AuthStateUsc interface {
	Create(ctx context.Context, authRequestID string) (entity.AuthState, error)
	Verify(w http.ResponseWriter, r *http.Request) (entity.AuthState, error)
}
