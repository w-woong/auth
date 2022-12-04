package port

import (
	"context"

	"github.com/w-woong/auth/dto"
)

type AuthRequestUsc interface {
	Save(ctx context.Context, id string) (dto.AuthRequest, error)
	Find(ctx context.Context, id string) (dto.AuthRequest, error)
	Remove(ctx context.Context, id string) (int64, error)

	Signal(ctx context.Context, id string, token dto.Token) error
}
