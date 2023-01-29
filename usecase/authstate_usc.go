package usecase

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/w-woong/auth/authutil"
	"github.com/w-woong/auth/entity"
	"github.com/w-woong/auth/port"
	"github.com/w-woong/common"
)

type authStateUsc struct {
	authStateTxBeginner common.TxBeginner
	authStateRepo       port.AuthStateRepo
}

func NewAuthStateUsc(authStateTxBeginner common.TxBeginner, authStateRepo port.AuthStateRepo) *authStateUsc {
	return &authStateUsc{
		authStateTxBeginner: authStateTxBeginner,
		authStateRepo:       authStateRepo,
	}
}

func (u *authStateUsc) Create(ctx context.Context, authRequestID string) (entity.AuthState, error) {
	tx, err := u.authStateTxBeginner.Begin()
	if err != nil {
		return entity.NilAuthState, err
	}
	defer tx.Rollback()

	state := strings.ReplaceAll(uuid.New().String(), "-", "")
	codeVerifier := authutil.GenerateCodeVerifier(43)

	authState := entity.AuthState{
		State:         state,
		CodeVerifier:  codeVerifier,
		AuthRequestID: authRequestID,
	}

	_, err = u.authStateRepo.Create(ctx, tx, authState)
	if err != nil {
		return entity.NilAuthState, err
	}

	if err = tx.Commit(); err != nil {
		return entity.NilAuthState, err
	}

	return authState, nil
}

func (u *authStateUsc) Verify(w http.ResponseWriter, r *http.Request) (entity.AuthState, error) {
	ctx := r.Context()
	tx, err := u.authStateTxBeginner.Begin()
	if err != nil {
		return entity.NilAuthState, err
	}
	defer tx.Rollback()

	receivedState := r.URL.Query().Get("state")
	if receivedState == "" {
		return entity.NilAuthState, errors.New("state is empty")
	}

	authState, err := u.authStateRepo.ReadByState(ctx, tx, receivedState)
	if err != nil {
		return entity.NilAuthState, err
	}
	u.authStateRepo.DeleteByState(ctx, tx, receivedState)

	if authState.State != receivedState {
		return entity.NilAuthState, errors.New("invalid state")
	}
	return authState, tx.Commit()
}
