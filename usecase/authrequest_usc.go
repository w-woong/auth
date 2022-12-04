package usecase

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/go-wonk/si/sicore"
	"github.com/go-wonk/si/sihttp"
	"github.com/w-woong/auth/conv"
	"github.com/w-woong/auth/dto"
	"github.com/w-woong/auth/entity"
	"github.com/w-woong/auth/port"
	"github.com/w-woong/common"
)

type AuthRequest struct {
	responseUrl string
	authUrl     string

	txBeginner  common.RWTxBeginner
	authRequest port.AuthRequestRepo
	client      *sihttp.Client
}

func NewAuthRequest(responseUrl, authUrl string, txBeginner common.RWTxBeginner, authRequest port.AuthRequestRepo) *AuthRequest {
	return &AuthRequest{
		responseUrl: responseUrl,
		authUrl:     authUrl,
		txBeginner:  txBeginner,
		authRequest: authRequest,
		client: sihttp.NewClient(sihttp.DefaultInsecureClient(),
			sihttp.WithWriterOpt(sicore.SetJsonEncoder()),
			sihttp.WithReaderOpt(sicore.SetJsonDecoder())),
	}
}

func (u *AuthRequest) Save(ctx context.Context, id string) (dto.AuthRequest, error) {
	tx, err := u.txBeginner.Begin()
	if err != nil {
		return dto.NilAuthRequest, err
	}
	defer tx.Rollback()

	_, err = u.authRequest.Read(ctx, tx, id)
	if err == nil {
		return dto.NilAuthRequest, errors.New("client request id exists")
	}

	ar := entity.AuthRequest{
		ID:          id,
		ResponseUrl: u.replaceByID(u.responseUrl, id),
		AuthUrl:     u.replaceByID(u.authUrl, id),
	}
	affected, err := u.authRequest.Create(ctx, tx, ar)
	if err != nil {
		return dto.NilAuthRequest, err
	}
	if affected != 1 {
		return dto.NilAuthRequest, errors.New("could not save")
	}

	if err = tx.Commit(); err != nil {
		return dto.NilAuthRequest, err
	}

	return conv.ToAuthRequestDto(&ar)
}

func (u *AuthRequest) Find(ctx context.Context, id string) (dto.AuthRequest, error) {
	tx, err := u.txBeginner.BeginR()
	if err != nil {
		return dto.NilAuthRequest, err
	}
	defer tx.Rollback()

	ar, err := u.authRequest.Read(ctx, tx, id)
	if err != nil {
		return dto.NilAuthRequest, err
	}
	return dto.AuthRequest{
		ID:          ar.ID,
		ResponseUrl: ar.ResponseUrl,
		AuthUrl:     ar.AuthUrl,
	}, tx.Commit()
}

func (u *AuthRequest) Remove(ctx context.Context, id string) (int64, error) {
	tx, err := u.txBeginner.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	affected, err := u.authRequest.Delete(ctx, tx, id)
	if err != nil {
		return 0, err
	}

	return affected, tx.Commit()

}

func (u *AuthRequest) Signal(ctx context.Context, id string, token dto.Token) error {
	tx, err := u.txBeginner.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	authRequest, err := u.authRequest.Read(ctx, tx, id)
	if err != nil {
		return err
	}

	_, err = u.authRequest.Delete(ctx, tx, id)
	if err != nil {
		return err
	}

	url := u.replaceByID(authRequest.ResponseUrl, authRequest.ID)
	header := make(http.Header)
	header.Add("Content-Type", "application/json; charset=utf-8")
	m := make(map[string]interface{})
	err = u.client.RequestPostDecode(url, header, &token, &m)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (u *AuthRequest) replaceByID(url string, id string) string {
	return strings.Replace(url, "{auth_request_id}", id, -1)
}
