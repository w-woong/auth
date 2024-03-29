package conv

import (
	"time"

	"github.com/w-woong/auth/entity"
	commondto "github.com/w-woong/common/dto"
	"github.com/wonksing/structmapper"
	"golang.org/x/oauth2"
)

func init() {
	structmapper.StoreMapper(&commondto.Token{}, &entity.Token{})
	structmapper.StoreMapper(&entity.Token{}, &commondto.Token{})
}

func ToTokenEntity(input *commondto.Token) (output entity.Token, err error) {
	err = structmapper.Map(input, &output)
	return
}

func ToTokenDto(input *entity.Token) (output commondto.Token, err error) {
	err = structmapper.Map(input, &output)
	return
}

func ToTokenDtoFromOauth2(token *oauth2.Token, id string, tokenSource string) (commondto.Token, error) {
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		idToken = ""
	}
	e := commondto.Token{
		ID:           id,
		TokenSource:  tokenSource,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.TokenType,
		Expiry:       token.Expiry.Unix(),
		IDToken:      idToken,
	}

	return e, nil
}

func ToTokenEntityFromOauth2(token *oauth2.Token, id string, tokenSource entity.TokenSource) (entity.Token, error) {
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		idToken = ""
	}
	e := entity.Token{
		ID:           id,
		TokenSource:  tokenSource,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.TokenType,
		Expiry:       token.Expiry.Unix(),
		IDToken:      idToken,
	}

	return e, nil
}

func ToTokenOauth2FromEntity(token *entity.Token) (*oauth2.Token, error) {
	o := &oauth2.Token{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.TokenType,
		Expiry:       time.Unix(token.Expiry, 0),
	}

	extra := make(map[string]interface{})
	extra["id_token"] = token.IDToken
	o = o.WithExtra(extra)

	return o, nil
}
