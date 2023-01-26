package usecase_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/w-woong/auth/entity"
	"github.com/w-woong/auth/usecase"
	"github.com/w-woong/common/utils"
	"golang.org/x/oauth2"
)

func Test_tokenUsc_Revoke(t *testing.T) {

	oauthConfig := oauth2.Config{
		ClientID:     "",
		ClientSecret: "",
		RedirectURL:  "https://localhost:5558/v1/auth/callback/google",
		Scopes:       []string{},
		// Endpoint:     google.Endpoint,
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://accounts.google.com/o/oauth2/auth",
			TokenURL:  "https://oauth2.googleapis.com/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
	openIDConf, _ := utils.GetOpenIDConfig("https://accounts.google.com/.well-known/openid-configuration")
	tokenUsc := usecase.NewTokenUsc(nil, nil,
		nil, nil,
		&oauthConfig, nil, entity.TokenSource("google"), openIDConf)

	o := &oauth2.Token{
		AccessToken:  "",
		RefreshToken: "",
		TokenType:    "Bearer",
		Expiry:       time.Unix(1674729287, 0),
	}

	extra := make(map[string]interface{})
	extra["id_token"] = ""
	o = o.WithExtra(extra)
	tokenUsc.Revoke(context.Background(), o)
}

func Test_tokenUsc_Refresh(t *testing.T) {

	oauthConfig := oauth2.Config{
		ClientID:     "",
		ClientSecret: "",
		RedirectURL:  "https://localhost:5558/v1/auth/callback/google",
		Scopes:       []string{},
		// Endpoint:     google.Endpoint,
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://accounts.google.com/o/oauth2/auth",
			TokenURL:  "https://oauth2.googleapis.com/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}

	openIDConf, _ := utils.GetOpenIDConfig("https://accounts.google.com/.well-known/openid-configuration")
	tokenUsc := usecase.NewTokenUsc(nil, nil,
		nil, nil,
		&oauthConfig, nil, entity.TokenSource("google"), openIDConf)

	o := &oauth2.Token{
		AccessToken:  "",
		RefreshToken: "",
		TokenType:    "Bearer",
		// Expiry:       time.Unix(1674729287, 0),
		Expiry: time.Unix(167472, 0),
	}

	extra := make(map[string]interface{})
	extra["id_token"] = ""
	o = o.WithExtra(extra)
	no, err := tokenUsc.Refresh(context.Background(), o)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(no)
}

func Test_tokenUsc_Userinfo(t *testing.T) {

	oauthConfig := oauth2.Config{
		ClientID:     "",
		ClientSecret: "",
		RedirectURL:  "https://localhost:5558/v1/auth/callback/google",
		Scopes:       []string{},
		// Endpoint:     google.Endpoint,
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://accounts.google.com/o/oauth2/auth",
			TokenURL:  "https://oauth2.googleapis.com/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}

	openIDConf, _ := utils.GetOpenIDConfig("https://accounts.google.com/.well-known/openid-configuration")
	tokenUsc := usecase.NewTokenUsc(nil, nil,
		nil, nil,
		&oauthConfig, nil, entity.TokenSource("google"), openIDConf)

	o := &oauth2.Token{
		AccessToken:  "",
		RefreshToken: "",
		TokenType:    "Bearer",
		// Expiry:       time.Unix(1674729287, 0),
		Expiry: time.Unix(1674731349, 0),
	}

	extra := make(map[string]interface{})
	extra["id_token"] = ""
	o = o.WithExtra(extra)
	err := tokenUsc.Userinfo(context.Background(), o)
	if err != nil {
		fmt.Println(err)
	}

}
