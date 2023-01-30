package usecase

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/w-woong/auth/authutil"
	"github.com/w-woong/auth/conv"
	"github.com/w-woong/auth/entity"
	"github.com/w-woong/auth/port"
	"github.com/w-woong/common"
	commondto "github.com/w-woong/common/dto"
	commonport "github.com/w-woong/common/port"
	"golang.org/x/oauth2"
)

type TokenUsc struct {
	tokenTxBeginner common.TxBeginner
	tokenRepo       port.TokenRepo

	tokenSource entity.TokenSource
	openIDConf  map[string]interface{}
	config      *oauth2.Config
	validator   commonport.IDTokenValidator

	userSvc commonport.UserSvc
}

func NewTokenUsc(tokenTxBeginner common.TxBeginner, tokenRepo port.TokenRepo,
	tokenSource entity.TokenSource, openIDConf map[string]interface{}, config *oauth2.Config,
	validator commonport.IDTokenValidator, userSvc commonport.UserSvc,
) *TokenUsc {

	return &TokenUsc{
		tokenTxBeginner: tokenTxBeginner,
		tokenRepo:       tokenRepo,
		config:          config,

		userSvc:     userSvc,
		tokenSource: tokenSource,
		openIDConf:  openIDConf,
		validator:   validator,
	}
}

func (u TokenUsc) TokenSource() string {
	return string(u.tokenSource)
}

func (u *TokenUsc) AuthorizeCode(w http.ResponseWriter, r *http.Request, state, codeVerifier string) error {
	url := u.config.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", authutil.GenerateCodeChallenge(codeVerifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("access_type", "offline"),
		oauth2.SetAuthURLParam("prompt", "consent"))

	http.Redirect(w, r, url, http.StatusFound)
	return nil
}

func (u *TokenUsc) Exchange(r *http.Request, codeVerifier string) (*oauth2.Token, error) {

	var opts []oauth2.AuthCodeOption
	opts = append(opts, oauth2.SetAuthURLParam("code_verifier", codeVerifier))

	token, err := u.config.Exchange(context.Background(), r.URL.Query().Get("code"), opts...)
	if err != nil {
		// failed
		return nil, err
	}
	if !token.Valid() {
		return nil, errors.New("token is not valid")
	}

	return token, nil
}

func (u *TokenUsc) ValidateIDToken(ctx context.Context, idToken string) (*jwt.Token, *commondto.IDTokenClaims, error) {
	return u.validator.Validate(idToken)
}

func (u *TokenUsc) SaveToken(ctx context.Context, w http.ResponseWriter, token *oauth2.Token) (commondto.Token, error) {
	tx, err := u.tokenTxBeginner.Begin()
	if err != nil {
		return commondto.NilToken, err
	}
	defer tx.Rollback()

	tokenEntity, err := conv.ToTokenEntityFromOauth2(token, uuid.New().String(), u.tokenSource)
	if err != nil {
		return commondto.NilToken, err
	}

	affected, err := u.tokenRepo.Create(ctx, tx, tokenEntity)
	if err != nil {
		return commondto.NilToken, err
	}
	if affected != 1 {
		return commondto.NilToken, errors.New("could not store token")
	}

	tokenForClient, err := conv.ToTokenDto(&tokenEntity)
	if err != nil {
		return commondto.NilToken, err
	}

	if err = tx.Commit(); err != nil {
		return commondto.NilToken, err
	}

	return tokenForClient, nil
}

func (u *TokenUsc) FindWithIDToken(ctx context.Context, id, idToken string) (*oauth2.Token, error) {

	token, err := u.tokenRepo.ReadNoTx(ctx, id)
	if err != nil {
		return nil, err
	}
	if token.IDToken != idToken {
		return nil, common.ErrIDTokenInconsistent
	}

	return conv.ToTokenOauth2FromEntity(&token)
}

func (u *TokenUsc) RemoveToken(ctx context.Context, id string) (int64, error) {
	tx, err := u.tokenTxBeginner.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var rowsAffected int64 = 0
	if rowsAffected, err = u.tokenRepo.Delete(ctx, tx, id); err != nil {
		return 0, err
	}

	return rowsAffected, tx.Commit()
}

func (u *TokenUsc) RegisterUser(ctx context.Context, tokenID string, claims commondto.IDTokenClaims) (commondto.User, error) {

	registeredUser, err := u.userSvc.RegisterUser(ctx, commondto.User{
		LoginID:     claims.Subject,
		LoginType:   "token",
		LoginSource: u.TokenSource(),
		Emails: commondto.Emails{
			commondto.Email{
				Email:    claims.Email,
				Priority: 0,
			},
		},
		CredentialToken: &commondto.CredentialToken{
			Value: tokenID,
		},
		Personal: &commondto.Personal{
			FirstName: claims.GivenName,
			LastName:  claims.FamilyName,
		},
	})
	if err != nil {
		return commondto.NilUser, err
	}

	return registeredUser, nil
}

func (u *TokenUsc) Refresh(ctx context.Context, token *oauth2.Token) (*oauth2.Token, error) {
	return u.config.TokenSource(ctx, token).Token()
	// refreshed := newOauthToken.AccessToken != oauthToken.AccessToken || newOauthToken.RefreshToken != oauthToken.RefreshToken
}

func (u *TokenUsc) Revoke(ctx context.Context, token *oauth2.Token) error {
	revokeEndpoint, ok := u.openIDConf["revocation_endpoint"]
	if !ok {
		return nil
	}

	reqBody := url.Values{}
	reqBody.Set("token", token.RefreshToken)
	resp, err := u.config.Client(ctx, token).Post(revokeEndpoint.(string), "application/x-www-form-urlencoded", strings.NewReader(reqBody.Encode()))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

func (u *TokenUsc) Userinfo(ctx context.Context, token *oauth2.Token) error {
	userinfoEndpoint, ok := u.openIDConf["revocation_endpoint"]
	if !ok {
		return nil
	}
	resp, err := u.config.Client(ctx, token).Get(userinfoEndpoint.(string))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}
