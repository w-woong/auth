package usecase

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/w-woong/auth/authutil"
	"github.com/w-woong/auth/conv"
	"github.com/w-woong/auth/dto"
	"github.com/w-woong/auth/entity"
	"github.com/w-woong/auth/port"
	"github.com/w-woong/common"
	"github.com/w-woong/common/validators"
	userdto "github.com/w-woong/user/dto"
	userport "github.com/w-woong/user/port"
	"golang.org/x/oauth2"
)

type TokenUsc struct {
	tokenTxBeginner common.TxBeginner
	tokenRepo       port.TokenRepo

	authStateTxBeginner common.TxBeginner
	authStateRepo       port.AuthStateRepo

	config      *oauth2.Config
	tokenSource entity.TokenSource

	userSvc userport.UserSvc
}

func NewTokenUsc(tokenTxBeginner common.TxBeginner, tokenRepo port.TokenRepo,
	authStateTxBeginner common.TxBeginner, authStateRepo port.AuthStateRepo,
	config *oauth2.Config, userSvc userport.UserSvc,
	tokenSource entity.TokenSource) *TokenUsc {

	return &TokenUsc{
		tokenTxBeginner:     tokenTxBeginner,
		tokenRepo:           tokenRepo,
		authStateTxBeginner: authStateTxBeginner,
		authStateRepo:       authStateRepo,
		config:              config,

		userSvc:     userSvc,
		tokenSource: tokenSource,
	}
}

func (u TokenUsc) TokenSource() string {
	return string(u.tokenSource)
}

func (u *TokenUsc) RetrieveAuthUrl(ctx context.Context, authRequestID string) (string, error) {
	tx, err := u.authStateTxBeginner.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	state := strings.ReplaceAll(uuid.New().String(), "-", "")
	codeVerifier := authutil.GenerateCodeVerifier(43)

	_, err = u.authStateRepo.Create(ctx, tx, entity.AuthState{
		State:         state,
		CodeVerifier:  codeVerifier,
		AuthRequestID: authRequestID,
	})
	if err != nil {
		return "", err
	}

	if err = tx.Commit(); err != nil {
		return "", err
	}

	url := u.config.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", authutil.GenerateCodeChallenge(codeVerifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("access_type", "offline"),
		oauth2.SetAuthURLParam("prompt", "consent"))

	return url, nil
}

// func (u *TokenUsc) ValidateIDToken(ctx context.Context, tokenIdentifier string, idTokenStr string) (dto.Token, error) {

// 	jwtToken, err := u.validateWithJwks(idTokenStr)
// 	if err != nil {
// 		return dto.NilToken, err
// 	}

// 	claims, ok := jwtToken.Claims.(*dto.IDTokenClaims)
// 	if !ok {
// 		return dto.NilToken, errors.New("unexpected id token claims")
// 	}

// 	return dto.Token{
// 		ID:          tokenIdentifier,
// 		TokenSource: u.TokenSource(),
// 		IDToken:     jwtToken.Raw,
// 		Expiry:      claims.ExpiresAt.Unix(),
// 	}, nil

// }

func (u *TokenUsc) Exchange(r *http.Request, authState entity.AuthState) (*oauth2.Token, error) {

	var opts []oauth2.AuthCodeOption
	opts = append(opts, oauth2.SetAuthURLParam("code_verifier", authState.CodeVerifier))

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

func (u *TokenUsc) SaveToken(ctx context.Context, w http.ResponseWriter, token *oauth2.Token) (dto.Token, error) {
	tx, err := u.tokenTxBeginner.Begin()
	if err != nil {
		return dto.NilToken, err
	}
	defer tx.Rollback()

	tokenEntity, err := conv.ToTokenEntityFromOauth2(token, uuid.New().String(), u.tokenSource)
	if err != nil {
		return dto.NilToken, err
	}

	affected, err := u.tokenRepo.Create(ctx, tx, tokenEntity)
	if err != nil {
		return dto.NilToken, err
	}
	if affected != 1 {
		return dto.NilToken, errors.New("could not store token")
	}

	tokenForClient, err := conv.ToTokenDto(&tokenEntity)
	if err != nil {
		return dto.NilToken, err
	}

	if err = tx.Commit(); err != nil {
		return dto.NilToken, err
	}

	// user registration
	// registeredUser, err := u.RegisterUser(ctx, tokenForClient.ID, tokenForClient.IDToken)
	// if err != nil {
	// 	return dto.NilToken, err
	// }
	// fmt.Println(registeredUser.String())

	return tokenForClient, nil
}

func (u *TokenUsc) FindOauth2TokenWithIDToken(ctx context.Context, id, idToken string) (*oauth2.Token, error) {

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

func (u *TokenUsc) RegisterUser(ctx context.Context, tokenID string, claims validators.IDTokenClaims) (userdto.User, error) {
	// jwtToken, err := u.validateWithJwks(idToken)
	// if err != nil {
	// 	return userdto.NilUser, err
	// }
	// claims, ok := jwtToken.Claims.(*dto.IDTokenClaims)
	// if !ok {
	// 	return userdto.NilUser, errors.New("unexpected token claims")
	// }

	registeredUser, err := u.userSvc.RegisterUser(ctx, userdto.User{
		LoginID: claims.Subject,
		Emails: userdto.Emails{
			userdto.Email{
				Email:    claims.Email,
				Priority: 0,
			},
		},
		Password: userdto.Password{
			Value: tokenID,
		},
		Personal: userdto.Personal{
			FirstName: claims.GivenName,
			LastName:  claims.FamilyName,
		},
	})
	if err != nil {
		return userdto.NilUser, err
	}
	fmt.Println(registeredUser.String())

	return registeredUser, nil
}

func (u *TokenUsc) ValidateState(w http.ResponseWriter, r *http.Request) (entity.AuthState, error) {
	ctx := r.Context()
	tx, err := u.authStateTxBeginner.Begin()
	if err != nil {
		return entity.NilAuthState, err
	}
	defer tx.Rollback()

	receivedState := r.URL.Query().Get("state")

	authState, err := u.authStateRepo.ReadByState(ctx, tx, receivedState)
	if err != nil {
		return entity.NilAuthState, err
	}
	u.authStateRepo.DeleteByState(ctx, tx, receivedState)

	if len(authState.State) > 0 && authState.State != receivedState {
		return entity.NilAuthState, errors.New("invalid state")
	}
	return authState, tx.Commit()
}

func (u *TokenUsc) Refresh(ctx context.Context, token *oauth2.Token) (*oauth2.Token, error) {
	return u.config.TokenSource(context.Background(), token).Token()
	// refreshed := newOauthToken.AccessToken != oauthToken.AccessToken || newOauthToken.RefreshToken != oauthToken.RefreshToken

}
