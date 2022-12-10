package port

import (
	"context"
	"net/http"

	"github.com/w-woong/auth/entity"
	commondto "github.com/w-woong/common/dto"
	"golang.org/x/oauth2"
)

type TokenUsc interface {
	TokenSource() string

	// RetrieveAuthUrl creates state and codeVerifier to set in cookie.
	// state is sent on query parameter and codeVeifier is used to generate codeChallenge
	// which is sent on query parameter as well as state.
	RetrieveAuthUrl(ctx context.Context, authRequestID string) (string, error)

	// ValidateIDToken retrieves jwks in order to parse and validate idToken.
	// ValidateIDToken(ctx context.Context, tokenIdentifier string, idTokenStr string) (commondto.Token, error)

	// ParseIDToken retrieves jwks in order to parse and validate idToken.
	// ParseIDToken(r *http.Request) (*jwt.Token, error)

	// Refresh retrieves token information(accessToken, refreshToken, tokenType...) to
	// renew the tokens if possible. It returns renewed token and true if the token is renewed.
	// It sets new IDToken to the cookie and token information to repository(like rdbms).
	// Refresh(ctx context.Context, tokenID string) (commondto.Token, bool, error)

	ValidateState(w http.ResponseWriter, r *http.Request) (entity.AuthState, error)

	Exchange(r *http.Request, authState entity.AuthState) (*oauth2.Token, error)

	SaveToken(ctx context.Context, w http.ResponseWriter, token *oauth2.Token) (commondto.Token, error)
	FindOauth2TokenWithIDToken(ctx context.Context, id, idToken string) (*oauth2.Token, error)
	RemoveToken(ctx context.Context, id string) (int64, error)

	RegisterUser(ctx context.Context, tokenID string, claims commondto.IDTokenClaims) (commondto.User, error)

	Refresh(ctx context.Context, token *oauth2.Token) (*oauth2.Token, error)
}

type TokenGetter interface {
	GetTokenIdentifier(r *http.Request) string
	// getIDToken retrieves id_token from cookie or header
	GetIDToken(r *http.Request) string
	GetTokenSource(r *http.Request) string
}

type TokenSetter interface {
	SetTokenIdentifier(w http.ResponseWriter, val string)
	SetIDToken(w http.ResponseWriter, val string)
	SetTokenSource(w http.ResponseWriter, val string)
}
