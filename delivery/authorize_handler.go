package delivery

import (
	"errors"
	"html/template"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/go-wonk/si"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/w-woong/auth/port"
	"github.com/w-woong/common"
	commondto "github.com/w-woong/common/dto"
	"github.com/w-woong/common/logger"
)

var (
	dump bool
)

func init() {
	dump, _ = strconv.ParseBool(os.Getenv("DUMP"))
}

type AuthorizeHandler struct {
	usc             port.TokenUsc
	authStateUsc    port.AuthStateUsc
	authRequestUsc  port.AuthRequestUsc
	authRequestWait time.Duration

	tokenGetter port.TokenGetter
	tokenSetter port.TokenSetter

	authCompleteTemplate *template.Template
}

func NewAuthorizeHandler(usc port.TokenUsc, authStateUsc port.AuthStateUsc, authRequestUsc port.AuthRequestUsc,
	tokenGetter port.TokenGetter, tokenSetter port.TokenSetter,
	authRequestWait time.Duration) *AuthorizeHandler {

	return &AuthorizeHandler{
		usc:             usc,
		authStateUsc:    authStateUsc,
		authRequestUsc:  authRequestUsc,
		authRequestWait: authRequestWait,

		tokenGetter:          tokenGetter,
		tokenSetter:          tokenSetter,
		authCompleteTemplate: template.Must(template.ParseFiles("./resources/html/auth_complete.html")),
	}
}

func setNoCache(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate;")
	w.Header().Set("pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

// AuthorizeWithAuthRequest is the start of authorization process to the authorization servers(like google, apple, kakao...)
func (d *AuthorizeHandler) AuthorizeWithAuthRequest(w http.ResponseWriter, r *http.Request) {
	if dump {
		dumpRequest(r) // Ignore the error
	}

	setNoCache(w)
	ctx := r.Context()
	vars := mux.Vars(r)
	authRequestID := vars["auth_request_id"]

	_, err := d.authRequestUsc.Find(ctx, authRequestID)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		logger.Error(err.Error())
		return
	}

	authState, err := d.authStateUsc.Create(ctx, authRequestID)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		logger.Error(err.Error())
		return
	}

	err = d.usc.AuthorizeCode(w, r, authState.State, authState.CodeVerifier)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		logger.Error(err.Error())
		return
	}
}

// CallbackWithAuthRequest is the url redirected from authorization server(like google, apple, kakao..)
// when authorization process is completed.
func (d *AuthorizeHandler) CallbackWithAuthRequest(w http.ResponseWriter, r *http.Request) {
	if dump {
		dumpRequest(r) // Ignore the error
	}

	setNoCache(w)
	ctx := r.Context()
	authState, err := d.authStateUsc.Verify(w, r)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		logger.Error(err.Error())
		return
	}

	token, err := d.usc.Exchange(r, authState.CodeVerifier)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		logger.Error(err.Error())
		return
	}

	tokenDto, err := d.usc.SaveToken(ctx, w, token)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		logger.Error(err.Error())
		return
	}

	_, claims, err := d.usc.ValidateIDToken(ctx, tokenDto.IDToken)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		logger.Error(err.Error())
		return
	}

	registeredUser, err := d.usc.RegisterUser(ctx, tokenDto.ID, *claims)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		logger.Error(err.Error())
		return
	}
	logger.Debug(registeredUser.String())

	d.tokenSetter.SetTokenIdentifier(w, tokenDto.ID)
	d.tokenSetter.SetIDToken(w, tokenDto.IDToken)
	d.tokenSetter.SetTokenSource(w, tokenDto.TokenSource)

	// TODO: respond with static page that leads to the app or web page
	// if err = si.EncodeJson(w, tokenDto.HideSensitive()); err != nil {
	// 	logger.Error(err.Error())
	// }
	if err = d.authCompleteTemplate.Execute(w, nil); err != nil {
		logger.Error(err.Error())
	}

	defer func() {
		_, err := d.authRequestUsc.Remove(ctx, authState.AuthRequestID)
		if err != nil {
			logger.Error(err.Error())
		}
	}()
	err = d.authRequestUsc.Signal(ctx, authState.AuthRequestID, tokenDto)
	if err != nil {
		logger.Error(err.Error())
		return
	}
}

// AuthRequest starts oauth2, the server creates an authRequestID. The server saves the authRequestID
// and pass it to the user.
func (d *AuthorizeHandler) AuthRequest(w http.ResponseWriter, r *http.Request) {
	if dump {
		dumpRequest(r) // Ignore the error
	}
	ctx := r.Context()

	setNoCache(w)
	authRequestID := uuid.New().String()
	authRequest, err := d.authRequestUsc.Save(ctx, authRequestID)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		logger.Error(err.Error())
		return
	}

	res := common.HttpBody{
		Status:   http.StatusOK,
		Count:    1,
		Document: &authRequest,
	}

	if err := res.EncodeTo(w); err != nil {
		logger.Error(err.Error())
	}

}

// AuthRequestWait
func (d *AuthorizeHandler) AuthRequestWait(w http.ResponseWriter, r *http.Request) {
	if dump {
		dumpRequest(r) // Ignore the error
	}
	setNoCache(w)
	ctx := r.Context()
	vars := mux.Vars(r)
	authRequestID := vars["auth_request_id"]

	_, err := d.authRequestUsc.Find(ctx, authRequestID)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		logger.Error(err.Error())
		return
	}

	ch := make(chan commondto.Token, 1)
	_clientMap.Store(authRequestID, ch)

	defer func(arID string) {
		_clientMap.Delete(arID)
		d.authRequestUsc.Remove(ctx, arID)
		// d.usc.RemoveStateByAuthRequestID(ctx, arID)
	}(authRequestID)

	ticker := time.NewTicker(d.authRequestWait)
	defer ticker.Stop()
	select {
	case token := <-ch:
		if err := si.EncodeJson(w, &token); err != nil {
			logger.Error(err.Error())
			return
		}
	case <-ticker.C:
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		logger.Error("tick expired")
		return
	}
}

var (
	_clientMap sync.Map
)

func (d *AuthorizeHandler) AuthRequestSignal(w http.ResponseWriter, r *http.Request) {
	if dump {
		dumpRequest(r) // Ignore the error
	}

	setNoCache(w)
	vars := mux.Vars(r)
	authRequestID := vars["auth_request_id"]

	token := commondto.Token{}
	if err := si.DecodeJson(&token, r.Body); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	val, loaded := _clientMap.LoadAndDelete(authRequestID)
	if !loaded {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	ch := val.(chan commondto.Token)
	ch <- token
	close(ch)
	w.Write([]byte(`{"status":200}`))
}

func (d *AuthorizeHandler) ValidateIDToken(w http.ResponseWriter, r *http.Request) {
	if dump {
		dumpRequest(r) // Ignore the error
	}

	setNoCache(w)
	ctx := r.Context()

	tokenIdentifier := d.tokenGetter.GetTokenIdentifier(r)
	if tokenIdentifier == "" {
		// return commondto.NilToken, errors.New("token identifier is empty")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	idTokenStr := d.tokenGetter.GetIDToken(r)
	_, claims, err := d.usc.ValidateIDToken(ctx, idTokenStr)
	// if err == nil {
	// 	err = common.ErrTokenExpired
	// }
	if err != nil {
		logger.Error(err.Error())
		if errors.Is(err, common.ErrTokenExpired) {
			foundOauth2Token, err := d.usc.FindWithIDToken(ctx, tokenIdentifier, idTokenStr)
			if err != nil {
				logger.Error(err.Error())
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			d.usc.RemoveToken(ctx, tokenIdentifier)
			d.tokenSetter.SetTokenIdentifier(w, "")
			d.tokenSetter.SetIDToken(w, "")
			d.tokenSetter.SetTokenSource(w, "")

			refreshedOauth2Token, err := d.usc.Refresh(ctx, foundOauth2Token)
			if err != nil {
				logger.Error(err.Error())
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			refreshedTokenDto, err := d.usc.SaveToken(ctx, w, refreshedOauth2Token)
			if err != nil {
				logger.Error(err.Error())
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			d.tokenSetter.SetTokenIdentifier(w, refreshedTokenDto.ID)
			d.tokenSetter.SetIDToken(w, refreshedTokenDto.IDToken)
			d.tokenSetter.SetTokenSource(w, refreshedTokenDto.TokenSource)
			if err := si.EncodeJson(w, refreshedTokenDto.HideSensitive()); err != nil {
				logger.Error(err.Error())
			}
			return
		}

		d.usc.RemoveToken(ctx, tokenIdentifier)
		d.tokenSetter.SetTokenIdentifier(w, "")
		d.tokenSetter.SetIDToken(w, "")
		d.tokenSetter.SetTokenSource(w, "")

		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	tokenSource := d.tokenGetter.GetTokenSource(r)
	d.tokenSetter.SetTokenIdentifier(w, tokenIdentifier)
	d.tokenSetter.SetIDToken(w, idTokenStr)
	d.tokenSetter.SetTokenSource(w, tokenSource)

	resTokenDto := commondto.Token{
		ID:          tokenIdentifier,
		IDToken:     idTokenStr,
		TokenSource: tokenSource,
		Expiry:      claims.ExpiresAt.Unix(),
	}

	if err := si.EncodeJson(w, resTokenDto.HideSensitive()); err != nil {
		logger.Error(err.Error())
	}

}

func dumpRequest(r *http.Request) error {
	data, err := httputil.DumpRequest(r, true)
	if err != nil {
		return err
	}
	logger.Debug(string(data), logger.UrlField(r.URL.String()))
	return nil
}
