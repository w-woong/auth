package delivery

import (
	"errors"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"sync"
	"time"

	"github.com/go-wonk/si"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/w-woong/auth/dto"
	"github.com/w-woong/auth/port"
	"github.com/w-woong/common"
	"github.com/w-woong/common/validators"
)

type AuthorizeHandler struct {
	usc             port.TokenUsc
	validator       validators.IDTokenValidator
	authRequestUsc  port.AuthRequestUsc
	authRequestWait time.Duration

	tokenGetter port.TokenGetter
	tokenSetter port.TokenSetter

	authCompleteTemplate *template.Template
}

func NewAuthorizeHandler(usc port.TokenUsc, validator validators.IDTokenValidator, authRequestUsc port.AuthRequestUsc,
	tokenGetter port.TokenGetter, tokenSetter port.TokenSetter,
	authRequestWait time.Duration) *AuthorizeHandler {

	return &AuthorizeHandler{
		usc:             usc,
		validator:       validator,
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
	_ = dumpRequest(os.Stdout, "AuthorizeWithAuthRequest", r) // Ignore the error
	setNoCache(w)
	ctx := r.Context()
	vars := mux.Vars(r)
	authRequestID := vars["auth_request_id"]

	_, err := d.authRequestUsc.Find(ctx, authRequestID)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		log.Println(err)
		return
	}

	url, err := d.usc.RetrieveAuthUrl(ctx, authRequestID)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		log.Println(err)
		return
	}

	log.Println(url)

	http.Redirect(w, r, url, http.StatusFound)
}

// CallbackWithAuthRequest is the url redirected from authorization server(like google, apple, kakao..)
// when authorization process is completed.
func (d *AuthorizeHandler) CallbackWithAuthRequest(w http.ResponseWriter, r *http.Request) {
	_ = dumpRequest(os.Stdout, "CallbackWithAuthRequest", r) // Ignore the error

	setNoCache(w)
	ctx := r.Context()
	authState, err := d.usc.ValidateState(w, r)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		log.Println(err)
		return
	}

	token, err := d.usc.Exchange(r, authState)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		log.Println(err)
		return
	}

	tokenDto, err := d.usc.SaveToken(ctx, w, token)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		log.Println(err)
		return
	}

	_, claims, err := d.validator.Validate(tokenDto.IDToken)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		log.Println(err)
		return
	}

	registeredUser, err := d.usc.RegisterUser(ctx, tokenDto.ID, *claims)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		log.Println(err)
		return
	}
	log.Println(registeredUser.String())

	d.tokenSetter.SetTokenIdentifier(w, tokenDto.ID)
	d.tokenSetter.SetIDToken(w, tokenDto.IDToken)
	d.tokenSetter.SetTokenSource(w, tokenDto.TokenSource)

	// TODO: respond with static page that leads to the app or web page
	// if err = si.EncodeJson(w, tokenDto.HideSensitive()); err != nil {
	// 	log.Println(err)
	// }
	if err = d.authCompleteTemplate.Execute(w, nil); err != nil {
		log.Println(err)
	}

	err = d.authRequestUsc.Signal(r.Context(), authState.AuthRequestID, tokenDto)
	if err != nil {
		log.Println(err)
		return
	}
}

// AuthRequest starts oauth2, the server creates an authRequestID. The server saves the authRequestID
// and pass it to the user.
func (d *AuthorizeHandler) AuthRequest(w http.ResponseWriter, r *http.Request) {
	_ = dumpRequest(os.Stdout, "AuthRequest", r) // Ignore the error
	ctx := r.Context()

	setNoCache(w)
	authRequestID := uuid.New().String()
	authRequest, err := d.authRequestUsc.Save(ctx, authRequestID)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		log.Println(err)
		return
	}

	res := common.HttpBody{
		Status:   http.StatusOK,
		Count:    1,
		Document: &authRequest,
	}

	if err := res.EncodeTo(w); err != nil {
		log.Println(err)
	}

}

// AuthRequestWait
func (d *AuthorizeHandler) AuthRequestWait(w http.ResponseWriter, r *http.Request) {
	_ = dumpRequest(os.Stdout, "AuthRequestWait", r) // Ignore the error
	setNoCache(w)
	ctx := r.Context()
	vars := mux.Vars(r)
	authRequestID := vars["auth_request_id"]

	_, err := d.authRequestUsc.Find(ctx, authRequestID)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		log.Println(err)
		return
	}

	ch := make(chan dto.Token, 1)
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
			log.Println(err)
			return
		}
	case <-ticker.C:
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		log.Println("tick expired")
		return
	}
}

var (
	_clientMap sync.Map
)

func (d *AuthorizeHandler) AuthRequestSignal(w http.ResponseWriter, r *http.Request) {
	_ = dumpRequest(os.Stdout, "AuthRequestSignal", r) // Ignore the error
	setNoCache(w)
	vars := mux.Vars(r)
	authRequestID := vars["auth_request_id"]

	token := dto.Token{}
	if err := si.DecodeJson(&token, r.Body); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	val, loaded := _clientMap.LoadAndDelete(authRequestID)
	if !loaded {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	ch := val.(chan dto.Token)
	ch <- token
	close(ch)
	w.Write([]byte(`{"status":200}`))
}

func (d *AuthorizeHandler) ValidateIDToken(w http.ResponseWriter, r *http.Request) {
	_ = dumpRequest(os.Stdout, "ValidateIDToken", r) // Ignore the error
	setNoCache(w)
	ctx := r.Context()

	tokenIdentifier := d.tokenGetter.GetTokenIdentifier(r)
	if tokenIdentifier == "" {
		// return dto.NilToken, errors.New("token identifier is empty")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	idTokenStr := d.tokenGetter.GetIDToken(r)
	_, claims, err := d.validator.Validate(idTokenStr)
	if err != nil {
		log.Println(err)
		if errors.Is(err, common.ErrTokenExpired) {
			foundOauth2Token, err := d.usc.FindOauth2TokenWithIDToken(ctx, tokenIdentifier, idTokenStr)
			if err != nil {
				log.Println(err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			d.usc.RemoveToken(ctx, tokenIdentifier)
			d.tokenSetter.SetTokenIdentifier(w, "")
			d.tokenSetter.SetIDToken(w, "")
			d.tokenSetter.SetTokenSource(w, "")

			refreshedOauth2Token, err := d.usc.Refresh(ctx, foundOauth2Token)
			if err != nil {
				log.Println(err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			refreshedTokenDto, err := d.usc.SaveToken(ctx, w, refreshedOauth2Token)
			if err != nil {
				log.Println(err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			d.tokenSetter.SetTokenIdentifier(w, refreshedTokenDto.ID)
			d.tokenSetter.SetIDToken(w, refreshedTokenDto.IDToken)
			d.tokenSetter.SetTokenSource(w, refreshedTokenDto.TokenSource)
			if err := si.EncodeJson(w, refreshedTokenDto.HideSensitive()); err != nil {
				log.Println(err)
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

	resTokenDto := dto.Token{
		ID:          tokenIdentifier,
		IDToken:     idTokenStr,
		TokenSource: tokenSource,
		Expiry:      claims.ExpiresAt.Unix(),
	}

	if err := si.EncodeJson(w, resTokenDto.HideSensitive()); err != nil {
		log.Println(err)
	}

}

func dumpRequest(writer io.Writer, header string, r *http.Request) error {
	data, err := httputil.DumpRequest(r, true)
	if err != nil {
		return err
	}
	writer.Write([]byte("\n" + header + ": \n"))
	writer.Write(data)
	return nil
}
