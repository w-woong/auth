package route

import (
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/w-woong/auth/delivery"
	"github.com/w-woong/auth/port"
	commonport "github.com/w-woong/common/port"
)

// func init() {
// 	rand.Seed(time.Now().Unix())
// }
func AuthorizeHandlerRoute(router *mux.Router, usc port.TokenUsc, validator commonport.IDTokenValidator,
	authRequestUsc port.AuthRequestUsc,
	tokenGetter port.TokenGetter, tokenSetter port.TokenSetter,
	authRequestWait time.Duration) *delivery.AuthorizeHandler {

	handler := delivery.NewAuthorizeHandler(usc, validator, authRequestUsc, tokenGetter, tokenSetter, authRequestWait)

	router.HandleFunc("/v1/auth/authorize/"+usc.TokenSource()+"/{auth_request_id}",
		handler.AuthorizeWithAuthRequest).Methods(http.MethodGet)
	router.HandleFunc("/v1/auth/callback/"+usc.TokenSource(), handler.CallbackWithAuthRequest)

	router.HandleFunc("/v1/auth/request/"+usc.TokenSource(), handler.AuthRequest).Methods(http.MethodGet)
	router.HandleFunc("/v1/auth/request/"+usc.TokenSource()+"/{auth_request_id}", handler.AuthRequestWait).Methods(http.MethodGet)
	router.HandleFunc("/v1/auth/request/"+usc.TokenSource()+"/{auth_request_id}", handler.AuthRequestSignal).Methods(http.MethodPost)

	router.HandleFunc("/v1/auth/validate/"+usc.TokenSource(), handler.ValidateIDToken).Methods(http.MethodGet)

	// router.HandleFunc("/test/auth/validate/google", func(w http.ResponseWriter, r *http.Request) {
	// 	if rand.Int31n(30)%30 == 0 {
	// 		w.WriteHeader(401)
	// 		w.Write([]byte(`{"status":401}`))
	// 		return
	// 	}
	// 	w.Write([]byte(`{"status":200}`))
	// })

	// router.HandleFunc("/test/resource", func(w http.ResponseWriter, r *http.Request) {
	// 	if rand.Int31n(3)%2 == 0 {
	// 		w.WriteHeader(401)
	// 		w.Write([]byte(`{"status":1000}`))
	// 		return
	// 	}
	// 	w.Write([]byte(`{"status":200}`))
	// })
	return handler
}
