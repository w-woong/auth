package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/go-wonk/si"
	"github.com/go-wonk/si/sigorm"
	"github.com/go-wonk/si/sihttp"
	"github.com/gorilla/mux"
	"github.com/w-woong/auth/adapter"
	"github.com/w-woong/auth/cmd/route"
	"github.com/w-woong/auth/entity"
	"github.com/w-woong/auth/port"
	"github.com/w-woong/auth/usecase"
	"github.com/w-woong/common"
	"github.com/w-woong/common/configs"
	"github.com/w-woong/common/logger"
	"github.com/w-woong/common/txcom"
	"github.com/w-woong/common/validators"
	useradapter "github.com/w-woong/user/adapter"
	userport "github.com/w-woong/user/port"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
)

var (
	Version = "undefined"

	printVersion     bool
	tickIntervalSec  int = 30
	addr             string
	certPem, certKey string
	readTimeout      int
	writeTimeout     int
	configName       string
	maxProc          int

	usePprof  = false
	pprofAddr = ":56060"
)

func init() {
	flag.StringVar(&addr, "addr", ":5558", "listen address")
	flag.BoolVar(&printVersion, "version", false, "print version")
	flag.IntVar(&tickIntervalSec, "tick", 30, "tick interval in second")
	flag.StringVar(&certKey, "key", "./certs/key.pem", "server key")
	flag.StringVar(&certPem, "pem", "./certs/cert.pem", "server pem")
	flag.IntVar(&readTimeout, "readTimeout", 30, "read timeout")
	flag.IntVar(&writeTimeout, "writeTimeout", 30, "write timeout")
	flag.StringVar(&configName, "config", "./configs/server.yml", "config file name")
	flag.IntVar(&maxProc, "mp", runtime.NumCPU(), "GOMAXPROCS")

	flag.BoolVar(&usePprof, "pprof", false, "use pprof")
	flag.StringVar(&pprofAddr, "pprof_addr", ":56060", "pprof listen address")

	flag.Parse()
}

func main() {
	if printVersion {
		fmt.Printf("version \"%v\"\n", Version)
		return
	}
	runtime.GOMAXPROCS(maxProc)

	// config
	conf := common.Config{}
	if err := configs.ReadConfigInto(configName, &conf); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	conf.Client.Oauth2.RedirectUrl = strings.ReplaceAll(conf.Client.Oauth2.RedirectUrl, "{token_source}", conf.Client.Oauth2.Token.Source)
	conf.Client.Oauth2.AuthRequest.ResponseUrl = strings.ReplaceAll(conf.Client.Oauth2.AuthRequest.ResponseUrl, "{token_source}", conf.Client.Oauth2.Token.Source)
	conf.Client.Oauth2.AuthRequest.AuthUrl = strings.ReplaceAll(conf.Client.Oauth2.AuthRequest.AuthUrl, "{token_source}", conf.Client.Oauth2.Token.Source)

	// logger
	logger.Open(conf.Logger.Level, conf.Logger.Stdout,
		conf.Logger.File.Name, conf.Logger.File.MaxSize, conf.Logger.File.MaxBackup,
		conf.Logger.File.MaxAge, conf.Logger.File.Compressed)
	defer logger.Close()

	// db
	sqlDB, err := si.OpenSqlDB(conf.Server.Repo.Driver, conf.Server.Repo.ConnStr,
		conf.Server.Repo.MaxIdleConns, conf.Server.Repo.MaxOpenConns,
		time.Duration(conf.Server.Repo.ConnMaxLifetimeMinutes)*time.Minute)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer sqlDB.Close()

	// gorm
	var gormDB *gorm.DB
	switch conf.Server.Repo.Driver {
	case "pgx":
		gormDB, err = sigorm.OpenPostgres(sqlDB)
	case "map":
	default:
		logger.Error(conf.Server.Repo.Driver + " is not allowed")
		os.Exit(1)
	}
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}

	clientID := os.Getenv("CLIENT_ID")
	if conf.Client.Oauth2.ClientID != "" {
		clientID = conf.Client.Oauth2.ClientID
	}
	clientSecret := os.Getenv("CLIENT_SECRET")
	if conf.Client.Oauth2.ClientSecret != "" {
		clientSecret = conf.Client.Oauth2.ClientSecret
	}
	redirectURL := os.Getenv("REDIRECT_URL")
	if conf.Client.Oauth2.RedirectUrl != "" {
		redirectURL = conf.Client.Oauth2.RedirectUrl
	}
	scopes := conf.Client.Oauth2.Scopes
	authUrl := conf.Client.Oauth2.AuthUrl
	tokenUrl := conf.Client.Oauth2.TokenUrl
	openIDConfUrl := conf.Client.Oauth2.OpenIDConfUrl
	jwksUrl, err := getJwksUrl(openIDConfUrl)
	if err != nil {
		logger.Error(err.Error())
		return
	}
	// repo

	tokenCookie := adapter.NewTokenCookie(1*time.Hour, "tid", "id_token", "token_source")
	tokenHeader := adapter.NewTokenHeader("tid", "id_token", "token_source")

	var tokenTxBeginner common.TxBeginner
	var tokenRepo port.TokenRepo
	var authStateTxBeginner common.TxBeginner
	var authStateRepo port.AuthStateRepo
	var authRequestTxBeginner common.RWTxBeginner
	var authRequestRepo port.AuthRequestRepo
	switch conf.Server.Repo.Driver {
	case "pgx":
		tokenTxBeginner = txcom.NewGormTxBeginner(gormDB)
		tokenRepo = adapter.NewTokenPg(gormDB)
		authStateTxBeginner = txcom.NewGormTxBeginner(gormDB)
		authStateRepo = adapter.NewAuthStatePg(gormDB)
		authRequestTxBeginner = txcom.NewGormTxBeginner(gormDB)
		authRequestRepo = adapter.NewAuthRequestPg(gormDB)

		gormDB.AutoMigrate(&entity.Token{}, &entity.AuthState{}, &entity.AuthRequest{})
	case "map":
		tokenTxBeginner = txcom.NewLockTxBeginner()
		tokenRepo = adapter.NewMapToken()

		authStateTxBeginner = txcom.NewLockTxBeginner()
		authStateRepo = adapter.NewMapAuthState()
		authRequestTxBeginner = txcom.NewLockTxBeginner()
		authRequestRepo = adapter.NewMapAuthRequest()
	default:
		logger.Error(conf.Server.Repo.Driver + " is not allowed")
		os.Exit(1)
	}

	var userSvc userport.UserSvc
	if conf.Client.UserHttp.Url != "" {
		userSvc = useradapter.NewUserHttp(sihttp.DefaultInsecureClient(),
			conf.Client.Oauth2.Token.Source,
			conf.Client.UserHttp.Url,
			conf.Client.UserHttp.BearerToken)
	} else {
		userSvc = useradapter.NewUserSvcNop()
	}

	oauthConfig := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		// Endpoint:     google.Endpoint,
		Endpoint: oauth2.Endpoint{
			AuthURL:   authUrl,
			TokenURL:  tokenUrl,
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
	tokenUsc := usecase.NewTokenUsc(tokenTxBeginner, tokenRepo,
		authStateTxBeginner, authStateRepo,
		&oauthConfig, userSvc, entity.TokenSource(conf.Client.Oauth2.Token.Source))
	validator := validators.NewJwksIDTokenValidator(jwksUrl)
	authRequestUsc := usecase.NewAuthRequest(
		conf.Client.Oauth2.AuthRequest.ResponseUrl,
		conf.Client.Oauth2.AuthRequest.AuthUrl,
		authRequestTxBeginner, authRequestRepo)

	tokenGetter := usecase.NewTokenGetter(tokenCookie, tokenHeader)
	tokenSetter := usecase.NewTokenSetter(tokenCookie, tokenHeader)

	// 라우터, gorilla mux를 쓴다
	router := mux.NewRouter()
	route.AuthorizeHandlerRoute(router, tokenUsc, validator, authRequestUsc,
		tokenGetter, tokenSetter, time.Duration(conf.Client.Oauth2.AuthRequest.Wait)*time.Second)

	// http 서버 생성
	tlsConfig := sihttp.CreateTLSConfigMinTls(tls.VersionTLS12)
	httpServer := sihttp.NewServerCors(router, tlsConfig, addr,
		time.Duration(writeTimeout)*time.Second, time.Duration(readTimeout)*time.Second,
		certPem, certKey,
		strings.Split(conf.Server.Http.AllowedOrigins, ","),
		strings.Split(conf.Server.Http.AllowedHeaders, ","),
		strings.Split(conf.Server.Http.AllowedMethods, ","),
	)

	// start
	logger.Info("start listening on " + addr)
	if err = httpServer.Start(); err != nil {
		logger.Error(err.Error())
	}

	// if certPem != "" && certKey != "" {
	// 	log.Fatal(httpServer.ListenAndServeTLS(certPem, certKey))
	// } else {
	// 	log.Fatal(httpServer.ListenAndServe())
	// }
}

func getJwksUrl(openIDConfUrl string) (string, error) {

	res, err := http.Get(openIDConfUrl)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	resb, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	m := make(map[string]interface{})
	if err = json.Unmarshal(resb, &m); err != nil {
		return "", err
	}
	jwksUrl, ok := m["jwks_uri"]
	if !ok {
		return "", errors.New("not found")
	}
	return jwksUrl.(string), nil
}
