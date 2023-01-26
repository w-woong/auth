package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
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
	commonadapter "github.com/w-woong/common/adapter"
	"github.com/w-woong/common/configs"
	"github.com/w-woong/common/logger"
	commonport "github.com/w-woong/common/port"
	"github.com/w-woong/common/txcom"
	"github.com/w-woong/common/utils"
	"github.com/w-woong/common/wrapper"
	"golang.org/x/oauth2"
	"gorm.io/gorm"

	// "go.elastic.co/apm/module/apmgorilla/v2"
	postgresapm "go.elastic.co/apm/module/apmgormv2/v2/driver/postgres" // postgres with gorm
	// _ "go.elastic.co/apm/module/apmsql/v2/pq" // postgres sql with pq
	"go.elastic.co/apm/v2"
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

	usePprof    = false
	pprofAddr   = ":56060"
	autoMigrate = false
)

func init() {
	flag.StringVar(&addr, "addr", ":5558", "listen address")
	flag.BoolVar(&printVersion, "version", false, "print version")
	flag.IntVar(&tickIntervalSec, "tick", 30, "tick interval in second")
	flag.StringVar(&certKey, "key", "./certs/key.pem", "server key")
	flag.StringVar(&certPem, "pem", "./certs/cert.pem", "server pem")
	flag.IntVar(&readTimeout, "readTimeout", 30, "read timeout")
	flag.IntVar(&writeTimeout, "writeTimeout", 30, "write timeout")
	flag.StringVar(&configName, "config", "./configs/server-google.yml", "config file name")
	flag.IntVar(&maxProc, "mp", runtime.NumCPU(), "GOMAXPROCS")

	flag.BoolVar(&usePprof, "pprof", false, "use pprof")
	flag.StringVar(&pprofAddr, "pprof_addr", ":56060", "pprof listen address")
	flag.BoolVar(&autoMigrate, "autoMigrate", false, "auto migrate")

	flag.Parse()
}

func main() {
	if printVersion {
		fmt.Printf("version \"%v\"\n", Version)
		return
	}
	runtime.GOMAXPROCS(maxProc)

	var err error
	// apm
	apmActive, _ := strconv.ParseBool(os.Getenv("ELASTIC_APM_ACTIVE"))
	if apmActive {
		tracer := apm.DefaultTracer()
		defer tracer.Flush(nil)
	}

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

	// db, gorm
	var gormDB *gorm.DB
	switch conf.Server.Repo.Driver {
	case "pgx":
		if apmActive {
			gormDB, err = gorm.Open(postgresapm.Open(conf.Server.Repo.ConnStr),
				&gorm.Config{Logger: logger.OpenGormLogger(conf.Server.Repo.LogLevel)},
			)
			if err != nil {
				logger.Error(err.Error())
				os.Exit(1)
			}
			db, err := gormDB.DB()
			if err != nil {
				logger.Error(err.Error())
				os.Exit(1)
			}
			defer db.Close()
		} else {
			// db
			// var db *sql.DB
			db, err := si.OpenSqlDB(conf.Server.Repo.Driver, conf.Server.Repo.ConnStr,
				conf.Server.Repo.MaxIdleConns, conf.Server.Repo.MaxOpenConns, time.Duration(conf.Server.Repo.ConnMaxLifetimeMinutes)*time.Minute)
			if err != nil {
				logger.Error(err.Error())
				os.Exit(1)
			}
			defer db.Close()

			gormDB, err = sigorm.OpenPostgresWithConfig(db,
				&gorm.Config{Logger: logger.OpenGormLogger(conf.Server.Repo.LogLevel)},
			)
			if err != nil {
				logger.Error(err.Error())
				os.Exit(1)
			}
		}
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
	openIDConf, err := utils.GetOpenIDConfig(conf.Client.Oauth2.OpenIDConfUrl)
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
	jwksUrl, err := utils.GetJwksUrl(conf.Client.Oauth2.OpenIDConfUrl)
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
	// repo

	tokenCookie := adapter.NewTokenCookie(1*time.Hour, conf.Client.Oauth2.Token.IDKeyName, conf.Client.Oauth2.Token.IDTokenKeyName, conf.Client.Oauth2.Token.TokenSourceKeyName)
	tokenHeader := adapter.NewTokenHeader(conf.Client.Oauth2.Token.IDKeyName, conf.Client.Oauth2.Token.IDTokenKeyName, conf.Client.Oauth2.Token.TokenSourceKeyName)

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

	if autoMigrate {
		gormDB.AutoMigrate(&entity.Token{}, &entity.AuthState{}, &entity.AuthRequest{})
	}
	var userSvc commonport.UserSvc
	if conf.Client.UserHttp.Url != "" {
		userSvc = commonadapter.NewUserHttp(sihttp.DefaultInsecureClient(),
			// conf.Client.Oauth2.Token.Source,
			conf.Client.UserHttp.Url,
			conf.Client.UserHttp.BearerToken,
			conf.Client.Oauth2.Token.TokenSourceKeyName,
			conf.Client.Oauth2.Token.IDKeyName, conf.Client.Oauth2.Token.IDTokenKeyName)
	} else if conf.Client.UserGrpc.Addr != "" {
		conn, err := wrapper.NewGrpcClient(conf.Client.UserGrpc, false)
		if err != nil {
			logger.Error(err.Error())
			os.Exit(1)
		}
		userSvc = commonadapter.NewUserGrpc(conn)
	} else {
		userSvc = commonadapter.NewUserSvcNop()
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
		&oauthConfig, userSvc, entity.TokenSource(conf.Client.Oauth2.Token.Source), openIDConf)

	jwksStore, err := utils.NewJwksCache(jwksUrl)
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
	validator := commonadapter.NewJwksIDTokenValidator(jwksStore, conf.Client.Oauth2.Token.TokenSourceKeyName, conf.Client.Oauth2.Token.IDKeyName, conf.Client.Oauth2.Token.IDTokenKeyName)
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

	// ticker
	ticker := time.NewTicker(time.Duration(tickIntervalSec) * time.Second)
	tickerDone := make(chan bool)
	common.StartTicker(tickerDone, ticker, func(t time.Time) {
		logger.Info(fmt.Sprintf("NoOfGR:%v, %v", runtime.NumGoroutine(), t))
	})

	// signal, wait for it to shutdown http server.
	common.StartSignalStopper(httpServer, syscall.SIGINT, syscall.SIGTERM)

	// start
	logger.Info("start listening on " + addr)
	if err = httpServer.Start(); err != nil {
		logger.Error(err.Error())
	}

	// finish
	ticker.Stop()
	tickerDone <- true
	logger.Info("finished")
}
