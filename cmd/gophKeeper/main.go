package main

import (
	"GophKeeper/config"
	"GophKeeper/internal/app/HTTP/handlers"
	"GophKeeper/internal/app/gRPC/grpchandlers"
	"GophKeeper/internal/app/gRPC/interceptors"
	"GophKeeper/internal/app/gRPC/proto"
	"GophKeeper/pkg/secure"
	"GophKeeper/pkg/storages/hashi_corp_vault"
	"GophKeeper/pkg/storages/postgreSQL"
	"crypto/tls"
	"database/sql"
	"github.com/go-chi/chi"
	_ "github.com/jackc/pgx/v5/stdlib"
	"go.uber.org/zap"
	"golang.org/x/crypto/acme/autocert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"log"
	"net"
	"net/http"
	"sync"
)

func main() {
	//configure
	conf := config.Config{}
	err := conf.Configure()
	if err != nil {
		log.Fatalf("cant configure the server, err: %v", err)
	}

	//prepare logger
	logConf := zap.NewProductionConfig()
	logLevel, err := zap.ParseAtomicLevel(conf.LogLevel)
	if err != nil {
		log.Fatalf("cant parse log level, err: %v", err)
	}
	logConf.Level = logLevel
	logConf.DisableStacktrace = true
	logger, err := logConf.Build()
	if err != nil {
		log.Fatalf("cant build logger, err: %v", err)
	}
	sugar := logger.Sugar()
	defer sugar.Sync()

	//prepare storage
	sqlDB, err := sql.Open("pgx", conf.DBConnString)
	if err != nil {
		sugar.Fatalf("cant create postgresql storage, err: %v", err)
	}
	storage := postgreSQL.NewPostgresDB(sqlDB)

	//prepare keykeeper
	hashiCorp, err := hashi_corp_vault.NewHashiCorpVault(conf.HashiCorpAddress, conf.HashiCorpToken)
	if err != nil {
		sugar.Fatalf("cant create hashi corp vault, err: %v", err)
	}

	//prepare JWTHelper
	jh := secure.NewJWTHelper(conf.JWTSecretKey, conf.JWTTimeoutHours)

	//prepare encryptor
	encryptor := secure.NewEncryptorAESGCM()

	//build HTTP router
	r := handlers.NewChiRouter(sugar, storage, jh, storage, hashiCorp, encryptor, conf)

	//prepare waitGroup
	wg := sync.WaitGroup{}

	//build and run HTTP server
	var httpServer *http.Server
	if conf.DebugMode {
		//build
		sugar.Info("debug mode is enabled. Building NO-TLS HTTP server")
		httpServer = buildHTTPServer(r, conf.ServerAddress)

		//run
		wg.Add(1)
		go func() {
			defer wg.Done()
			err = httpServer.ListenAndServe()
			if err != nil {
				sugar.Fatalf("cant start http server, err: %v", err)
			}
		}()
	} else {
		//build
		sugar.Info("Building HTTPS server")
		httpServer = buildHTTPSServer(r, conf.ServerAddress)

		//run
		wg.Add(1)
		go func() {
			defer wg.Done()
			err = httpServer.ListenAndServe()
			if err != nil {
				sugar.Fatalf("cant start http server, err: %v", err)
			}
		}()
	}

	//build and run gRPC server
	var grpcServer *grpc.Server
	listen, err := net.Listen("tcp", conf.GRPCAddress)
	if err != nil {
		sugar.Fatalf("cant start grpc server, err: %v", err)
	}

	if conf.DebugMode {
		//build
		sugar.Info("debug mode is enabled. Building NO-TLS GRPC server")
		grpcServer = buildGRPCServerNoTLS(conf.GRPCAddress, sugar, jh)

		//run
		proto.RegisterGophKeeperServiceServer(grpcServer, grpchandlers.NewGophKeeperServer(storage, hashiCorp, sugar, secure.NewEncryptionFileFabric(), conf.MaxBinDataChunkSize))
		wg.Add(1)
		go func() {
			defer wg.Done()
			err = grpcServer.Serve(listen)
			if err != nil {
				sugar.Fatalf("cant start grpc server, err: %v", err)
			}
		}()
	} else {
		//build
		sugar.Info("Building GRPC server (TLS ON)")
		grpcServer = buildGRPCServerWithTLS(conf.GRPCAddress, sugar, jh)

		//run
		proto.RegisterGophKeeperServiceServer(grpcServer, grpchandlers.NewGophKeeperServer(storage, hashiCorp, sugar, secure.NewEncryptionFileFabric(), conf.MaxBinDataChunkSize))
		wg.Add(1)
		go func() {
			defer wg.Done()
			err = grpcServer.Serve(listen)
			if err != nil {
				sugar.Fatalf("cant start grpc server, err: %v", err)
			}
		}()
	}

	wg.Wait()
}

// buildHTTPSServer builds a server. But it doesn`t run it.
func buildHTTPSServer(r chi.Router, address string) *http.Server {
	manager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache("cache-dir"),
		HostPolicy: autocert.HostWhitelist("gophkeeper.ru"),
	}

	server := &http.Server{
		Handler:   r,
		Addr:      address,
		TLSConfig: manager.TLSConfig(),
	}

	return server
}

// buildHTTPSServer builds a gRPC server. But it doesn`t run it.
func buildGRPCServerWithTLS(address string, logger *zap.SugaredLogger, jh *secure.JWTHelper) *grpc.Server {
	manager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache("cache-dir"),
		HostPolicy: autocert.HostWhitelist("gophkeeper.ru"),
	}

	TLSOpt := grpc.Creds(credentials.NewTLS(&tls.Config{GetCertificate: manager.GetCertificate}))
	grpcServer := grpc.NewServer(grpc.StreamInterceptor(interceptors.AuthInterceptor(logger, jh)), TLSOpt)

	return grpcServer
}

// buildHTTPServer build HTTP server (no TLS).
// DEBUG MODE ONLY!!
func buildHTTPServer(r chi.Router, address string) *http.Server {
	server := &http.Server{
		Handler: r,
		Addr:    address,
	}

	return server
}

// buildHTTPSServer builds a gRPC server (no TLS).
// DEBUG MODE ONLY!!
func buildGRPCServerNoTLS(address string, logger *zap.SugaredLogger, jh *secure.JWTHelper) *grpc.Server {
	grpcServer := grpc.NewServer(grpc.StreamInterceptor(interceptors.AuthInterceptor(logger, jh)))
	return grpcServer
}
