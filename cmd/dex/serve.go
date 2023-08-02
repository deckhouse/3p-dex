package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	gosundheit "github.com/AppsFlyer/go-sundheit"
	"github.com/AppsFlyer/go-sundheit/checks"
	gosundheithttp "github.com/AppsFlyer/go-sundheit/http"
	"github.com/ghodss/yaml"
	grpcprometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	"github.com/dexidp/dex/api/v2"
	"github.com/dexidp/dex/config"
	"github.com/dexidp/dex/pkg/log"
	"github.com/dexidp/dex/server"
	"github.com/dexidp/dex/storage"
)

func commandServe() *cobra.Command {
	options := &config.Overrides{}

	cmd := &cobra.Command{
		Use:     "serve [flags] [config file]",
		Short:   "Launch Dex",
		Example: "dex serve config.yaml",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true

			return runServe(args[0], options)
		},
	}

	flags := cmd.Flags()

	flags.StringVar(&options.WebHTTPSAddr, "web-http-addr", "", "Web HTTP address")
	flags.StringVar(&options.WebHTTPSAddr, "web-https-addr", "", "Web HTTPS address")
	flags.StringVar(&options.TelemetryAddr, "telemetry-addr", "", "Telemetry address")
	flags.StringVar(&options.GRPCAddr, "grpc-addr", "", "gRPC API address")

	return cmd
}

func runServe(configFile string, options *config.Overrides) error {
	configData, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("failed to read config file %s: %v", configFile, err)
	}

	var c config.Config
	if err := yaml.Unmarshal(configData, &c); err != nil {
		return fmt.Errorf("error parse config file %s: %v", configFile, err)
	}
	c.ApplyOverrides(options)

	logger, err := newLogger(c.Logger.Level, c.Logger.Format)
	if err != nil {
		return fmt.Errorf("invalid config: %v", err)
	}

	logger.Infof(
		"Dex Version: %s, Go Version: %s, Go OS/ARCH: %s %s",
		version,
		runtime.Version(),
		runtime.GOOS,
		runtime.GOARCH,
	)

	if err := c.Validate(logger); err != nil {
		return err
	}
	c.Log(logger)

	s, err := c.Storage.Config.Open(logger)
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %v", err)
	}
	defer s.Close()

	logger.Infof("config storage: %s", c.Storage.Type)

	if len(c.StaticClients) > 0 {
		clients := make([]storage.Client, 0, len(c.StaticClients))
		for _, client := range c.StaticClients {
			c, err := config.ToStorageClient(client)
			if err != nil {
				return err
			}

			clients = append(clients, c)
			logger.Infof("config static client: %s", client.Name)
		}
		s = storage.WithStaticClients(s, clients)
	}

	if len(c.StaticPasswords) > 0 {
		passwords := make([]storage.Password, 0, len(c.StaticPasswords))
		for _, password := range c.StaticPasswords {
			p, err := config.ToStoragePassword(password)
			if err != nil {
				return err
			}

			passwords = append(passwords, p)
		}
		s = storage.WithStaticPasswords(s, passwords, logger)
	}

	storageConnectors := make([]storage.Connector, 0, len(c.StaticConnectors))

	if c.EnablePasswordDB {
		storageConnectors = append(storageConnectors, storage.Connector{
			ID:   server.LocalConnector,
			Name: "Email",
			Type: server.LocalConnector,
		})
	}

	for _, connector := range c.StaticConnectors {
		c, err := config.ToStorageConnector(connector)
		if err != nil {
			return fmt.Errorf("failed to initialize storage connectors: %v", err)
		}
		storageConnectors = append(storageConnectors, c)
		logger.Infof("config connector: %s", connector.ID)
	}

	s = storage.WithStaticConnectors(s, storageConnectors)

	prometheusRegistry := prometheus.NewRegistry()
	if err = prometheusRegistry.Register(collectors.NewGoCollector()); err != nil {
		return fmt.Errorf("failed to register Go runtime metrics: %v", err)
	}
	if err = prometheusRegistry.Register(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{})); err != nil {
		return fmt.Errorf("failed to register process metrics: %v", err)
	}

	// explicitly convert to UTC.
	now := func() time.Time { return time.Now().UTC() }

	healthChecker := gosundheit.New()

	serverConfig := server.Config{
		AllowedGrantTypes:      c.OAuth2.GrantTypes,
		SupportedResponseTypes: c.OAuth2.ResponseTypes,
		SkipApprovalScreen:     c.OAuth2.SkipApprovalScreen,
		AlwaysShowLoginScreen:  c.OAuth2.AlwaysShowLoginScreen,
		PasswordConnector:      c.OAuth2.PasswordConnector,
		AllowedOrigins:         c.Web.AllowedOrigins,
		Issuer:                 c.Issuer,
		Storage:                s,
		Web:                    c.Frontend,
		Logger:                 logger,
		Now:                    now,
		PrometheusRegistry:     prometheusRegistry,
		HealthChecker:          healthChecker,
	}
	if c.Expiry.SigningKeys != "" {
		signingKeys, err := time.ParseDuration(c.Expiry.SigningKeys)
		if err != nil {
			return fmt.Errorf("invalid config value %q for signing keys expiry: %v", c.Expiry.SigningKeys, err)
		}
		logger.Infof("config signing keys expire after: %v", signingKeys)
		serverConfig.RotateKeysAfter = signingKeys
	}
	if c.Expiry.IDTokens != "" {
		idTokens, err := time.ParseDuration(c.Expiry.IDTokens)
		if err != nil {
			return fmt.Errorf("invalid config value %q for id token expiry: %v", c.Expiry.IDTokens, err)
		}
		logger.Infof("config id tokens valid for: %v", idTokens)
		serverConfig.IDTokensValidFor = idTokens
	}
	if c.Expiry.AuthRequests != "" {
		authRequests, err := time.ParseDuration(c.Expiry.AuthRequests)
		if err != nil {
			return fmt.Errorf("invalid config value %q for auth request expiry: %v", c.Expiry.AuthRequests, err)
		}
		logger.Infof("config auth requests valid for: %v", authRequests)
		serverConfig.AuthRequestsValidFor = authRequests
	}
	if c.Expiry.DeviceRequests != "" {
		deviceRequests, err := time.ParseDuration(c.Expiry.DeviceRequests)
		if err != nil {
			return fmt.Errorf("invalid config value %q for device request expiry: %v", c.Expiry.AuthRequests, err)
		}
		logger.Infof("config device requests valid for: %v", deviceRequests)
		serverConfig.DeviceRequestsValidFor = deviceRequests
	}
	refreshTokenPolicy, err := server.NewRefreshTokenPolicy(
		logger,
		c.Expiry.RefreshTokens.DisableRotation,
		c.Expiry.RefreshTokens.ValidIfNotUsedFor,
		c.Expiry.RefreshTokens.AbsoluteLifetime,
		c.Expiry.RefreshTokens.ReuseInterval,
	)
	if err != nil {
		return fmt.Errorf("invalid refresh token expiration policy config: %v", err)
	}
	serverConfig.RefreshTokenPolicy = refreshTokenPolicy

	serv, err := server.NewServer(context.Background(), serverConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize server: %v", err)
	}

	var group run.Group

	// Set up telemetry server
	if c.Telemetry.HTTP != "" {
		const name = "telemetry"

		telemetryRouter := http.NewServeMux()
		telemetryRouter.Handle("/metrics", promhttp.HandlerFor(prometheusRegistry, promhttp.HandlerOpts{}))

		// Configure health checker
		{
			handler := gosundheithttp.HandleHealthJSON(healthChecker)
			telemetryRouter.Handle("/healthz", handler)

			// Kubernetes style health checks
			telemetryRouter.HandleFunc("/healthz/live", func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("ok"))
			})
			telemetryRouter.Handle("/healthz/ready", handler)
		}

		if err := healthChecker.RegisterCheck(
			&checks.CustomCheck{
				CheckName: "storage",
				CheckFunc: storage.NewCustomHealthCheckFunc(serverConfig.Storage, serverConfig.Now),
			},
			gosundheit.ExecutionPeriod(15*time.Second),
			gosundheit.InitiallyPassing(true),
		); err != nil {
			return fmt.Errorf("registering healthcheck handler: %v", err)
		}

		logger.Infof("listening (%s) on %s", name, c.Telemetry.HTTP)

		l, err := net.Listen("tcp", c.Telemetry.HTTP)
		if err != nil {
			return fmt.Errorf("listening (%s) on %s: %v", name, c.Telemetry.HTTP, err)
		}

		if c.Telemetry.EnableProfiling {
			pprofHandler(telemetryRouter)
		}

		srv := &http.Server{
			Handler: telemetryRouter,
		}
		defer srv.Close()

		group.Add(func() error {
			return srv.Serve(l)
		}, func(err error) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			logger.Debugf("starting graceful shutdown (%s)", name)
			if err := srv.Shutdown(ctx); err != nil {
				logger.Errorf("graceful shutdown (%s): %v", name, err)
			}
		})
	}

	// Set up http server
	if c.Web.HTTP != "" {
		const name = "http"

		logger.Infof("listening (%s) on %s", name, c.Web.HTTP)

		l, err := net.Listen("tcp", c.Web.HTTP)
		if err != nil {
			return fmt.Errorf("listening (%s) on %s: %v", name, c.Web.HTTP, err)
		}

		srv := &http.Server{
			Handler: serv,
		}
		defer srv.Close()

		group.Add(func() error {
			return srv.Serve(l)
		}, func(err error) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			logger.Debugf("starting graceful shutdown (%s)", name)
			if err := srv.Shutdown(ctx); err != nil {
				logger.Errorf("graceful shutdown (%s): %v", name, err)
			}
		})
	}

	// Set up https server
	if c.Web.HTTPS != "" {
		const name = "https"

		logger.Infof("listening (%s) on %s", name, c.Web.HTTPS)

		l, err := net.Listen("tcp", c.Web.HTTPS)
		if err != nil {
			return fmt.Errorf("listening (%s) on %s: %v", name, c.Web.HTTPS, err)
		}

		tlsConfig, err := newTLSReloader(logger, c.Web.TLSCert, c.Web.TLSKey, "", baseTLSConfig())
		if err != nil {
			return fmt.Errorf("invalid config: get HTTP TLS: %v", err)
		}

		srv := &http.Server{
			Handler:   serv,
			TLSConfig: tlsConfig,
		}
		defer srv.Close()

		group.Add(func() error {
			return srv.ServeTLS(l, "", "")
		}, func(err error) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			logger.Debugf("starting graceful shutdown (%s)", name)
			if err := srv.Shutdown(ctx); err != nil {
				logger.Errorf("graceful shutdown (%s): %v", name, err)
			}
		})
	}

	// Set up grpc server
	if c.GRPC.Addr != "" {
		grpcMetrics := grpcprometheus.NewServerMetrics()
		err = prometheusRegistry.Register(grpcMetrics)
		if err != nil {
			return fmt.Errorf("failed to register gRPC server metrics: %v", err)
		}

		var grpcOptions []grpc.ServerOption

		if c.GRPC.TLSCert != "" {
			tlsConfig, err := newTLSReloader(logger, c.GRPC.TLSCert, c.GRPC.TLSKey, c.GRPC.TLSClientCA, baseTLSConfig())
			if err != nil {
				return fmt.Errorf("invalid config: get gRPC TLS: %v", err)
			}

			if c.GRPC.TLSClientCA != "" {
				// Only add metrics if client auth is enabled
				grpcOptions = append(grpcOptions,
					grpc.StreamInterceptor(grpcMetrics.StreamServerInterceptor()),
					grpc.UnaryInterceptor(grpcMetrics.UnaryServerInterceptor()),
				)
			}

			grpcOptions = append(grpcOptions, grpc.Creds(credentials.NewTLS(tlsConfig)))
		}

		logger.Infof("listening (grpc) on %s", c.GRPC.Addr)
		grpcListener, err := net.Listen("tcp", c.GRPC.Addr)
		if err != nil {
			return fmt.Errorf("listening (grcp) on %s: %w", c.GRPC.Addr, err)
		}

		grpcSrv := grpc.NewServer(grpcOptions...)
		api.RegisterDexServer(grpcSrv, server.NewAPI(serverConfig.Storage, logger, version))

		grpcMetrics.InitializeMetrics(grpcSrv)
		if c.GRPC.Reflection {
			logger.Info("enabling reflection in grpc service")
			reflection.Register(grpcSrv)
		}

		group.Add(func() error {
			return grpcSrv.Serve(grpcListener)
		}, func(err error) {
			logger.Debugf("starting graceful shutdown (grpc)")
			grpcSrv.GracefulStop()
		})
	}

	group.Add(run.SignalHandler(context.Background(), os.Interrupt, syscall.SIGTERM))
	if err := group.Run(); err != nil {
		if _, ok := err.(run.SignalError); !ok {
			return fmt.Errorf("run groups: %w", err)
		}
		logger.Infof("%v, shutdown now", err)
	}
	return nil
}

var (
	logLevels  = []string{"debug", "info", "error"}
	logFormats = []string{"json", "text"}
)

type utcFormatter struct {
	f logrus.Formatter
}

func (f *utcFormatter) Format(e *logrus.Entry) ([]byte, error) {
	e.Time = e.Time.UTC()
	return f.f.Format(e)
}

func newLogger(level string, format string) (log.Logger, error) {
	var logLevel logrus.Level
	switch strings.ToLower(level) {
	case "debug":
		logLevel = logrus.DebugLevel
	case "", "info":
		logLevel = logrus.InfoLevel
	case "error":
		logLevel = logrus.ErrorLevel
	default:
		return nil, fmt.Errorf("log level is not one of the supported  (%s): %s", strings.Join(logLevels, ", "), level)
	}

	var formatter utcFormatter
	switch strings.ToLower(format) {
	case "", "text":
		formatter.f = &logrus.TextFormatter{DisableColors: true}
	case "json":
		formatter.f = &logrus.JSONFormatter{}
	default:
		return nil, fmt.Errorf("log format is not one of the supported values (%s): %s", strings.Join(logFormats, ", "), format)
	}

	return &logrus.Logger{
		Out:       os.Stderr,
		Formatter: &formatter,
		Level:     logLevel,
	}, nil
}

func pprofHandler(router *http.ServeMux) {
	router.HandleFunc("/debug/pprof/", pprof.Index)
	router.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	router.HandleFunc("/debug/pprof/profile", pprof.Profile)
	router.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	router.HandleFunc("/debug/pprof/trace", pprof.Trace)
}
