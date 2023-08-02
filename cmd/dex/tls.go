package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/fsnotify/fsnotify"

	"github.com/dexidp/dex/pkg/log"
)

var allowedTLSCiphers = []uint16{
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
}

func baseTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: allowedTLSCiphers,
	}
}

// newTLSReloader returns a [tls.Config] with GetCertificate or GetConfigForClient set
// to reload certificates from the given paths on SIGHUP or on file creates (atomic update via rename).
func newTLSReloader(logger log.Logger, certFile, keyFile, caFile string, baseConfig *tls.Config) (*tls.Config, error) {
	// trigger reload on channel
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGHUP)

	// files to watch
	watchFiles := map[string]struct{}{
		certFile: {},
		keyFile:  {},
	}
	if caFile != "" {
		watchFiles[caFile] = struct{}{}
	}
	watchDirs := make(map[string]struct{}) // dedupe dirs
	for f := range watchFiles {
		dir := filepath.Dir(f)
		if !strings.HasPrefix(f, dir) {
			// normalize name to have ./ prefix if only a local path was provided
			// can't pass "" to watcher.Add
			watchFiles[dir+string(filepath.Separator)+f] = struct{}{}
		}
		watchDirs[dir] = struct{}{}
	}
	// trigger reload on file change
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("create watcher for TLS reloader: %v", err)
	}
	// recommended by fsnotify: watch the dir to handle renames
	// https://pkg.go.dev/github.com/fsnotify/fsnotify#hdr-Watching_files
	for dir := range watchDirs {
		logger.Debugf("watching dir: %v", dir)
		err := watcher.Add(dir)
		if err != nil {
			return nil, fmt.Errorf("watch dir for TLS reloader: %v", err)
		}
	}

	// load once outside the goroutine, so we can return an error on misconfig
	initialConfig, err := loadTLSConfig(certFile, keyFile, caFile, baseConfig)
	if err != nil {
		return nil, fmt.Errorf("load TLS config: %v", err)
	}

	// stored version of current tls config
	ptr := &atomic.Pointer[tls.Config]{}
	ptr.Store(initialConfig)

	// start background worker to reload certs
	go func() {
	loop:
		for {
			select {
			case sig := <-sigc:
				logger.Debug("reloading cert from signal: %v", sig)
			case evt := <-watcher.Events:
				if _, ok := watchFiles[evt.Name]; !ok || !evt.Has(fsnotify.Create) {
					continue loop
				}
				logger.Debug("reloading cert from fsnotify: %v %v", evt.Name, evt.Op.String())
			case err := <-watcher.Errors:
				logger.Errorf("TLS reloader watch: %v", err)
			}

			loaded, err := loadTLSConfig(certFile, keyFile, caFile, baseConfig)
			if err != nil {
				logger.Errorf("reload TLS config: %v", err)
			}
			ptr.Store(loaded)
		}
	}()

	conf := &tls.Config{}
	// https://pkg.go.dev/crypto/tls#baseConfig
	// Server configurations must set one of Certificates, GetCertificate or GetConfigForClient.
	if caFile != "" {
		// grpc will use this via tls.Server for mTLS
		conf.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) { return ptr.Load(), nil }
	} else {
		// net/http only uses Certificates or GetCertificate
		conf.GetCertificate = func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) { return &ptr.Load().Certificates[0], nil }
	}
	return conf, nil
}

// loadTLSConfig loads the given file paths into a [tls.Config]
func loadTLSConfig(certFile, keyFile, caFile string, baseConfig *tls.Config) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading TLS keypair: %v", err)
	}
	loadedConfig := baseConfig.Clone() // copy
	loadedConfig.Certificates = []tls.Certificate{cert}
	if caFile != "" {
		cPool := x509.NewCertPool()
		clientCert, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("reading from client CA file: %v", err)
		}
		if !cPool.AppendCertsFromPEM(clientCert) {
			return nil, errors.New("failed to parse client CA")
		}

		loadedConfig.ClientAuth = tls.RequireAndVerifyClientCert
		loadedConfig.ClientCAs = cPool
	}
	return loadedConfig, nil
}

