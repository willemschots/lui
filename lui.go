// Package lui is a convenience wrapper around net/http. It provides:
// - Quick methods for setting up http/https servers
// - Graceful shutdowns
// - Optional config file support
package lui

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"
	"golang.org/x/crypto/acme/autocert"
)

const (
	// DefaultReadTimeout is the read timeout used by https/https servers when no specific read timeout is provided
	DefaultReadTimeout = time.Second * 10
	// DefaultHeaderReadTimeout is the read timeout used by https/https servers when no specific read header timeout is provided
	DefaultHeaderReadTimeout = time.Second * 5
	// DefaultWriteTimeout is the read timeout used by https/https servers when no specific timeout is provided
	DefaultWriteTimeout = time.Second * 30
	// DefaultIdleTimeout is the idle timeout used by https/https servers when no specific timeout is provided
	DefaultIdleTimeout = time.Second * 60
	// DefaultShutdownTimeout is the shutdown timeout used by https/https servers when no specific timeout is provided
	DefaultShutdownTimeout = time.Second * 30
	// DefaultHTTPAddr is the default http address
	DefaultHTTPAddr = ":80"
	// DefaultHTTPSAddr is the default https address
	DefaultHTTPSAddr = ":443"
)

// OptionFunc configures an option on the server
type OptionFunc func(*Server) error

// Server uses net/http servers to serve a handler
type Server struct {
	// ShutdownTimeout specifies how long to wait until we cancel a graceful shutdown
	ShutdownTimeout time.Duration
	// HTTP serves a handler over http. If a TLS option is provided, this
	// handler will be a redirect handler that redirects to https.
	HTTP *http.Server

	// HTTPS serves the main handler over https. Can be nil when only serving over http
	HTTPS *http.Server

	runHTTPS bool

	errors chan *serverError
}

// New creates a new server configured with the provided options.
func New(handler http.Handler, options ...OptionFunc) (*Server, error) {
	s := &Server{
		ShutdownTimeout: DefaultShutdownTimeout,
		HTTP: &http.Server{
			Addr:              DefaultHTTPAddr,
			Handler:           handler,
			ReadTimeout:       DefaultReadTimeout,
			ReadHeaderTimeout: DefaultHeaderReadTimeout,
			WriteTimeout:      DefaultWriteTimeout,
			IdleTimeout:       DefaultIdleTimeout,
		},
		HTTPS: &http.Server{
			Addr:              DefaultHTTPSAddr,
			Handler:           handler,
			TLSConfig:         &tls.Config{},
			ReadTimeout:       DefaultReadTimeout,
			ReadHeaderTimeout: DefaultHeaderReadTimeout,
			WriteTimeout:      DefaultWriteTimeout,
			IdleTimeout:       DefaultIdleTimeout,
		},
		runHTTPS: false,
		errors:   make(chan *serverError),
	}

	for _, option := range options {
		err := option(s)
		if err != nil {
			return nil, err
		}
	}

	if s.runHTTPS == false {
		s.HTTPS = nil
	}

	return s, nil
}

func (s *Server) ListenAndServe() error {
	if s.HTTP == nil {
		return errors.New("http server is nil")
	}

	go func() {
		err := s.HTTP.ListenAndServe()
		if err != http.ErrServerClosed {
			s.errors <- &serverError{
				server: s.HTTP,
				err:    fmt.Errorf("http listen error: %v", err),
			}
		}
	}()

	if s.HTTPS != nil {
		go func() {
			err := s.HTTPS.ListenAndServeTLS("", "")
			if err != http.ErrServerClosed {
				s.errors <- &serverError{
					server: s.HTTPS,
					err:    fmt.Errorf("https listen error: %v", err),
				}
			}
		}()
	}

	return s.waitForShutdown()
}

func (s *Server) waitForShutdown() error {
	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)

	shutdownWG := &sync.WaitGroup{}

	var err error

	shutdownErrors := make(chan *serverError)

	// block until one of the servers errors or a shutdown signal is received
	select {
	case <-quit:
		// shutdown all servers
		shutdownWG.Add(1)
		if s.HTTPS != nil {
			shutdownWG.Add(1)
		}

		go s.shutdownServer(s.HTTP, shutdownWG, shutdownErrors)
		if s.HTTPS != nil {
			go s.shutdownServer(s.HTTPS, shutdownWG, shutdownErrors)
		}
	case e := <-s.errors:
		if s.HTTPS == nil {
			// http (the only) server errored
			return e.err
		}

		shutdownWG.Add(1)

		// one of the servers errored, shutdown the other one
		switch e.server {
		case s.HTTP:
			go s.shutdownServer(s.HTTPS, shutdownWG, shutdownErrors)
		case s.HTTPS:
			go s.shutdownServer(s.HTTP, shutdownWG, shutdownErrors)
		}

		err = e.err
	}

	// collect shutdown errors
	collectWG := &sync.WaitGroup{}
	collectWG.Add(1)

	done := make(chan struct{})
	go func() {
		fmt.Println("started collecting errors")
		for {
			select {
			case e := <-shutdownErrors:
				err = multierror.Append(err, e.err)
			case <-done:
				fmt.Println("collected errors")
				collectWG.Done()
				return
			}
		}
	}()

	// wait for the servers to finish shutting down
	shutdownWG.Wait()

	// Signal that we're done collecting errors and wait for the collecting to finish
	done <- struct{}{}
	collectWG.Wait()

	return err
}

func (s *Server) shutdownServer(server *http.Server, wg *sync.WaitGroup, errors chan<- *serverError) {
	defer wg.Done()

	ctx, cancel := context.WithTimeout(context.Background(), s.ShutdownTimeout)
	defer cancel()

	server.SetKeepAlivesEnabled(false)

	err := server.Shutdown(ctx)
	fmt.Printf("shutting down %v\n", err)
	if err != nil {
		errors <- &serverError{
			server: server,
			err:    err,
		}
	}
}

// HTTPAddr option sets the address on which the http server listens
func HTTPAddr(addr string) OptionFunc {
	return func(s *Server) error {
		s.HTTP.Addr = addr
		return nil
	}
}

// HTTPSAddr option sets the address on which the https server listens
func HTTPSAddr(addr string) OptionFunc {
	return func(s *Server) error {
		s.HTTPS.Addr = addr
		return nil
	}
}

// TLSFiles option configures TLS via the provided certificate and key files.
// When this option is provided the main handler will be served over https
func TLSFiles(certFile, keyFile string) OptionFunc {
	return func(s *Server) error {
		// We'll be serving the main handler over https
		s.runHTTPS = true

		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("could not open tls files: %v", err)
		}

		s.HTTP.Handler = http.HandlerFunc(handleHTTPRedirect)
		s.HTTPS.TLSConfig = &tls.Config{
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return &cert, nil
			},
		}

		return nil
	}
}

// TLSAuto option configures TLS via a basic autocert manager
func TLSAuto(email, dirCache string, hostnames ...string) OptionFunc {
	return func(s *Server) error {
		// We'll be serving the main handler over https
		s.runHTTPS = true

		m := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Email:      email,
			HostPolicy: autocert.HostWhitelist(hostnames...),
			Cache:      autocert.DirCache(dirCache),
		}

		s.HTTP.Handler = m.HTTPHandler(nil)
		s.HTTPS.TLSConfig = m.TLSConfig()

		return nil
	}
}

// TLSAutoManager option configures TLS via the provided autocert manager
func TLSAutoManager(m *autocert.Manager) OptionFunc {
	return func(s *Server) error {
		// We'll be serving the main handler over https
		s.runHTTPS = true

		s.HTTP.Handler = m.HTTPHandler(nil)
		s.HTTPS.TLSConfig = m.TLSConfig()
		return nil
	}
}

// ReadTimeout option sets a specific read timeout. Set to 0 for no timeout (not recommended)
func ReadTimeout(t time.Duration) OptionFunc {
	return func(s *Server) error {
		s.HTTP.ReadTimeout = t
		s.HTTPS.ReadTimeout = t
		return nil
	}
}

// ReadHeaderTimeout option sets a specific read timeout. Set to 0 for no timeout (not recommended)
func ReadHeaderTimeout(t time.Duration) OptionFunc {
	return func(s *Server) error {
		s.HTTP.ReadHeaderTimeout = t
		s.HTTPS.ReadHeaderTimeout = t
		return nil
	}
}

// WriteTimeout option sets a specific write timeout. Set to 0 for no timeout (not recommended)
func WriteTimeout(t time.Duration) OptionFunc {
	return func(s *Server) error {
		s.HTTP.WriteTimeout = t
		s.HTTPS.WriteTimeout = t
		return nil
	}
}

// IdleTimeout option sets a specific idle timeout. Set to 0 for no timeout (not recommended)
func IdleTimeout(t time.Duration) OptionFunc {
	return func(s *Server) error {
		s.HTTP.IdleTimeout = t
		s.HTTPS.IdleTimeout = t
		return nil
	}
}

// ShutdownTimeout option sets a specific shutdown timeout. Set to 0 for direct shutdown
func ShutdownTimeout(t time.Duration) OptionFunc {
	return func(s *Server) error {
		s.ShutdownTimeout = t
		return nil
	}
}

// handleHTTPRedirect is copied from autocert package
func handleHTTPRedirect(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "HEAD" {
		http.Error(w, "Use HTTPS", http.StatusBadRequest)
		return
	}
	target := "https://" + stripPort(r.Host) + r.URL.RequestURI()
	http.Redirect(w, r, target, http.StatusFound)
}

// stripPort is copied from autocert package
func stripPort(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return net.JoinHostPort(host, "443")
}

type serverError struct {
	server *http.Server
	err    error
}
