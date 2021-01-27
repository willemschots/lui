package lui_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/willemschots/lui"
	"golang.org/x/crypto/acme/autocert"
)

var mainHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
})

type handlerAssert func(t *testing.T, handler http.Handler)

func TestNew(t *testing.T) {
	tt := map[string]struct {
		options   []lui.OptionFunc // options provided to the constructor lui.New
		expect    *lui.Server      // public fields are compared for expected values
		httpTest  handlerAssert    // verifies the http handler
		httpsTest handlerAssert    // verifies the https handler
	}{
		"defaults": {
			options: []lui.OptionFunc{},
			expect: &lui.Server{
				ShutdownTimeout: time.Second * 30,
				HTTP: &http.Server{
					Addr:              ":80",
					ReadTimeout:       time.Second * 10,
					ReadHeaderTimeout: time.Second * 5,
					WriteTimeout:      time.Second * 30,
					IdleTimeout:       time.Second * 60,
				},
			},
			httpTest:  assertMainHandler,
			httpsTest: nil,
		},
		"tls files": {
			options: []lui.OptionFunc{
				lui.TLSFiles("testdata/test.crt", "testdata/test.key"),
			},
			expect: &lui.Server{
				ShutdownTimeout: time.Second * 30,
				HTTP: &http.Server{
					Addr:              ":80",
					ReadTimeout:       time.Second * 10,
					ReadHeaderTimeout: time.Second * 5,
					WriteTimeout:      time.Second * 30,
					IdleTimeout:       time.Second * 60,
				},
				HTTPS: &http.Server{
					Addr:              ":443",
					TLSConfig:         &tls.Config{},
					ReadTimeout:       time.Second * 10,
					ReadHeaderTimeout: time.Second * 5,
					WriteTimeout:      time.Second * 30,
					IdleTimeout:       time.Second * 60,
				},
			},
			httpTest:  assertRedirectToHTTPS,
			httpsTest: assertMainHandler,
		},
		"tls auto": {
			options: []lui.OptionFunc{
				lui.TLSAuto("info@example.org", "./testdata/autocert", "example.org"),
			},
			expect: &lui.Server{
				ShutdownTimeout: time.Second * 30,
				HTTP: &http.Server{
					Addr:              ":80",
					ReadTimeout:       time.Second * 10,
					ReadHeaderTimeout: time.Second * 5,
					WriteTimeout:      time.Second * 30,
					IdleTimeout:       time.Second * 60,
				},
				HTTPS: &http.Server{
					Addr:              ":443",
					TLSConfig:         &tls.Config{},
					ReadTimeout:       time.Second * 10,
					ReadHeaderTimeout: time.Second * 5,
					WriteTimeout:      time.Second * 30,
					IdleTimeout:       time.Second * 60,
				},
			},
			httpTest:  assertACMEDoesNotRedirect,
			httpsTest: assertMainHandler,
		},
		"tls auto cert manager": {
			options: []lui.OptionFunc{
				lui.TLSAutoManager(&autocert.Manager{
					Prompt:     autocert.AcceptTOS,
					Email:      "info@example.org",
					HostPolicy: nil,
					Cache:      nil,
				}),
			},
			expect: &lui.Server{
				ShutdownTimeout: time.Second * 30,
				HTTP: &http.Server{
					Addr:              ":80",
					ReadTimeout:       time.Second * 10,
					ReadHeaderTimeout: time.Second * 5,
					WriteTimeout:      time.Second * 30,
					IdleTimeout:       time.Second * 60,
				},
				HTTPS: &http.Server{
					Addr:              ":443",
					TLSConfig:         &tls.Config{},
					ReadTimeout:       time.Second * 10,
					ReadHeaderTimeout: time.Second * 5,
					WriteTimeout:      time.Second * 30,
					IdleTimeout:       time.Second * 60,
				},
			},
			httpTest:  assertACMEDoesNotRedirect,
			httpsTest: assertMainHandler,
		},
		"http address": {
			options: []lui.OptionFunc{
				lui.HTTPAddr(":8080"),
			},
			expect: &lui.Server{
				ShutdownTimeout: time.Second * 30,
				HTTP: &http.Server{
					Addr:              ":8080",
					ReadTimeout:       time.Second * 10,
					ReadHeaderTimeout: time.Second * 5,
					WriteTimeout:      time.Second * 30,
					IdleTimeout:       time.Second * 60,
				},
			},
			httpTest:  assertMainHandler,
			httpsTest: nil,
		},
		"https address": {
			options: []lui.OptionFunc{
				lui.TLSFiles("testdata/test.crt", "testdata/test.key"),
				lui.HTTPSAddr(":4438"),
			},
			expect: &lui.Server{
				ShutdownTimeout: time.Second * 30,
				HTTP: &http.Server{
					Addr:              ":80",
					ReadTimeout:       time.Second * 10,
					ReadHeaderTimeout: time.Second * 5,
					WriteTimeout:      time.Second * 30,
					IdleTimeout:       time.Second * 60,
				},
				HTTPS: &http.Server{
					Addr:              ":4438",
					TLSConfig:         &tls.Config{},
					ReadTimeout:       time.Second * 10,
					ReadHeaderTimeout: time.Second * 5,
					WriteTimeout:      time.Second * 30,
					IdleTimeout:       time.Second * 60,
				},
			},
			httpTest:  assertRedirectToHTTPS,
			httpsTest: assertMainHandler,
		},
		"shutdown timeout": {
			options: []lui.OptionFunc{
				lui.ShutdownTimeout(time.Millisecond * 30),
			},
			expect: &lui.Server{
				ShutdownTimeout: time.Millisecond * 30,
				HTTP: &http.Server{
					Addr:              ":80",
					ReadTimeout:       time.Second * 10,
					ReadHeaderTimeout: time.Second * 5,
					WriteTimeout:      time.Second * 30,
					IdleTimeout:       time.Second * 60,
				},
			},
			httpTest:  assertMainHandler,
			httpsTest: nil,
		},
		"read timeout": {
			options: []lui.OptionFunc{
				lui.TLSFiles("testdata/test.crt", "testdata/test.key"),
				lui.ReadTimeout(time.Millisecond * 30),
			},
			expect: &lui.Server{
				ShutdownTimeout: time.Second * 30,
				HTTP: &http.Server{
					Addr:              ":80",
					ReadTimeout:       time.Millisecond * 30,
					ReadHeaderTimeout: time.Second * 5,
					WriteTimeout:      time.Second * 30,
					IdleTimeout:       time.Second * 60,
				},
				HTTPS: &http.Server{
					Addr:              ":443",
					TLSConfig:         &tls.Config{},
					ReadTimeout:       time.Millisecond * 30,
					ReadHeaderTimeout: time.Second * 5,
					WriteTimeout:      time.Second * 30,
					IdleTimeout:       time.Second * 60,
				},
			},
			httpTest:  assertRedirectToHTTPS,
			httpsTest: assertMainHandler,
		},
		"read header timeout": {
			options: []lui.OptionFunc{
				lui.TLSFiles("testdata/test.crt", "testdata/test.key"),
				lui.ReadHeaderTimeout(time.Millisecond * 30),
			},
			expect: &lui.Server{
				ShutdownTimeout: time.Second * 30,
				HTTP: &http.Server{
					Addr:              ":80",
					ReadTimeout:       time.Second * 10,
					ReadHeaderTimeout: time.Millisecond * 30,
					WriteTimeout:      time.Second * 30,
					IdleTimeout:       time.Second * 60,
				},
				HTTPS: &http.Server{
					Addr:              ":443",
					TLSConfig:         &tls.Config{},
					ReadTimeout:       time.Second * 10,
					ReadHeaderTimeout: time.Millisecond * 30,
					WriteTimeout:      time.Second * 30,
					IdleTimeout:       time.Second * 60,
				},
			},
			httpTest:  assertRedirectToHTTPS,
			httpsTest: assertMainHandler,
		},
		"write timeout": {
			options: []lui.OptionFunc{
				lui.TLSFiles("testdata/test.crt", "testdata/test.key"),
				lui.WriteTimeout(time.Millisecond * 30),
			},
			expect: &lui.Server{
				ShutdownTimeout: time.Second * 30,
				HTTP: &http.Server{
					Addr:              ":80",
					ReadTimeout:       time.Second * 10,
					ReadHeaderTimeout: time.Second * 5,
					WriteTimeout:      time.Millisecond * 30,
					IdleTimeout:       time.Second * 60,
				},
				HTTPS: &http.Server{
					Addr:              ":443",
					TLSConfig:         &tls.Config{},
					ReadTimeout:       time.Second * 10,
					ReadHeaderTimeout: time.Second * 5,
					WriteTimeout:      time.Millisecond * 30,
					IdleTimeout:       time.Second * 60,
				},
			},
			httpTest:  assertRedirectToHTTPS,
			httpsTest: assertMainHandler,
		},
		"idle timeout": {
			options: []lui.OptionFunc{
				lui.TLSFiles("testdata/test.crt", "testdata/test.key"),
				lui.IdleTimeout(time.Millisecond * 30),
			},
			expect: &lui.Server{
				ShutdownTimeout: time.Second * 30,
				HTTP: &http.Server{
					Addr:              ":80",
					ReadTimeout:       time.Second * 10,
					ReadHeaderTimeout: time.Second * 5,
					WriteTimeout:      time.Second * 30,
					IdleTimeout:       time.Millisecond * 30,
				},
				HTTPS: &http.Server{
					Addr:              ":443",
					TLSConfig:         &tls.Config{},
					ReadTimeout:       time.Second * 10,
					ReadHeaderTimeout: time.Second * 5,
					WriteTimeout:      time.Second * 30,
					IdleTimeout:       time.Millisecond * 30,
				},
			},
			httpTest:  assertRedirectToHTTPS,
			httpsTest: assertMainHandler,
		},
	}

	for test, tc := range tt {
		t.Run(test, func(t *testing.T) {
			setupTLSFiles(t, "testdata/test.crt", "testdata/test.key")
			srv, err := lui.New(mainHandler, tc.options...)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			assertServer(t, tc.expect, srv)

			if tc.httpTest != nil {
				tc.httpTest(t, srv.HTTP.Handler)
			}

			if tc.httpsTest != nil {
				tc.httpsTest(t, srv.HTTPS.Handler)
			}
		})

	}
}

func TestNewErrorFromOption(t *testing.T) {
	testErr := errors.New("test")
	optionFunc := func(s *lui.Server) error {
		return testErr
	}

	_, err := lui.New(mainHandler, optionFunc)
	if err != testErr {
		t.Errorf("expected error %v but got %v", testErr, err)
	}
}

func assertServer(t *testing.T, expect, x *lui.Server) {
	if expect == nil && x == nil {
		return
	}

	if (expect == nil || x == nil) && (expect != x) {
		t.Errorf("expected server %v but got %v", expect, x)
		return
	}

	if expect.ShutdownTimeout != x.ShutdownTimeout {
		t.Errorf("shutdown timeout %v but got %v", expect.ShutdownTimeout, x.ShutdownTimeout)
	}

	assertHTTPServer(t, expect.HTTP, x.HTTP)
	assertHTTPServer(t, expect.HTTPS, x.HTTPS)
	if x.HTTPS != nil {
		assertTLSConfig(t, expect.HTTPS.TLSConfig, x.HTTPS.TLSConfig)
	}
}

func assertHTTPServer(t *testing.T, expect, x *http.Server) {
	if expect == nil && x == nil {
		return
	}

	if (expect == nil || x == nil) && (expect != x) {
		t.Errorf("expected http server %v but got %v", expect, x)
		return
	}

	if expect.Addr != x.Addr {
		t.Errorf("expected addr %v but got %v", expect.Addr, x.Addr)
	}

	if x.Handler == nil {
		t.Error("expected server to have a handler but got <nil>")
	}

	if expect.ReadTimeout != x.ReadTimeout {
		t.Errorf("expected read timeout %v but got %v", expect.ReadTimeout, x.ReadTimeout)
	}

	if expect.ReadHeaderTimeout != x.ReadHeaderTimeout {
		t.Errorf("expected read header timeout %v but got %v", expect.ReadHeaderTimeout, x.ReadHeaderTimeout)
	}

	if expect.WriteTimeout != x.WriteTimeout {
		t.Errorf("expected write timeout %v but got %v", expect.WriteTimeout, x.WriteTimeout)
	}

	if expect.IdleTimeout != x.IdleTimeout {
		t.Errorf("expected idle timeout %v but got %v", expect.IdleTimeout, x.IdleTimeout)
	}
}

func assertTLSConfig(t *testing.T, expect, x *tls.Config) {
	// TODO: Find a better way of testing the get certificate method
	if x.GetCertificate == nil {
		t.Errorf("expected a get certificate method to be provided but got <nil>")
	}
}

func assertMainHandler(t *testing.T, handler http.Handler) {
	w := httptest.NewRecorder()
	r, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	assertNoErr(t, err)

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %v but got %v", http.StatusOK, w.Code)
	}

	body := w.Body.String()
	if body != "ok" {
		t.Errorf("expected body %v but got %v", "ok", body)
	}
}

func assertRedirectToHTTPS(t *testing.T, handler http.Handler) {
	// valid methods for redirects
	for _, method := range []string{
		http.MethodGet,
		http.MethodHead,
	} {
		w := httptest.NewRecorder()
		r, err := http.NewRequest(method, "http://example.com/test", nil)
		assertNoErr(t, err)

		handler.ServeHTTP(w, r)

		if w.Code != http.StatusFound {
			t.Errorf("expected status %v but got %v", http.StatusFound, w.Code)
		}

		loc := w.Header().Get("Location")
		if loc != "https://example.com/test" {
			t.Errorf("expected location header %v but got %v", "https://example.com/test", loc)
		}
	}

	// invalid methods for redirects
	for _, method := range []string{
		http.MethodConnect,
		http.MethodDelete,
		http.MethodOptions,
		http.MethodPatch,
		http.MethodPost,
		http.MethodPut,
		http.MethodTrace,
	} {

		w := httptest.NewRecorder()
		r, err := http.NewRequest(method, "http://example.com/test", nil)
		assertNoErr(t, err)

		handler.ServeHTTP(w, r)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %v but got %v", http.StatusBadRequest, w.Code)
		}
	}
}

func assertACMEDoesNotRedirect(t *testing.T, handler http.Handler) {
	assertRedirectToHTTPS(t, handler)

	w := httptest.NewRecorder()
	r, err := http.NewRequest(http.MethodGet, "http://example.com/.well-known/acme-challenge/test", nil)
	assertNoErr(t, err)

	handler.ServeHTTP(w, r)

	// check that we don't redirect this url
	if w.Code == http.StatusFound {
		t.Errorf("unexpected status %v", http.StatusFound)
	}
}

func assertNoErr(t *testing.T, err error) {
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// setupTLSFiles creates the self signed private key and certificate
func setupTLSFiles(t *testing.T, certPath, keyPath string) {
	private, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}

	certFile, err := os.Create(certPath)
	if err != nil {
		t.Fatal(err)
	}
	defer certFile.Close()

	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	if err != nil {
		t.Fatal(err)
	}

	keyData, err := x509.MarshalECPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}

	keyFile, err := os.Create(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer keyFile.Close()

	err = pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyData})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		err = os.Remove(certPath)
		if err != nil {
			t.Fatal(err)
		}

		err = os.Remove(keyPath)
		if err != nil {
			t.Fatal(err)
		}
	})
}
