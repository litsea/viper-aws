package main

import (
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/spf13/viper"

	vp "github.com/litsea/viper-aws"
	"github.com/litsea/viper-aws/secrets"
)

func main() {
	lvl := new(slog.LevelVar)
	lvl.Set(slog.LevelInfo)
	l := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: lvl,
	}))
	v := viper.NewWithOptions(viper.WithLogger(l))

	// Shared AWS credential, set environment variables:
	//   AWS_ACCESS_KEY_ID
	//   AWS_SECRET_ACCESS_KEY
	//   AWS_SESSION_TOKEN (optional)
	// Static AWS credential, Use option functions:
	//   WithAccessKey()
	//   WithSecretKey()
	//   WithSessionToken()
	p, err := secrets.NewConfigProvider(
		secrets.WithRegion("us-east-1"),
		secrets.WithSecretID("/app-a/local/test"),
		secrets.WithLogger(l),
		secrets.WithOnChangeFunc(func(out *secretsmanager.GetSecretValueOutput) {
			l.Info("secret value changed", "version", *out.VersionId,
				"createdDate", out.CreatedDate)
		}),
	)
	if err != nil {
		l.Error("init config", "err", err)
		os.Exit(1)
	}

	cfg := vp.New(v, vp.WithProvider(p))
	if err = cfg.Read(); err != nil {
		l.Error("init config", "err", err)
		os.Exit(1)
	}

	startServer(lvl)

	for {
		foo := cfg.V().Get("foo")

		l.Info("config foo value", "foo", foo)
		time.Sleep(3 * time.Second)
	}
}

func startServer(lvl *slog.LevelVar) {
	// http://localhost:8001/update-log-lvl?lvl=error
	http.HandleFunc("/update-log-lvl", func(w http.ResponseWriter, r *http.Request) {
		lv := r.URL.Query().Get("lvl")
		switch lv {
		case "debug":
			lvl.Set(slog.LevelDebug)
		case "info":
			lvl.Set(slog.LevelInfo)
		case "warn":
			lvl.Set(slog.LevelWarn)
		case "error":
			lvl.Set(slog.LevelError)
		default:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("invalid lvl: " + lv))
			return
		}
		_, _ = w.Write([]byte("log lvl set to " + lv))
	})

	srv := &http.Server{
		Addr:              ":8001",
		ReadHeaderTimeout: 3 * time.Second,
	}

	go func() {
		_ = srv.ListenAndServe()
	}()
}
