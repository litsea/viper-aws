package main

import (
	"log/slog"
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
	sid := "/app-a/local/test"
	cfg, err := vp.NewSecrets(v, sid, []vp.Option{}, []secrets.Option{
		secrets.WithRegion("us-east-1"),
		secrets.WithLogger(l),
		secrets.WithOnChangeFunc(func(out *secretsmanager.GetSecretValueOutput) {
			l.Info("secret value changed", "version", *out.VersionId,
				"createdDate", out.CreatedDate)
		}),
	})
	if err != nil {
		l.Error("init secrets config", "err", err)
		os.Exit(1)
	}

	for {
		foo := cfg.V().Get("foo")

		l.Info("config foo value", "foo", foo)
		time.Sleep(3 * time.Second)
	}
}
