package main

import (
	"log/slog"
	"os"
	"time"

	"github.com/spf13/viper"

	vp "github.com/litsea/viper-aws"
	"github.com/litsea/viper-aws/parameterstore"
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
	basePath := "/app-a/local/"
	cfg, err := vp.NewParameterStore(v, basePath, []vp.Option{}, []parameterstore.Option{
		parameterstore.WithRegion("us-east-1"),
		parameterstore.WithLogger(l),
		parameterstore.WithOnChangeFunc(func(ps *parameterstore.Parameters, changes *parameterstore.Changes) {
			for _, k := range changes.Created {
				p := ps.Get(k)
				l.Info("parameter Created", "fullPath", ps.GetFullPath(k),
					"version", p.Version, "lastModifiedDate", p.LastModifiedDate)
			}

			for _, k := range changes.Updated {
				p := ps.Get(k)
				l.Info("parameter Updated", "fullPath", ps.GetFullPath(k),
					"version", p.Version, "lastModifiedDate", p.LastModifiedDate)
			}

			for _, k := range changes.Deleted {
				l.Info("parameter Deleted", "fullPath", ps.GetFullPath(k))
			}
		}),
	})
	if err != nil {
		l.Error("init parameterstore config", "err", err)
		os.Exit(1)
	}

	for {
		l.Info("config values", "foo", cfg.V().Get("foo"), "bar", cfg.V().Get("bar"))
		time.Sleep(3 * time.Second)
	}
}
