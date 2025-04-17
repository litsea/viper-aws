package main

import (
	"flag"
	"log/slog"
	"os"

	"github.com/spf13/viper"

	"github.com/litsea/viper-aws/secrets"
)

var l = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{}))

// CMD for update secret version stage
func main() {
	var sid string
	flag.StringVar(&sid, "sid", "", "AWS Secrets ID")
	flag.Parse()

	if sid == "" {
		l.Error("You must provide a AWS Secrets ID")
		os.Exit(1)
	}

	checkSecretAndUpdateVersionStage(sid)
}

func checkSecretAndUpdateVersionStage(sid string) {
	l.Info("Start get secrets and update version stage", "sid", sid)

	p, err := secrets.NewConfigProvider(
		secrets.WithSecretID(sid),
		secrets.WithLogger(l),
		secrets.WithUpdateStage(true),
	)
	if err != nil {
		l.Error("secrets.NewConfigProvider", "err", err)
		os.Exit(1)
	}

	var rp viper.RemoteProvider
	result, err := p.GetResult(rp)
	if err != nil {
		l.Error("Get secrets and update version stage", "err", err)
		os.Exit(1)
	}

	l.Info("Get secrets and update version stage done",
		"version", *result.VersionId, "stages", result.VersionStages)
}
