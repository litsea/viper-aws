package secrets

import (
	"time"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/litsea/viper-aws/log"
)

type Option func(p *Provider)

func WithSecretID(id string) Option {
	return func(p *Provider) {
		p.secretID = id
	}
}

func WithRegion(r string) Option {
	return func(p *Provider) {
		p.region = r
	}
}

func WithAccessKey(ak string) Option {
	return func(p *Provider) {
		p.accessKey = ak
	}
}

func WithSecretKey(sk string) Option {
	return func(p *Provider) {
		p.secretKey = sk
	}
}

func WithSessionToken(t string) Option {
	return func(p *Provider) {
		p.sessionToken = t
	}
}

func WithUpdateStage(u bool) Option {
	return func(p *Provider) {
		p.updateStage = u
	}
}

func WithKeepStages(i int) Option {
	return func(p *Provider) {
		if i > 2 && i < 18 {
			p.keepStages = i
		}
	}
}

func WithWatchInterval(w time.Duration) Option {
	return func(p *Provider) {
		if w > time.Second {
			p.watchInterval = w
		}
	}
}

func WithLogger(l log.Logger) Option {
	return func(p *Provider) {
		if l != nil {
			p.l = l
		}
	}
}

func WithOnChangeFunc(fn func(out *secretsmanager.GetSecretValueOutput)) Option {
	return func(p *Provider) {
		p.onChangeFunc = fn
	}
}
