package parameterstore

import (
	"time"

	"github.com/litsea/viper-aws/log"
)

type Option func(p *Provider)

func WithBasePath(bp string) Option {
	return func(p *Provider) {
		if bp == "" {
			return
		}

		if bp[len(bp)-1] != '/' {
			bp += "/"
		}
		p.basePath = bp
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

func WithOnChangeFunc(fn func(ps *Parameters, changes *Changes)) Option {
	return func(p *Provider) {
		p.onChangeFunc = fn
	}
}
