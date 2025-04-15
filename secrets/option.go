package secrets

import (
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
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

func WithLogger(l Logger) Option {
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
