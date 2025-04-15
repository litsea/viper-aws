package viperaws

import (
	"github.com/litsea/viper-aws/remote"
)

type Option func(c *Config)

func WithType(t string) Option {
	return func(c *Config) {
		c.typ = t
	}
}

func WithFile(f string) Option {
	return func(c *Config) {
		c.file = f
	}
}

func WithProvider(p remote.ConfigProvider) Option {
	return func(c *Config) {
		c.provider = p
	}
}
