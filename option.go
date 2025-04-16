package viperaws

import (
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"

	"github.com/litsea/viper-aws/log"
	"github.com/litsea/viper-aws/remote"
)

type Option func(c *Config)

func WithLogger(l log.Logger) Option {
	return func(c *Config) {
		if l != nil {
			c.l = l
		}
	}
}

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

func WithOnFileChange(fn func(evt fsnotify.Event)) Option {
	return func(c *Config) {
		if fn != nil {
			c.onFileChangeFunc = fn
		}
	}
}

func WithProvider(p remote.ConfigProvider) Option {
	return func(c *Config) {
		c.provider = p
	}
}

func WithSetDefaultFunc(fn func(v *viper.Viper)) Option {
	return func(c *Config) {
		if fn != nil {
			c.setDefaultFn = fn
		}
	}
}
