package viperaws

import (
	"fmt"

	"github.com/spf13/viper"

	"github.com/litsea/viper-aws/remote"
)

type Config struct {
	v            *viper.Viper
	typ          string
	file         string
	provider     remote.ConfigProvider
	setDefaultFn func(v *viper.Viper)
}

func New(v *viper.Viper, opts ...Option) *Config {
	c := &Config{
		v:    v,
		typ:  "yaml",
		file: "./app.yaml",
	}

	for _, opt := range opts {
		opt(c)
	}

	c.v.SetConfigType(c.typ)

	return c
}

func (c *Config) V() *viper.Viper {
	return c.v
}

func (c *Config) Read() error {
	var err error

	if c.provider != nil {
		remote.RegisterConfigProvider(c.provider.Name(), c.provider)
		_ = c.v.AddRemoteProvider(c.provider.Name(), "endpoint", "path")
		err = c.v.ReadRemoteConfig()
	} else {
		c.v.SetConfigFile(c.file)
		err = c.v.ReadInConfig()
	}

	if err != nil {
		return fmt.Errorf("config.Read: %w", err)
	}

	if c.setDefaultFn != nil {
		c.setDefaultFn(c.v)
	}

	if c.provider != nil {
		err = c.v.WatchRemoteConfigOnChannel()
		if err != nil {
			return fmt.Errorf("config.Read: WatchRemoteConfig %w", err)
		}
	} else {
		c.v.WatchConfig()
	}

	return nil
}
