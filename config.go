package viperaws

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"

	"github.com/litsea/viper-aws/log"
	"github.com/litsea/viper-aws/parameterstore"
	"github.com/litsea/viper-aws/remote"
	"github.com/litsea/viper-aws/secrets"
)

type Config struct {
	v                *viper.Viper
	l                log.Logger
	typ              string
	file             string
	onFileChangeFunc func(evt fsnotify.Event)
	provider         remote.ConfigProvider
	setDefaultFn     func(v *viper.Viper)
}

func New(v *viper.Viper, opts ...Option) *Config {
	c := &Config{
		v:    v,
		l:    &log.EmptyLogger{},
		typ:  "yaml",
		file: "./app.yaml",
	}

	for _, opt := range opts {
		opt(c)
	}

	c.v.SetConfigType(c.typ)

	return c
}

func NewFile(v *viper.Viper, opts ...Option) (*Config, error) {
	cfg := New(v, opts...)
	err := cfg.Read()
	if err != nil {
		return nil, fmt.Errorf("viperaws.NewFile: read failed, %w", err)
	}

	cfg.v.OnConfigChange(cfg.OnFileDeDupChangeFn(cfg.onFileChangeFunc))
	cfg.v.WatchConfig()

	return cfg, nil
}

func NewSecrets(v *viper.Viper, sid string, vos []Option, pos []secrets.Option) (*Config, error) {
	pos = append(pos,
		secrets.WithSecretID(sid),
	)
	p, err := secrets.NewConfigProvider(pos...)
	if err != nil {
		return nil, fmt.Errorf("viperaws.NewSecrets: NewConfigProvider, %w", err)
	}

	vos = append(vos, WithProvider(p))

	cfg := New(v, vos...)
	err = cfg.Read()
	if err != nil {
		return nil, fmt.Errorf("viperaws.NewSecrets: read failed, %w", err)
	}

	err = cfg.v.WatchRemoteConfigOnChannel()
	if err != nil {
		return nil, fmt.Errorf("viperaws.NewSecrets: WatchRemoteConfigOnChannel %w", err)
	}

	return cfg, nil
}

func NewParameterStore(
	v *viper.Viper, bp string, vos []Option, pos []parameterstore.Option,
) (*Config, error) {
	pos = append(pos,
		parameterstore.WithBasePath(bp),
	)
	p, err := parameterstore.NewConfigProvider(pos...)
	if err != nil {
		return nil, fmt.Errorf("viperaws.NewParameterStore: NewConfigProvider, %w", err)
	}

	vos = append(vos, WithProvider(p))

	cfg := New(v, vos...)
	cfg.v.SetConfigType("json")
	err = cfg.Read()
	if err != nil {
		return nil, fmt.Errorf("viperaws.NewParameterStore: read failed, %w", err)
	}

	err = cfg.v.WatchRemoteConfigOnChannel()
	if err != nil {
		return nil, fmt.Errorf("viperaws.NewParameterStore: WatchRemoteConfigOnChannel %w", err)
	}

	return cfg, nil
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

	return nil
}

// OnFileDeDupChangeFn fsnotify may have duplicate events
// See:
// https://github.com/spf13/viper/issues/948
// https://pkg.go.dev/github.com/fsnotify/fsnotify#Watcher
// https://github.com/fsnotify/fsnotify/blob/main/cmd/fsnotify/dedup.go
func (c *Config) OnFileDeDupChangeFn(fn func(evt fsnotify.Event)) func(evt fsnotify.Event) {
	var (
		// Wait 200ms for new events; each new event resets the timer.
		waitFor = 200 * time.Millisecond

		// Keep track of the timers, as path → timer.
		mu     sync.Mutex
		timers = make(map[string]*time.Timer)
	)

	return func(evt fsnotify.Event) {
		// Get timer.
		mu.Lock()
		t, ok := timers[evt.Name]
		mu.Unlock()

		// No timer yet, so create one.
		if !ok {
			t = time.AfterFunc(math.MaxInt64, func() {
				defer func() {
					if err := recover(); err != nil {
						c.l.Error("viperaws.Config.OnFileDeDupChangeFn: recovery form panic",
							"err", fmt.Errorf("panic error: %v", err))
					}
				}()

				fn(evt)
			})
			t.Stop()

			mu.Lock()
			timers[evt.Name] = t
			mu.Unlock()
		}

		// Reset the timer for this path, so it will start from 200ms again.
		t.Reset(waitFor)
	}
}
