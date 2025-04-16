package viperaws

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"

	"github.com/litsea/viper-aws/remote"
	"github.com/litsea/viper-aws/secrets"
)

type Config struct {
	v                *viper.Viper
	typ              string
	file             string
	onFileChangeFunc func(evt fsnotify.Event)
	provider         remote.ConfigProvider
	setDefaultFn     func(v *viper.Viper)
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

func NewFile(v *viper.Viper, opts ...Option) (*Config, error) {
	cfg := New(v, opts...)
	err := cfg.Read()
	if err != nil {
		return nil, fmt.Errorf("viperaws.NewFile: read failed, %w", err)
	}

	cfg.v.OnConfigChange(cfg.onFileChangeFunc)
	cfg.v.WatchConfig()

	return cfg, nil
}

func NewSecrets(v *viper.Viper, sid string, vos []Option, pos []secrets.Option) (*Config, error) {
	pos = append(pos,
		secrets.WithSecretID(sid),
	)
	p := secrets.NewConfigProvider(pos...)

	vos = append(vos, WithProvider(p))

	cfg := New(v, vos...)
	err := cfg.Read()
	if err != nil {
		return nil, fmt.Errorf("viperaws.NewSecrets: read failed, %w", err)
	}

	err = cfg.v.WatchRemoteConfigOnChannel()
	if err != nil {
		return nil, fmt.Errorf("viperaws.NewSecrets: WatchRemoteConfigOnChannel %w", err)
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
func OnFileDeDupChangeFn(fn func(evt fsnotify.Event)) func(evt fsnotify.Event) {
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
			t = time.AfterFunc(math.MaxInt64, func() { fn(evt) })
			t.Stop()

			mu.Lock()
			timers[evt.Name] = t
			mu.Unlock()
		}

		// Reset the timer for this path, so it will start from 200ms again.
		t.Reset(waitFor)
	}
}
