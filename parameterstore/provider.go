package parameterstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/spf13/viper"

	"github.com/litsea/viper-aws/log"
)

var ErrAwsSSMParametersEmpty = errors.New("AWS SSM parameters is empty")

// Provider implements reads configuration from AWS Parameter Store.
type Provider struct {
	clt           *ssm.Client
	region        string
	accessKey     string
	secretKey     string
	sessionToken  string
	basePath      string // /<project>/<env>/
	versions      map[string]int64
	watchInterval time.Duration
	quit          chan bool
	l             log.Logger
	onChangeFunc  func(ps *Parameters, changes *Changes)
}

type Changes struct {
	Current []string
	Created []string
	Updated []string
	Deleted []string
}

// NewConfigProvider returns a new Provider.
func NewConfigProvider(opts ...Option) (*Provider, error) {
	p := &Provider{
		region:        "us-east-1",
		versions:      make(map[string]int64),
		watchInterval: 5 * time.Second,
		quit:          make(chan bool),
		l:             &log.EmptyLogger{},
	}

	for _, opt := range opts {
		opt(p)
	}

	r := os.Getenv("AWS_REGION")
	if r != "" {
		p.region = r
	}

	awsOpts := []func(*config.LoadOptions) error{
		config.WithRegion(p.region),
	}

	if p.accessKey != "" && p.secretKey != "" {
		cred := aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(
			p.accessKey, p.secretKey, p.sessionToken))
		awsOpts = append(awsOpts, config.WithCredentialsProvider(cred))
	}

	awsCfg, err := config.LoadDefaultConfig(context.Background(), awsOpts...)
	if err != nil {
		return nil, fmt.Errorf("viperaws.parameterstore.NewConfigProvider: LoadDefaultConfig %s, %w",
			p.basePath, err)
	}

	// Create Secrets Manager client
	p.clt = ssm.NewFromConfig(awsCfg)

	return p, nil
}

func (p *Provider) Name() string {
	return "aws-parameterstore:" + p.basePath
}

func (p *Provider) Get(rp viper.RemoteProvider) (io.Reader, error) {
	result, err := p.GetResult(rp)
	if err != nil {
		return nil, err
	}

	for k, v := range result.parameters {
		p.versions[k] = v.Version
	}

	return result, nil
}

// GetResult Get the parameters by basePath
//
// Required IAM policy:
// Get the parameters by path: ssm:GetParametersByPath
func (p *Provider) GetResult(_ viper.RemoteProvider) (*Parameters, error) {
	getFn := func(next *string) (*ssm.GetParametersByPathOutput, error) {
		input := &ssm.GetParametersByPathInput{
			Path:           aws.String(p.basePath),
			WithDecryption: aws.Bool(true),
			MaxResults:     aws.Int32(10), // Maximum value of 10
			NextToken:      next,
		}

		return p.clt.GetParametersByPath(context.Background(), input)
	}

	var next *string
	ps := make(map[string]*Parameter)

	for {
		result, err := getFn(next)
		if err != nil {
			// For a list of exceptions thrown, see
			// https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_GetParametersByPath.html
			return nil, fmt.Errorf("viperaws.parameterstore.Provider.GetResult: GetParametersByPath %s, %w",
				p.basePath, err)
		}

		if result == nil {
			break
		}

		if len(result.Parameters) > 0 {
			for _, v := range result.Parameters {
				if v.Name == nil {
					continue
				}

				k := strings.Replace(*v.Name, p.basePath, "", 1)
				ps[k] = &Parameter{
					Key:              *v.Name,
					Value:            v.Value,
					Version:          v.Version,
					LastModifiedDate: *v.LastModifiedDate,
				}
			}
		}

		if result.NextToken == nil {
			break
		}

		next = result.NextToken
	}

	if len(ps) == 0 {
		return nil, fmt.Errorf("viperaws.parameterstore.Provider.GetResult: %s, %w",
			p.basePath, ErrAwsSSMParametersEmpty)
	}

	return NewParameters(p.basePath, ps), nil
}

func (p *Provider) Watch(rp viper.RemoteProvider) (io.Reader, error) {
	r, err := p.Get(rp)
	if err != nil {
		return nil, fmt.Errorf("viperaws.parameterstore.Provider.Watch: %s, %w",
			p.basePath, err)
	}

	return r, nil
}

func (p *Provider) WatchChannel(rp viper.RemoteProvider) (<-chan *viper.RemoteResponse, chan bool) {
	p.l.Info("viperaws.parameterstore.Provider.WatchChannel: start watching...", "basePath", p.basePath)

	ticker := time.NewTicker(p.watchInterval)

	ch := make(chan *viper.RemoteResponse)
	quit := make(chan bool)

	go func() {
		defer func() {
			if err := recover(); err != nil {
				p.l.Error("viperaws.parameterstore.Provider.WatchChannel: recovery form panic",
					"err", fmt.Errorf("panic error: %v", err))
			}
		}()

		for {
			select {
			case <-ticker.C:
				ps, err := p.GetResult(rp)
				if err != nil {
					p.l.Error("viperaws.parameterstore.Provider.WatchChannel, GetResult",
						"basePath", p.basePath, "err", err)
					continue
				}

				changes := p.getChanges(ps)
				if len(changes.Created) == 0 && len(changes.Updated) == 0 && len(changes.Deleted) == 0 {
					continue
				}

				buf := new(bytes.Buffer)
				_, err = buf.ReadFrom(ps)
				if err != nil {
					p.l.Error("viperaws.parameterstore.Provider.WatchChannel, Read buffer",
						"basePath", p.basePath, "err", err)
					continue
				}

				ch <- &viper.RemoteResponse{
					Value: buf.Bytes(),
				}

				if p.onChangeFunc != nil {
					p.onChangeFunc(ps, changes)
				}
			case <-p.quit:
				ticker.Stop()
				return
			}
		}
	}()
	return ch, quit
}

func (p *Provider) getChanges(ps *Parameters) *Changes {
	changes := &Changes{
		Current: make([]string, 0),
		Updated: make([]string, 0),
		Created: make([]string, 0),
		Deleted: make([]string, 0),
	}
	for k, v := range p.versions {
		pp, ok := ps.parameters[k]
		if ok {
			if pp.Version != v {
				changes.Updated = append(changes.Updated, k)
			}
		} else {
			// https://github.com/spf13/viper/pull/1456
			changes.Deleted = append(changes.Deleted, k)
		}
	}

	vs := make(map[string]int64, len(ps.parameters))
	for k, v := range ps.parameters {
		changes.Current = append(changes.Current, k)
		vs[k] = v.Version
		if _, ok := p.versions[k]; !ok {
			changes.Created = append(changes.Created, k)
		}
	}

	p.versions = vs

	return changes
}

func (p *Provider) QuitWatch() {
	p.l.Info("viperaws.parameterstore.Provider.QuitWatch", "basePath", p.basePath)
	p.quit <- true
}
