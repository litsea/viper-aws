package secrets

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/spf13/viper"
)

var ErrAwsSecretsEmptyValue = errors.New("AWS Secrets value is empty")

// Provider implements reads configuration from Hashicorp Vault.
type Provider struct {
	region       string
	secretID     string
	accessKey    string
	secretKey    string
	sessionToken string
	versionId    string
	quit         chan bool
	l            Logger
	onChangeFunc func(out *secretsmanager.GetSecretValueOutput)
}

// NewConfigProvider returns a new Provider.
func NewConfigProvider(opts ...Option) *Provider {
	p := &Provider{
		region: "us-east-1",
		quit:   make(chan bool),
		l:      &emptyLogger{},
	}

	for _, opt := range opts {
		opt(p)
	}

	r := os.Getenv("AWS_REGION")
	if r != "" {
		p.region = r
	}

	return p
}

func (p *Provider) Name() string {
	return "aws-secrets:" + p.secretID
}

func (p *Provider) Get(rp viper.RemoteProvider) (io.Reader, error) {
	result, err := p.get(rp)
	if err != nil {
		return nil, err
	}

	p.versionId = *result.VersionId

	return strings.NewReader(*result.SecretString), nil
}

func (p *Provider) get(_ viper.RemoteProvider) (*secretsmanager.GetSecretValueOutput, error) {
	var (
		cfg aws.Config
		err error
	)

	opts := []func(*config.LoadOptions) error{
		config.WithRegion(p.region),
	}

	if p.accessKey != "" && p.secretKey != "" {
		cred := aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(
			p.accessKey, p.secretKey, p.sessionToken))
		opts = append(opts, config.WithCredentialsProvider(cred))
	}

	cfg, err = config.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("secrets.Provider.get: LoadDefaultConfig %s, %w",
			p.secretID, err)
	}

	// Create Secrets Manager client
	svc := secretsmanager.NewFromConfig(cfg)

	// VersionStage defaults to AWSCURRENT if unspecified
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(p.secretID),
		VersionStage: aws.String("AWSCURRENT"),
	}

	// IAM policy: secretsmanager:GetSecretValue
	result, err := svc.GetSecretValue(context.Background(), input)
	if err != nil {
		// For a list of exceptions thrown, see
		// https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
		return nil, fmt.Errorf("secrets.Provider.get: GetSecretValue %s, %w",
			p.secretID, err)
	}

	if result == nil || result.SecretString == nil || *result.SecretString == "" {
		return nil, fmt.Errorf("secrets.Provider.get: %s, %w",
			p.secretID, ErrAwsSecretsEmptyValue)
	}

	stg := result.CreatedDate.Format("v2006.0102.150405")
	if !slices.Contains(result.VersionStages, stg) {
		// IAM policy: secretsmanager:UpdateSecretVersionStage
		in := secretsmanager.UpdateSecretVersionStageInput{
			SecretId:        aws.String(p.secretID),
			MoveToVersionId: result.VersionId,
			VersionStage:    aws.String(stg),
		}
		_, err = svc.UpdateSecretVersionStage(context.Background(), &in)
		if err != nil {
			p.l.Warn("secrets.Provider.get: UpdateSecretVersionStage",
				"secretID", p.secretID, "stage", stg, "err", err)
		}
	}

	return result, nil
}

func (p *Provider) Watch(rp viper.RemoteProvider) (io.Reader, error) {
	r, err := p.Get(rp)
	if err != nil {
		return nil, fmt.Errorf("secrets.Provider.Watch: %w", err)
	}

	return r, nil
}

func (p *Provider) WatchChannel(rp viper.RemoteProvider) (<-chan *viper.RemoteResponse, chan bool) {
	ticker := time.NewTicker(time.Second * 5)

	ch := make(chan *viper.RemoteResponse)
	quit := make(chan bool)

	go func() {
		for {
			select {
			case <-ticker.C:
				out, err := p.get(rp)
				if err != nil {
					p.l.Error("secrets.Provider.WatchChannel", "err", err)
					continue
				}
				bs := []byte(*out.SecretString)

				if p.versionId == *out.VersionId {
					continue
				}

				p.versionId = *out.VersionId
				ch <- &viper.RemoteResponse{
					Value: bs,
				}

				if p.onChangeFunc != nil {
					p.onChangeFunc(out)
				}
			case <-quit:
				ticker.Stop()
				close(ch)
				return
			}
		}
	}()
	return ch, quit
}
