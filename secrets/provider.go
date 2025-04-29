package secrets

import (
	"cmp"
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
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/spf13/viper"

	"github.com/litsea/viper-aws/log"
)

var ErrAwsSecretsEmptyValue = errors.New("AWS Secrets value is empty")

// Provider implements reads configuration from AWS Secrets Manager.
type Provider struct {
	clt           *secretsmanager.Client
	region        string
	secretID      string
	accessKey     string
	secretKey     string
	sessionToken  string
	versionId     string
	updateStage   bool
	keepStages    int
	watchInterval time.Duration
	quit          chan bool
	l             log.Logger
	onChangeFunc  func(out *secretsmanager.GetSecretValueOutput)
}

// NewConfigProvider returns a new Provider.
func NewConfigProvider(opts ...Option) (*Provider, error) {
	p := &Provider{
		region:        "us-east-1",
		updateStage:   false,
		keepStages:    10,
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
		return nil, fmt.Errorf("viperaws.secrets.NewConfigProvider: LoadDefaultConfig %s, %w",
			p.secretID, err)
	}

	// Create Secrets Manager client
	p.clt = secretsmanager.NewFromConfig(awsCfg)

	return p, nil
}

func (p *Provider) Name() string {
	return "aws-secrets:" + p.secretID
}

func (p *Provider) Get(rp viper.RemoteProvider) (io.Reader, error) {
	result, err := p.GetResult(rp)
	if err != nil {
		return nil, err
	}

	p.versionId = *result.VersionId

	return strings.NewReader(*result.SecretString), nil
}

// GetResult Get the secret values, will also update the version stages
//
// Required IAM policy:
// Get the value: secretsmanager:GetSecretValue
// Update the version stages: secretsmanager:ListSecretVersionIds,
// secretsmanager:UpdateSecretVersionStage
func (p *Provider) GetResult(_ viper.RemoteProvider) (*secretsmanager.GetSecretValueOutput, error) {
	// VersionStage defaults to AWSCURRENT if unspecified
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(p.secretID),
		VersionStage: aws.String("AWSCURRENT"),
	}

	// IAM policy: secretsmanager:GetSecretValue
	result, err := p.clt.GetSecretValue(context.Background(), input)
	if err != nil {
		// For a list of exceptions thrown, see
		// https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
		return nil, fmt.Errorf("viperaws.secrets.Provider.GetResult: GetSecretValue %s, %w",
			p.secretID, err)
	}

	if result == nil || result.SecretString == nil || *result.SecretString == "" {
		return nil, fmt.Errorf("viperaws.secrets.Provider.GetResult: %s, %w",
			p.secretID, ErrAwsSecretsEmptyValue)
	}

	if p.updateStage {
		// Max 20 stages
		// https://docs.aws.amazon.com/secretsmanager/latest/userguide/reference_limits.html
		stg := result.CreatedDate.Format("v2006.0102.150405")
		if !slices.Contains(result.VersionStages, stg) {
			p.cleanVersionStages()
			p.updateSecretStage(secretsmanager.UpdateSecretVersionStageInput{
				SecretId:        aws.String(p.secretID),
				MoveToVersionId: result.VersionId,
				VersionStage:    aws.String(stg),
			})
		}
	}

	return result, nil
}

func (p *Provider) cleanVersionStages() {
	in := secretsmanager.ListSecretVersionIdsInput{
		SecretId:   aws.String(p.secretID),
		MaxResults: aws.Int32(100),
	}
	out, err := p.clt.ListSecretVersionIds(context.Background(), &in)
	if err != nil {
		p.l.Warn("viperaws.secrets.Provider.cleanVersionStages: ListSecretVersionIds",
			"secretID", p.secretID, "err", err)
		return
	}

	if len(out.Versions) <= p.keepStages {
		return
	}

	vs := out.Versions

	// The original output is disorganized
	slices.SortFunc(vs, func(a, b types.SecretVersionsListEntry) int {
		if a.CreatedDate == nil || b.CreatedDate == nil {
			return 0
		}
		return cmp.Compare(b.CreatedDate.Unix(), a.CreatedDate.Unix())
	})

	// Keep current and previous
	vs = slices.DeleteFunc(vs, func(v types.SecretVersionsListEntry) bool {
		if len(v.VersionStages) == 0 {
			return true
		}
		return slices.Contains(v.VersionStages, "AWSCURRENT") ||
			slices.Contains(v.VersionStages, "AWSPREVIOUS")
	})

	vs = vs[p.keepStages-2:]

	for _, v := range vs {
		if v.VersionId == nil || len(v.VersionStages) == 0 {
			continue
		}

		for _, stg := range v.VersionStages {
			p.updateSecretStage(secretsmanager.UpdateSecretVersionStageInput{
				SecretId:            aws.String(p.secretID),
				RemoveFromVersionId: v.VersionId,
				VersionStage:        aws.String(stg),
			})
		}
	}
}

func (p *Provider) updateSecretStage(in secretsmanager.UpdateSecretVersionStageInput) {
	_, err := p.clt.UpdateSecretVersionStage(context.Background(), &in)
	msg := "viperaws.secrets.Provider.updateSecretStage: "
	if in.MoveToVersionId != nil {
		msg += "add new stage"
	} else {
		msg += "delete old stage"
	}

	if err != nil {
		// Concurrent updates cause 400 error (version stage already updated)
		// InvalidParameterException:
		// Staging label vx.y.z isn't currently attached to version <UUID>
		var ee *types.InvalidParameterException
		if !errors.As(err, &ee) {
			p.l.Warn(msg, "secretID", p.secretID, "stage", *in.VersionStage, "err", err)
		}
		return
	}

	p.l.Info(msg, "secretID", p.secretID, "stage", *in.VersionStage)
}

func (p *Provider) Watch(rp viper.RemoteProvider) (io.Reader, error) {
	r, err := p.Get(rp)
	if err != nil {
		return nil, fmt.Errorf("viperaws.secrets.Provider.Watch: %s, %w",
			p.secretID, err)
	}

	return r, nil
}

func (p *Provider) WatchChannel(rp viper.RemoteProvider) (<-chan *viper.RemoteResponse, chan bool) {
	p.l.Info("viperaws.secrets.Provider.WatchChannel: start watching...", "secretID", p.secretID)

	ticker := time.NewTicker(p.watchInterval)

	ch := make(chan *viper.RemoteResponse)
	quit := make(chan bool)

	go func() {
		defer func() {
			if err := recover(); err != nil {
				p.l.Error("viperaws.secrets.Provider.WatchChannel: recovery form panic",
					"err", fmt.Errorf("panic error: %v", err))
			}
		}()

		for {
			select {
			case <-ticker.C:
				out, err := p.GetResult(rp)
				if err != nil {
					p.l.Error("viperaws.secrets.Provider.WatchChannel",
						"secretID", p.secretID, "err", err)
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
			case <-p.quit:
				ticker.Stop()
				return
			}
		}
	}()
	return ch, quit
}

func (p *Provider) QuitWatch() {
	p.l.Info("viperaws.secrets.Provider.QuitWatch", "secretID", p.secretID)
	p.quit <- true
}
