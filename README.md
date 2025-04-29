# viper-aws

## Remote Providers

* [AWS Secrets](secrets/)
* [AWS Parameter Store](parameterstore/)

## Usage

Examples:
* [AWS Secrets](examples/secrets/main.go)
* [AWS Parameter Store](examples/parameterstore/main.go)

## Update Secrets version stage CMD

```shell
# Linux & macOS
AWS_PROFILE=.. go run ./cmd/secrets-update/ -sid=/gin-example/local

# Windows git bash
MSYS_NO_PATHCONV=1 AWS_PROFILE=.. go run ./cmd/secrets-update/ -sid=/gin-example/local

# Windows powershell
$env:AWS_PROFILE='..'; go run cmd/secrets-update/ -sid=/gin-example/local
```
