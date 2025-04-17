# viper-aws

## Usage

Examples:
* [Basic](examples/basic/main.go)

## Remote Providers

* [AWS Secrets](secrets/)

## Update secrets version stage CMD

```shell
# Linux & macOS
AWS_PROFILE=.. go run ./cmd/secrets-update/ -sid=/gin-example/local

# Windows git bash
MSYS_NO_PATHCONV=1 AWS_PROFILE=.. go run ./cmd/secrets-update/ -sid=/gin-example/local

# Windows powershell
$env:AWS_PROFILE='..'; go run cmd/secrets-update/ -sid=/gin-example/local
```
