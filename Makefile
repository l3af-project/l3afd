.PHONY: all

export GOPATH := $(HOME)/go
all: swagger build

swagger:
	@mkdir $(GOPATH) || true 
	@go install github.com/swaggo/swag/cmd/swag@latest
	@$(GOPATH)/bin/swag init -d "./" -g "apis/configwatch.go"

build:
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-extldflags=-static"

install: swagger
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go install -ldflags="-extldflags=-static"
