.PHONY: all

export GOPATH := $(HOME)/go
all: swagger build

swagger:
	@mkdir $(GOPATH) || true 
	@go install github.com/swaggo/swag/cmd/swag@latest
	@$(GOPATH)/bin/swag init -d "./" -g "apis/configwatch.go"

build:
	@CGO_ENABLED=0 go build

install: swagger
	@CGO_ENABLED=0 go install
