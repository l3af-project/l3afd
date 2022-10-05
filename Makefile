.PHONY: all

export GOPATH := $(HOME)/go
all: swagger build

swagger:
	@mkdir $(GOPATH) || true 
	@go install github.com/swaggo/swag/cmd/swag@latest
	@$(GOPATH)/bin/swag init -d "./" -g "apis/configwatch.go"

build:
	@go build

install: swagger
	@go install .
