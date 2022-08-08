.PHONY: all

export GOPATH := $(HOME)/go
all: swagger build

swagger:
	@mkdir $(GOPATH) || true 
	@go get -u github.com/swaggo/swag/cmd/swag
	@go get -u github.com/swaggo/http-swagger
	@go get -u github.com/alecthomas/template
	@$(GOPATH)/bin/swag init -d "./" -g "apis/configwatch.go"

build:
	@go build

install: swagger
	@go install .
