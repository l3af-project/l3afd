.PHONY: all

export GOPATH := $(HOME)/go
all: swagger build

swagger:
	@mkdir $(GOPATH) || true 
	@go install github.com/swaggo/swag/cmd/swag@latest
	@$(GOPATH)/bin/swag init -d "./" -g "apis/configwatch.go"

build:
	@CGO_ENABLED=0 go build -ldflags \
		"-X main.Version=v1.0.0 \
		 -X main.VersionSHA=`git rev-parse HEAD`"
install: swagger
	@CGO_ENABLED=0 go install -ldflags \
		"-X main.Version=v1.0.0 \
		 -X main.VersionSHA=`git rev-parse HEAD`"
