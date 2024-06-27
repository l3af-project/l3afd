.PHONY: all

export GOPATH := $(HOME)/go
all: swagger build

swagger:
	@mkdir $(GOPATH) || true 
	@go install github.com/swaggo/swag/cmd/swag@latest
	@$(GOPATH)/bin/swag init -d "./" -g "apis/configwatch.go"

build:
	@CGO_ENABLED=0 go build -cover -ldflags \
		"-X main.Version=v2.0.0 \
		 -X main.VersionSHA=`git rev-parse HEAD`"
install: swagger
	@go mod tidy
	@CGO_ENABLED=0 go install -cover -ldflags \
		"-X main.Version=v2.0.0 \
		 -X main.VersionSHA=`git rev-parse HEAD`"

container-image:
	@docker build . -t l3afd 