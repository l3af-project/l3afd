.PHONY: all

all: swagger build

swagger:
	@go get -u github.com/swaggo/swag/cmd/swag
	@go get -u github.com/swaggo/http-swagger
	@go get -u github.com/alecthomas/template
	@swag init -d "./" -g "apis/configwatch.go"

build:
	@go build
