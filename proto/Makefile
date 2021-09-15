
gen-all: gen-dir gen-grpc

gen-dir:
	mkdir -p gen

## compile all proto file
gen-grpc:
	protoc v1/l3afdconfig/l3afdconfig_service.proto -I=. \
		  --go_out=gen --go_opt=paths=source_relative \
 		  --go-grpc_out=gen --go-grpc_opt=paths=source_relative \
 		  --grpc-gateway_out=gen  --grpc-gateway_opt=paths=source_relative \
 		  --openapiv2_out=gen --openapiv2_opt logtostderr=true ;
# 		  --swagger_out=gen --go_opt=paths=source_relative;
clean:
	rm -rf gen/v1/l3afdconfig/l3afdconfig_service*
deps:
	go get -u google.golang.org/protobuf/cmd/protoc-gen-go
	go get -u google.golang.org/grpc/cmd/protoc-gen-go-grpc
	go get -u github.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger