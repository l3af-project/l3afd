ARG GOARCH="amd64"
ARG VERSION="2.0.0"


FROM golang:1.22 AS builder
# golang envs
ARG GOARCH="amd64"
ARG GOOS=linux
ENV CGO_ENABLED=0

WORKDIR /go/src/app
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 go build -o /go/bin/l3afd -ldflags \
"-X main.Version=${VERSION} \
 -X main.VersionSHA=`git rev-parse HEAD`"

FROM gcr.io/distroless/static-debian12
COPY --from=builder --chown=root:root /go/bin/l3afd /l3afd
CMD ["/l3afd"]
