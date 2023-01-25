GITTAG=`git describe --tags`
VERSION=`git rev-parse --short HEAD`
flags=-ldflags="-s -w -X main.gitVersion=${VERSION} -X main.gitTag=${GITTAG} -extldflags -static"

all: build

vet:
	go vet .

build:
	go clean; rm -rf pkg; CGO_ENABLED=0 go build -o kpass ${flags}

build_debug:
	go clean; rm -rf pkg; CGO_ENABLED=0 go build -o kpass ${flags} -gcflags="-m -m"

build_amd64: build_linux

build_darwin_amd64:
	go clean; rm -rf pkg kpass; GOOS=darwin CGO_ENABLED=0 go build -o kpass ${flags}

build_darwin_arm64:
	go clean; rm -rf pkg kpass; GOARCH=arm64 GOOS=darwin CGO_ENABLED=0 go build -o kpass ${flags}

build_linux:
	go clean; rm -rf pkg kpass; GOOS=linux CGO_ENABLED=0 go build -o kpass ${flags}

build_power8:
	go clean; rm -rf pkg kpass; GOARCH=ppc64le GOOS=linux CGO_ENABLED=0 go build -o kpass ${flags}

build_arm64:
	go clean; rm -rf pkg kpass; GOARCH=arm64 GOOS=linux CGO_ENABLED=0 go build -o kpass ${flags}

build_windows_amd64:
	go clean; rm -rf pkg kpass; GOARCH=amd64 GOOS=windows CGO_ENABLED=0 go build -o kpass ${flags}

build_windows_arm64:
	go clean; rm -rf pkg kpass; GOARCH=arm64 GOOS=windows CGO_ENABLED=0 go build -o kpass ${flags}

install:
	go install

clean:
	go clean; rm -rf pkg

test : test1

test1:
	go test -v -bench=.
