MAKEFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
ROOT_DIR := $(dir $(MAKEFILE_PATH))
BUILD_VERSION=dev-snapshot

all:
	mkdir -p bin
	go build -ldflags="-X main.BuildVersion=$(BUILD_VERSION)" -o bin/mkat ./cmd/managed-kubernetes-auditing-toolkit/main.go

test:
	go test ./... -v

thirdparty-licenses:
	go get github.com/google/go-licenses
	go install github.com/google/go-licenses
	go-licenses csv github.com/datadog/managed-kubernetes-auditing-toolkit/cmd/managed-kubernetes-auditing-toolkit | sort > $(ROOT_DIR)/LICENSE-3rdparty.csv

