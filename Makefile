SHELL := /bin/bash
.ONESHELL:
.SHELLFLAGS += -x -e -o pipefail
.PHONY: test-gen-cert lint test

PWD = $(shell pwd)
CERT_DIR = tests/certs/

lint:
	golangci-lint run -v --timeout 5000s

test: test-gen-cert
	go test \
		-timeout 30s \
		-p 1 \
		-count=1 \
		-failfast \
		-shuffle=on \
		-coverprofile=${PWD}/coverage.txt \
		-covermode=atomic \
		-v \
		beryju.io/radius-eap
	go tool cover \
		-html ${PWD}/coverage.txt \
		-o ${PWD}/coverage.html

test-gen-cert:
	crtls -o ${CERT_DIR} ca generate
	crtls -o ${CERT_DIR} cert generate client
	crtls -o ${CERT_DIR} cert generate server
