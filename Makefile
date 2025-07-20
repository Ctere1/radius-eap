SHELL := /bin/bash
.ONESHELL:
.SHELLFLAGS += -x -e -o pipefail
.PHONY: test-gen-cert lint test

CERT_DIR = tests/certs/

lint:
	golangci-lint run -v --timeout 5000s

test: test-gen-cert
	go test \
		-timeout 30s \
		-count=1 \
		-failfast \
		-shuffle=on \
		-v \
		beryju.io/radius-eap/tests

test-gen-cert:
	pipx install --force git+https://github.com/BeryJu/crtls.git
	mkdir -p ${CERT_DIR}
	crtls ca generate --out-dir ${CERT_DIR}
	crtls cert generate client --out-dir ${CERT_DIR}
	crtls cert generate server --out-dir ${CERT_DIR}
