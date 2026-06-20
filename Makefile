SHELL := /bin/bash
.ONESHELL:
.SHELLFLAGS += -x -e -o pipefail

PWD = $(shell pwd)
CERT_DIR = ${PWD}/tests/certs/

lint:
	golangci-lint run -v --timeout 5000s

test: test-cert-gen
	go test \
		-timeout 60s \
		-p 1 \
		-count=1 \
		-failfast \
		-shuffle=on \
		-coverprofile=${PWD}/coverage.txt \
		-covermode=atomic \
		-coverpkg=../... \
		-v \
		$(shell go list ./...)
	go tool cover \
		-html ${PWD}/coverage.txt \
		-o ${PWD}/coverage.html

# test-race runs the suite under the data-race detector. It is kept separate from
# the coverage run above because -race changes runtime behaviour and timing.
test-race: test-cert-gen
	go test \
		-race \
		-timeout 120s \
		-p 1 \
		-count=1 \
		-shuffle=on \
		$(shell go list ./...)

test-cert-clean:
	rm -rf ${CERT_DIR}

test-cert-gen:
	crtls -o ${CERT_DIR} ca generate
	crtls -o ${CERT_DIR} cert generate client
	crtls -o ${CERT_DIR} cert generate server
