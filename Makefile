.PHONY: test-gen-cert


test-gen-cert:
	pipx install --force git+https://github.com/BeryJu/crtls.git
	crtls ca generate --out-dir tests/certs/
	crtls cert generate client --out-dir tests/certs/
	crtls cert generate server --out-dir tests/certs/
