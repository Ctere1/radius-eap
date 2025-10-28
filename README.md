[![Go Report Card](https://goreportcard.com/badge/github.com/Ctere1/radius-eap)](https://goreportcard.com/report/github.com/Ctere1/radius-eap)
[![pkg.go.dev](https://pkg.go.dev/badge/github.com/Ctere1/radius-eap)](https://pkg.go.dev/github.com/Ctere1/radius-eap)

# About

A minimal and pragmatic implementation of common **EAP** methods for **RADIUS**, designed for experimentation, learning, and integration.

- Forked from [github.com/BeryJu/radius-eap](https://github.com/BeryJu/radius-eap)
- In-depth write-up: [Implementing EAP](https://beryju.io/blog/2025-05-implementing-eap/) by **BeryJu**

> 🧪 Currently exploring MFA (Multi-Factor Authentication) support for Wi-Fi networks using EAP methods.  
> If you have experience or insights in this area, your input would be greatly appreciated!

Thanks to **BeryJu** for the original implementation and the excellent blog post.

# EAP protocol implementation

Install `eapol_test` (`sudo apt install eapoltest`)

Both PEAP and EAP-TLS require a minimal PKI setup. A CA, a certificate for the server and for EAP-TLS a client certificate need to be provided.

Save either of the config files below and run eapoltest like so:

```
# peap.conf is the config file under the PEAP testing section
# foo is the shared RADIUS secret
# 1.2.3.4 is the IP of the RADIUS server
eapol_test -c peap.conf -s foo -a 1.2.3.4
```

### PEAP testing

```
network={
    ssid="DoesNotMatterForThisTest"
    key_mgmt=WPA-EAP
    eap=PEAP
    identity="foo"
    password="bar"
    ca_cert="ca.pem"
    phase2="auth=MSCHAPV2"
}
```

### EAP-TLS testing

```
network={
    ssid="DoesNotMatterForThisTest"
    key_mgmt=WPA-EAP
    eap=TLS
    identity="foo"
    ca_cert="ca.pem"
    client_cert="cert_client.pem"
    private_key="cert_client.key"
    eapol_flags=3
    eap_workaround=0
}
```
