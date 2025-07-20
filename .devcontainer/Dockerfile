FROM mcr.microsoft.com/devcontainers/go:1-1.24-bookworm

ARG TARGETARCH

RUN sudo apt-get update && \
    sudo apt-get install -y eapoltest wget && \
    wget -O /usr/bin/crtls https://github.com/BeryJu/crtls/releases/download/v0.1.3/crtls_linux_${TARGETARCH} && \
    chmod +x /usr/bin/crtls
