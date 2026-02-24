FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o nightfall-api ./cmd/api/main.go

# Final stage
FROM alpine:latest

# Install base deps
RUN apk --no-cache add \
    ca-certificates \
    bash \
    curl \
    wget \
    unzip \
    openssl \
    python3 \
    python3-dev \
    py3-pip \
    libffi-dev \
    ruby \
    git \
    gcc \
    musl-dev \
    openssl-dev \
    make \
    perl \
    libpcap-dev

# ── nmap ──
RUN apk --no-cache add nmap nmap-scripts \
    && nmap --version | head -1 && echo "[OK] nmap installed"

# ── nikto ──
RUN apk --no-cache add nikto \
    || (git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /usr/local/bin/nikto) \
    && echo "[OK] nikto installed"

# ── nuclei ──
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then NUCLEI_ARCH="amd64"; elif [ "$ARCH" = "aarch64" ]; then NUCLEI_ARCH="arm64"; else NUCLEI_ARCH="amd64"; fi && \
    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_${NUCLEI_ARCH}.zip" -O /tmp/nuclei.zip && \
    unzip -o /tmp/nuclei.zip -d /usr/local/bin/ && \
    rm -f /tmp/nuclei.zip && \
    chmod +x /usr/local/bin/nuclei && \
    nuclei -version 2>&1 | head -1 && echo "[OK] nuclei installed"

# ── wapiti ──
RUN PIP_DEFAULT_TIMEOUT=30 pip3 install --break-system-packages wapiti3 \
    && wapiti --version 2>&1 | head -1 && echo "[OK] wapiti installed" \
    || echo "[WARN] wapiti install failed — optional tool"

# ── fierce ──
RUN PIP_DEFAULT_TIMEOUT=30 pip3 install --break-system-packages fierce \
    && fierce --version 2>&1 | head -1 && echo "[OK] fierce installed" \
    || echo "[WARN] fierce install failed — optional tool"

# ── sslscan (build from source) ──
RUN git clone --depth 1 https://github.com/rbsec/sslscan.git /tmp/sslscan \
    && cd /tmp/sslscan \
    && make static \
    && cp sslscan /usr/local/bin/ \
    && cd / && rm -rf /tmp/sslscan \
    && sslscan --version 2>&1 | head -1 && echo "[OK] sslscan installed" \
    || echo "[WARN] sslscan build failed — optional tool"

# ── whatweb ──
RUN wget -q "https://github.com/urbanadventurer/WhatWeb/archive/refs/heads/master.tar.gz" -O /tmp/whatweb.tar.gz \
    && tar xzf /tmp/whatweb.tar.gz -C /opt/ \
    && ln -sf /opt/WhatWeb-master/whatweb /usr/local/bin/whatweb \
    && rm /tmp/whatweb.tar.gz \
    && chmod +x /usr/local/bin/whatweb \
    && echo "[OK] whatweb installed"

# ── skipfish (build from source) ──
RUN apk --no-cache add pcre-dev \
    && git clone --depth 1 https://github.com/spinkham/skipfish.git /tmp/skipfish \
    && cd /tmp/skipfish \
    && make \
    && cp skipfish /usr/local/bin/ \
    && cp -r dictionaries /usr/local/share/skipfish-dictionaries \
    && cd / && rm -rf /tmp/skipfish \
    && echo "[OK] skipfish installed" \
    || echo "[WARN] skipfish build failed — optional tool"

# ── sqlmap ──
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && ln -sf /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap \
    && chmod +x /usr/local/bin/sqlmap \
    && echo "[OK] sqlmap installed" \
    || echo "[WARN] sqlmap install failed — optional tool"

# ── ffuf ──
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then FFUF_ARCH="amd64"; elif [ "$ARCH" = "aarch64" ]; then FFUF_ARCH="arm64"; else FFUF_ARCH="amd64"; fi && \
    wget -q "https://github.com/ffuf/ffuf/releases/latest/download/ffuf_2.1.0_linux_${FFUF_ARCH}.tar.gz" -O /tmp/ffuf.tgz \
    && tar xzf /tmp/ffuf.tgz -C /tmp \
    && cp /tmp/ffuf /usr/local/bin/ffuf \
    && chmod +x /usr/local/bin/ffuf \
    && rm -f /tmp/ffuf.tgz /tmp/ffuf \
    && echo "[OK] ffuf installed" \
    || echo "[WARN] ffuf install failed — optional tool"

# ── subfinder ──
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then SUBFINDER_ARCH="amd64"; elif [ "$ARCH" = "aarch64" ]; then SUBFINDER_ARCH="arm64"; else SUBFINDER_ARCH="amd64"; fi && \
    wget -q "https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_${SUBFINDER_ARCH}.zip" -O /tmp/subfinder.zip \
    && unzip -o /tmp/subfinder.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/subfinder \
    && rm -f /tmp/subfinder.zip \
    && echo "[OK] subfinder installed" \
    || echo "[WARN] subfinder install failed — optional tool"

# ── httpx ──
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then HTTPX_ARCH="amd64"; elif [ "$ARCH" = "aarch64" ]; then HTTPX_ARCH="arm64"; else HTTPX_ARCH="amd64"; fi && \
    wget -q "https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_linux_${HTTPX_ARCH}.zip" -O /tmp/httpx.zip \
    && unzip -o /tmp/httpx.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/httpx \
    && rm -f /tmp/httpx.zip \
    && echo "[OK] httpx installed" \
    || echo "[WARN] httpx install failed — optional tool"

# ── gobuster ──
RUN apk --no-cache add gobuster \
    && echo "[OK] gobuster installed" \
    || echo "[WARN] gobuster install failed — optional tool"

# ── dalfox ──
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then DALFOX_ARCH="amd64"; elif [ "$ARCH" = "aarch64" ]; then DALFOX_ARCH="arm64"; else DALFOX_ARCH="amd64"; fi && \
    wget -q "https://github.com/hahwul/dalfox/releases/latest/download/dalfox_${DALFOX_ARCH}.tar.gz" -O /tmp/dalfox.tgz \
    && tar xzf /tmp/dalfox.tgz -C /tmp \
    && cp /tmp/dalfox /usr/local/bin/dalfox \
    && chmod +x /usr/local/bin/dalfox \
    && rm -f /tmp/dalfox.tgz /tmp/dalfox \
    && echo "[OK] dalfox installed" \
    || echo "[WARN] dalfox install failed — optional tool"

# ── testssl.sh ──
RUN git clone --depth 1 https://github.com/testssl/testssl.sh.git /opt/testssl.sh \
    && ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh \
    && chmod +x /usr/local/bin/testssl.sh \
    && echo "[OK] testssl.sh installed" \
    || echo "[WARN] testssl.sh install failed — optional tool"

# ── kiterunner ──
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then KR_ARCH="amd64"; elif [ "$ARCH" = "aarch64" ]; then KR_ARCH="arm64"; else KR_ARCH="amd64"; fi && \
    wget -q "https://github.com/assetnote/kiterunner/releases/latest/download/kiterunner_linux_${KR_ARCH}.tar.gz" -O /tmp/kr.tgz \
    && tar xzf /tmp/kr.tgz -C /tmp \
    && cp /tmp/kr /usr/local/bin/kr \
    && chmod +x /usr/local/bin/kr \
    && rm -f /tmp/kr.tgz /tmp/kr \
    && echo "[OK] kiterunner installed" \
    || echo "[WARN] kiterunner install failed — optional tool"

# ── amass ──
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then A=amd64; elif [ "$ARCH" = "aarch64" ]; then A=arm64; else A=amd64; fi && \
    URL=$(wget -qO- https://api.github.com/repos/owasp-amass/amass/releases/latest | grep -o "https://[^\"]*linux_${A}\\.zip" | head -n1) && \
    if [ -n "$URL" ]; then wget -q "$URL" -O /tmp/amass.zip && unzip -o /tmp/amass.zip -d /tmp/amass >/dev/null && cp /tmp/amass/*/amass /usr/local/bin/amass && chmod +x /usr/local/bin/amass && echo "[OK] amass installed"; else echo "[WARN] amass asset not found"; fi \
    || echo "[WARN] amass install failed — optional tool"

# ── uncover ──
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then A=amd64; elif [ "$ARCH" = "aarch64" ]; then A=arm64; else A=amd64; fi && \
    URL=$(wget -qO- https://api.github.com/repos/projectdiscovery/uncover/releases/latest | grep -o "https://[^\"]*linux_${A}\\.zip" | head -n1) && \
    if [ -n "$URL" ]; then wget -q "$URL" -O /tmp/uncover.zip && unzip -o /tmp/uncover.zip -d /usr/local/bin/ >/dev/null && chmod +x /usr/local/bin/uncover && echo "[OK] uncover installed"; else echo "[WARN] uncover asset not found"; fi \
    || echo "[WARN] uncover install failed — optional tool"

# ── gau ──
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then A=amd64; elif [ "$ARCH" = "aarch64" ]; then A=arm64; else A=amd64; fi && \
    URL=$(wget -qO- https://api.github.com/repos/lc/gau/releases/latest | grep -o "https://[^\"]*linux_${A}\\.tar\\.gz" | head -n1) && \
    if [ -n "$URL" ]; then wget -q "$URL" -O /tmp/gau.tgz && tar xzf /tmp/gau.tgz -C /tmp && cp /tmp/gau /usr/local/bin/gau && chmod +x /usr/local/bin/gau && echo "[OK] gau installed"; else echo "[WARN] gau asset not found"; fi \
    || echo "[WARN] gau install failed — optional tool"

# ── dnsx ──
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then A=amd64; elif [ "$ARCH" = "aarch64" ]; then A=arm64; else A=amd64; fi && \
    URL=$(wget -qO- https://api.github.com/repos/projectdiscovery/dnsx/releases/latest | grep -o "https://[^\"]*linux_${A}\\.zip" | head -n1) && \
    if [ -n "$URL" ]; then wget -q "$URL" -O /tmp/dnsx.zip && unzip -o /tmp/dnsx.zip -d /usr/local/bin/ >/dev/null && chmod +x /usr/local/bin/dnsx && echo "[OK] dnsx installed"; else echo "[WARN] dnsx asset not found"; fi \
    || echo "[WARN] dnsx install failed — optional tool"

# ── alterx ──
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then A=amd64; elif [ "$ARCH" = "aarch64" ]; then A=arm64; else A=amd64; fi && \
    URL=$(wget -qO- https://api.github.com/repos/projectdiscovery/alterx/releases/latest | grep -o "https://[^\"]*linux_${A}\\.zip" | head -n1) && \
    if [ -n "$URL" ]; then wget -q "$URL" -O /tmp/alterx.zip && unzip -o /tmp/alterx.zip -d /usr/local/bin/ >/dev/null && chmod +x /usr/local/bin/alterx && echo "[OK] alterx installed"; else echo "[WARN] alterx asset not found"; fi \
    || echo "[WARN] alterx install failed — optional tool"

# ── crtsh helper ──
RUN printf '%s\n' \
    '#!/bin/sh' \
    'set -eu' \
    'DOMAIN="${1:-}"' \
    'if [ -z "$DOMAIN" ]; then' \
    '  echo "usage: crtsh <domain>"' \
    '  exit 1' \
    'fi' \
    'curl -fsSL "https://crt.sh/?q=%25.${DOMAIN}&output=json" | tr "," "\n" | sed -n "s/.*\"name_value\":\"\\([^\"]*\\)\".*/\\1/p" | tr "\\\\n" "\n" | sed "s/\\r//g" | sed "s/^\\*\\.//" | awk "NF" | sort -u' \
    > /usr/local/bin/crtsh \
    && chmod +x /usr/local/bin/crtsh

# ── shared wordlists ──
RUN mkdir -p /usr/local/share/nightfall/wordlists \
    && printf "/admin\n/login\n/dashboard\n/api\n/graphql\n/.env\n/robots.txt\n/sitemap.xml\n" > /usr/local/share/nightfall/wordlists/common.txt \
    && printf "users\naccounts\nauth\ntoken\nv1\nv2\nhealth\nstatus\n" > /usr/local/share/nightfall/wordlists/api.txt \
    && printf "admin\ninternal\nstaging\ndev\nqa\napi\n" > /usr/local/share/nightfall/wordlists/vhosts.txt \
    && echo "[OK] nightfall wordlists prepared"

# Cleanup build deps (keep what tools need at runtime)
RUN apk del gcc musl-dev openssl-dev make git 2>/dev/null; true

WORKDIR /root/

# Copy binary
COPY --from=builder /app/nightfall-api .

# Copy internal directory (for passive scanner modules)
COPY --from=builder /app/internal ./internal

EXPOSE 8080

CMD ["./nightfall-api"]
