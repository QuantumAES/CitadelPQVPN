# Runtime-образ для PQ-туннеля. Бинарь citadel-m1 собирается на хосте и копируется внутрь
# (aws-lc слинкован статически; нужен только glibc — debian trixie = glibc 2.41, как на хосте).
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iptables iputils-ping curl ca-certificates dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY citadel-m1 citadel-token /usr/local/bin/
COPY entrypoint-exit.sh entrypoint-client.sh entrypoint-issuer.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/citadel-m1 /usr/local/bin/citadel-token \
             /usr/local/bin/entrypoint-exit.sh \
             /usr/local/bin/entrypoint-client.sh \
             /usr/local/bin/entrypoint-issuer.sh
