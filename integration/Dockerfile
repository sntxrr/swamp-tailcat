# One image for every role in the integration harness: tailcat server, the
# DERP relay, key generation, and the Deno probe runner.
#
# tailcat and derper are built from source at pinned versions. derper comes
# from the same tailscale.com version tailcat's go.mod requires, so client
# and relay speak the same DERP protocol.

ARG TAILCAT_REF=b4dc28e
ARG DENO_VERSION=2.9.6

FROM golang:1.27 AS build
ARG TAILCAT_REF
RUN git clone https://github.com/tailscale/tailcat.git /src \
 && git -C /src checkout "${TAILCAT_REF}"
WORKDIR /src
RUN CGO_ENABLED=0 go build -o /out/tailcat ./cmd/tailcat \
 && TS_VERSION="$(go list -m -f '{{.Version}}' tailscale.com)" \
 && CGO_ENABLED=0 GOBIN=/out go install "tailscale.com/cmd/derper@${TS_VERSION}"

FROM denoland/deno:bin-${DENO_VERSION} AS deno

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates openssh-client openssl procps \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/tailcat /out/derper /usr/local/bin/
COPY --from=deno /deno /usr/local/bin/deno

# The probe runs on internal-only networks with no route to npm or jsr, so
# every dependency is cached at build time.
WORKDIR /app
COPY extensions/models/tailcat-probe/tailcat_probe.ts extensions/models/tailcat-probe/
COPY integration/ integration/
RUN deno cache extensions/models/tailcat-probe/tailcat_probe.ts \
      integration/probe_test.ts
