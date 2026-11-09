# The server as a container image, built by .github/workflows/image.yml through the shared mcp-image.yml and pushed
# from a version tag as ghcr.io/<owner>/s3l-security-mcp.
#
#   docker build -t s3l-security-mcp:local .
#
# A build without a tag would be called latest, the name a deployment pulls, and nothing would tell it from a release.
# So a local build is tagged local, and the version built in says what it is: VERSION is 0.0.0-local unless the build
# passes one (the shared workflow passes the release's version from its tag, and 0.0.0-<branch>.<commit> from a
# branch), the server reports it in initialize and the image carries it as org.opencontainers.image.version. A local
# build that should name its commit passes it, since the image sees no git:
#
#   docker build -t s3l-security-mcp:local --build-arg VERSION=0.0.0-local.$(git rev-parse --short HEAD) .
#
# The server listens on every interface at the port of SNAIL_MCP_SECURITY_URL (8829) for the platform's workers
# (McpEndpoint, which DOTNET_RUNNING_IN_CONTAINER opens on every interface: a browser's request is still refused), and
# its egress proxy at 3128 for the scanners it runs. The SDK is pinned to the band global.json asks for: on the floating
# sdk:10.0 a newer feature band would one day refuse the build.
#
# The server is native: the SDK compiles it ahead of time (Native AOT), which needs clang and zlib in the build stage,
# and the image runs the one executable on runtime-deps, with no .NET runtime in it. It is compiled for the platform
# the image is built for (TARGETARCH, which buildx sets): ahead-of-time compilation does not cross architectures in the
# SDK image, so linux-x64 alone would not build on an arm64 machine, such as a Mac running the stand.
ARG VERSION=0.0.0-local

FROM mcr.microsoft.com/dotnet/sdk:10.0.302 AS build
ARG VERSION
ARG TARGETARCH
RUN apt-get update \
    && apt-get install --yes --no-install-recommends clang zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /source
COPY . .
RUN case "$TARGETARCH" in amd64|"") rid=linux-x64 ;; *) rid="linux-$TARGETARCH" ;; esac \
    && dotnet publish src/Snail.MCP.Security.csproj -c Release -r "$rid" -o /app -p:Version=$VERSION

FROM mcr.microsoft.com/dotnet/runtime-deps:10.0
ARG VERSION
LABEL org.opencontainers.image.version=$VERSION
WORKDIR /app
COPY --from=build /app .
# The scan history lives in the server's data folder, a volume on the stand: made here so the volume takes the app user's ownership.
RUN mkdir -p /home/app/.s3l-mcp-security && chown -R app:app /home/app
EXPOSE 8829 3128
USER app

ENTRYPOINT ["/app/Snail.MCP.Security"]
