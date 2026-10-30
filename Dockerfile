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
# The server listens on every interface at 8829 for the platform's workers, and its egress proxy at 3128 for the
# scanners it runs. The SDK is pinned to the band global.json asks for: on the floating sdk:10.0 a newer feature
# band would one day refuse the build. The server is framework-dependent: published without Native AOT onto the
# ASP.NET runtime.
ARG VERSION=0.0.0-local

FROM mcr.microsoft.com/dotnet/sdk:10.0.302 AS build
ARG VERSION
WORKDIR /source
COPY . .
RUN dotnet publish src/Snail.MCP.Security.csproj -c Release -o /app -p:PublishAot=false -p:UseAppHost=false -p:Version=$VERSION

FROM mcr.microsoft.com/dotnet/aspnet:10.0
ARG VERSION
LABEL org.opencontainers.image.version=$VERSION
WORKDIR /app
COPY --from=build /app .
# The scan history lives in the server's data folder, a volume on the stand: made here so the volume takes the app user's ownership.
RUN mkdir -p /home/app/.s3l-mcp-security && chown -R app:app /home/app
ENV ASPNETCORE_HTTP_PORTS=8829 \
    Logging__LogLevel__Default=Information \
    Logging__LogLevel__Microsoft.AspNetCore=Warning
EXPOSE 8829 3128
USER app

ENTRYPOINT ["dotnet", "/app/Snail.MCP.Security.dll"]
