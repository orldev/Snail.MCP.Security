# The server as a container image, built by .github/workflows/image.yml through the shared mcp-image.yml and pushed
# from a version tag as ghcr.io/<owner>/s3l-security-mcp.
#
#   docker build --build-context feed=../../nuget -t snail/s3l-security-mcp .
#
# Snail.Sdk is not on nuget.org yet: the build takes the author's local feed as a build context named feed, and restore
# finds it under the name nuget.config maps Snail.Sdk to. The Nomad client travels in packages/.
#
# The server listens on every interface at 8829 for the platform's workers, and its egress proxy at 3128 for the
# scanners it runs. The SDK is pinned to the band global.json asks for: on the floating sdk:10.0 a newer feature
# band would one day refuse the build. The server is framework-dependent: published without Native AOT onto the
# ASP.NET runtime.
FROM mcr.microsoft.com/dotnet/sdk:10.0.302 AS build
WORKDIR /source
COPY --from=feed . /feed
RUN dotnet nuget add source /feed --name LocalPackages
COPY . .
RUN dotnet publish src/Snail.MCP.Security.csproj -c Release -o /app -p:PublishAot=false -p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app .
ENV ASPNETCORE_HTTP_PORTS=8829 \
    Logging__LogLevel__Default=Information \
    Logging__LogLevel__Microsoft.AspNetCore=Warning
EXPOSE 8829 3128
USER app

ENTRYPOINT ["dotnet", "/app/Snail.MCP.Security.dll"]
