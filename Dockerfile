FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY src/QuillSign/QuillSign.csproj src/QuillSign/
RUN dotnet restore src/QuillSign/QuillSign.csproj
COPY src/ src/
COPY assets/ assets/
COPY licenses/ licenses/
COPY THIRD-PARTY-NOTICES.txt ./THIRD-PARTY-NOTICES.txt
RUN dotnet publish src/QuillSign/QuillSign.csproj -c Release --no-restore -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later"
WORKDIR /app
COPY LICENSE ./LICENSE
COPY --from=build /app .
USER $APP_UID
EXPOSE 8080
ENTRYPOINT ["dotnet", "QuillSign.dll"]

# Compose uses this target for local HTTP health checks and service diagnostics.
FROM runtime AS development
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
USER $APP_UID

# Keep the default production image independent of development-only tools.
FROM runtime AS final
