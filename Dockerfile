FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY src/QuillSign/QuillSign.csproj src/QuillSign/
RUN dotnet restore src/QuillSign/QuillSign.csproj
COPY src/ src/
COPY assets/ assets/
RUN dotnet publish src/QuillSign/QuillSign.csproj -c Release --no-restore -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later"
WORKDIR /app
COPY LICENSE ./LICENSE
COPY --from=build /app .
USER $APP_UID
EXPOSE 8080
ENTRYPOINT ["dotnet", "QuillSign.dll"]
