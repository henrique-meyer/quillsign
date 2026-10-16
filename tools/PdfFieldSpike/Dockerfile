FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY tools/PdfFieldSpike/ tools/PdfFieldSpike/
COPY src/QuillSign/Documents/PdfValidation.cs src/QuillSign/Documents/
COPY src/QuillSign/Signing/FieldGeometry.cs src/QuillSign/Signing/
COPY src/QuillSign/wwwroot/vendor/pdfjs/standard_fonts/LiberationSans-Regular.ttf src/QuillSign/wwwroot/vendor/pdfjs/standard_fonts/
COPY src/QuillSign/wwwroot/vendor/pdfjs/standard_fonts/LICENSE_LIBERATION src/QuillSign/wwwroot/vendor/pdfjs/standard_fonts/
RUN dotnet publish tools/PdfFieldSpike/PdfFieldSpike.csproj -c Release -p:RestoreLockedMode=true -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app .
COPY LICENSE ./LICENSE
USER $APP_UID
ENTRYPOINT ["dotnet", "PdfFieldSpike.dll"]
