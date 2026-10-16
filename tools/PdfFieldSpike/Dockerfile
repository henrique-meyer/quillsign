FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY tools/PdfFieldSpike/ tools/PdfFieldSpike/
COPY licenses/PdfPig-LICENSE.txt licenses/PdfPig-LICENSE.txt
COPY licenses/PdfPig-NOTICES.txt licenses/PdfPig-NOTICES.txt
COPY licenses/PDFsharp-MIT.txt licenses/PDFsharp-MIT.txt
COPY src/QuillSign/Documents/PdfValidation.cs src/QuillSign/Documents/
COPY src/QuillSign/Documents/EmbeddedPdfFont.cs src/QuillSign/Documents/
COPY src/QuillSign/Documents/SenderPdfRenderer.cs src/QuillSign/Documents/
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
