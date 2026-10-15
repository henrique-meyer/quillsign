# QuillSign

An open-source e-signature app being built around sequential signing, no accounts, and no subscriptions.

The project is in early development. The current .NET 10 Razor Pages app provides the demo startup page and a database-independent `/health` endpoint. Document upload and signing are not enabled yet.

Run locally with the .NET 10 SDK:

```sh
dotnet run --project src/QuillSign/QuillSign.csproj --urls http://localhost:5080
```

Or build and run the container:

```sh
docker build -t quillsign .
docker run --rm -p 8080:8080 quillsign
```

See [the implementation plan](docs/plan.md), [Azure infrastructure](infra/README.md), [hosting setup](infra/HOSTING.md), and [SES setup](infra/aws/SES.md). Deployment names, domains, identifiers, and credentials belong in ignored configuration. PR CI requires no cloud secrets.

Software is provided as-is. Operators are responsible for checking whether electronic signatures are suitable for their use case and jurisdiction. Public demo data will be purged periodically.
Open-source e-signature app with no accounts and no subscriptions. Verify your email with a magic link, upload a document, add signers who sign in order, and get a sealed, audit-trailed PDF that follows the US e-signature laws (ESIGN and UETA).
