# VulnTrack

VulnTrack is a vulnerability tracker. It collects security findings from internal reports, external reporters and scanners, and helps a team triage, assign and fix them within an agreed time. It is my exam project in Secure Software Development at EASV, fall 2026.

The backend is ASP.NET Core 10 and the frontend is React with TypeScript. Login goes through Keycloak with OpenID Connect. The backend is the OIDC client, so tokens never reach the browser. The browser only holds an encrypted session cookie that JavaScript can't read.

## Running it

You need Docker. Copy the example environment file and pick your own secrets in it.

```sh
cp .env.example .env
docker compose up --build
```

All dependencies are installed and built inside containers, so nothing from npm or NuGet runs on your machine. When it is up, open <http://localhost:8000>. The Keycloak admin console is at <http://localhost:8080> and uses the admin login from `.env`.

Both ports are only bound to localhost. The login redirects expect `localhost`, so use that and not `127.0.0.1`.

## Test users

There is one test user per role. They are created by the realm import in `keycloak/realm/vulntrack.json`.

| Username | Password | Role |
|---|---|---|
| analyst | analyst-test-pw | Analyst |
| developer | developer-test-pw | Developer |
| pm | pm-test-password | PM |
| auditor | auditor-test-pw | Auditor |

## Development

The repository has a dev container, so it can be opened in GitHub Codespaces with Docker, .NET and Node ready. Open the codespace from VS Code on your desktop rather than in the browser. Then the ports are forwarded to `localhost`, which the login redirects depend on.

To work on the code with hot reload, start Keycloak on its own and run the backend and frontend directly.

```sh
docker compose up keycloak
dotnet user-secrets --project backend/VulnTrack.Api set Oidc:ClientSecret <OIDC_CLIENT_SECRET from .env>
dotnet run --project backend/VulnTrack.Api
cd frontend && npm install && npm run dev
```

The app is then on <http://localhost:5173>. Vite forwards API and login requests to the backend, so the browser still sees one origin.

The backend tests run with `dotnet test --solution backend/VulnTrack.slnx`. CI runs them on every pull request together with formatting, linting, a dependency audit of both NuGet and npm packages, and a build of the container image.
