# VulnTrack

A vulnerability tracker that takes in security findings from internal reports, external reporters and scanners, and tracks them through triage, assignment and remediation.

## Setup

Requires Docker.

```bash
git clone https://github.com/RuneKrogh/vulntrack.git
cd vulntrack
cp .env.example .env   # then set your own passwords, client secret and encryption key
docker compose up --build
```

Open <http://localhost:8000>. Use `localhost` and not `127.0.0.1`, since the login redirects expect it. The Keycloak admin console is at <http://localhost:8080>, with the admin login from `.env`. To start over with an empty database, run `docker compose down -v` before starting it again.

Dependencies are installed and built inside containers, so nothing from npm or NuGet runs on your machine.

The descriptions and reporter emails of findings are encrypted with `ENCRYPTION_KEY`. It must be 32 random bytes in base64, which `openssl rand -base64 32` gives you. The app doesn't start without a valid key, and findings can't be read without the key they were saved with.

## Test users

| Username | Password | Role | Can |
|---|---|---|---|
| analyst | analyst-test-pw | Analyst | See all findings, create, edit and assign them, and set any status |
| developer | developer-test-pw | Developer | See only the findings assigned to them, set them to In progress or Remediated, and edit them except for the severity |
| pm | pm-test-password | PM | The same as an analyst |
| auditor | auditor-test-pw | Auditor | See all findings and the dashboard, but not change anything |

Only analysts and PMs see the reporter's email on findings from the public form.

## Reporting a vulnerability

External reporters use the form at <http://localhost:8000/report>, which needs no login. Each IP address can send 5 reports per 10 minutes, so the form can't be used to flood the database. Restarting the app with `docker compose restart app` resets the limit.

## Tests

The tests need the .NET 10 SDK and a running Docker, since they start a PostgreSQL container.

```bash
dotnet test --solution backend/VulnTrack.slnx
```
