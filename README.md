# VulnTrack

A vulnerability tracker that takes in security findings from internal reports, external reporters and scanners, and tracks them through triage, assignment and remediation.

## Setup

Requires Docker.

```bash
git clone https://github.com/RuneKrogh/vulntrack.git
cd vulntrack
cp .env.example .env   # then set your own passwords and client secret
docker compose up --build
```

Open <http://localhost:8000>. Use `localhost` and not `127.0.0.1`, since the login redirects expect it. The Keycloak admin console is at <http://localhost:8080>, with the admin login from `.env`.

Dependencies are installed and built inside containers, so nothing from npm or NuGet runs on your machine.

## Test users

| Username | Password | Role |
|---|---|---|
| analyst | analyst-test-pw | Analyst |
| developer | developer-test-pw | Developer |
| pm | pm-test-password | PM |
| auditor | auditor-test-pw | Auditor |

## Tests

```bash
dotnet test --solution backend/VulnTrack.slnx
```
