# snow-resorts-auth-service

Authentication microservice for Snow Resorts: login, RS256 JWT access tokens, single-use
refresh-token rotation with reuse detection, and the `/.well-known/jwks.json` endpoint other
services use to validate tokens.

- **Port:** 8081
- **DB schema:** `auth`
- **Shared libs:** `com.snowresorts:security-lib` (from GitHub Packages)

## Build & test

Requires a `github` server credential in `~/.m2/settings.xml` (see
[`settings.xml.example`](settings.xml.example)) to resolve the shared libraries.

```bash
./mvnw clean verify
./mvnw spring-boot:run    # runs with the `local` profile against the local Docker stack
```

Bring up Postgres/Redis/MinIO/Mailpit from the [`snow-resorts-infra`](https://github.com/yurileao/snow-resorts-infra) repo (`make dev`).

## Password reset (local dev)

With the `local` profile, outbound mail goes to **Mailpit** (`localhost:1025`; UI at `:8025`). Reset e-mails are **multipart HTML** with a clickable link — they are **not** delivered to real inboxes.

| Setting | Local default | Purpose |
|---------|---------------|---------|
| `spring.mail.host` | `localhost` (in `application-local.yml`) | SMTP → Mailpit |
| `snow.auth.password-reset-base-url` | `http://localhost:8080/reset-password` | Link embedded in the e-mail |
| `PASSWORD_RESET_BASE_URL` | (env / `.env.local`) | `http://<LAN_IP>:8080/reset-password` on a physical phone — see `.env.local.example` |

The nginx gateway serves [`reset-password.html`](../snow-resorts-infra/docker/nginx/static/reset-password.html) at `/reset-password`, which redirects to `snowresorts://reset-password?token=…` so the mobile app opens the reset screen.

If `spring.mail.host` is unset, tokens are **logged** instead of e-mailed (`LoggingPasswordResetNotifier`).

Full walkthrough: [LOCAL_DEV.md § Recuperar senha](../LOCAL_DEV.md#recuperar-senha-mailpit--redirect) in the workspace root.

## CI/CD

[`.github/workflows/ci-cd.yml`](.github/workflows/ci-cd.yml) builds + tests on every PR, and on
push to `staging`/`main` builds the Docker image, pushes to ECR and triggers a rolling ECS
deployment. Requires repo secrets: `AWS_DEPLOY_ROLE_ARN` (the `GITHUB_TOKEN` is built-in).
