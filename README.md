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

Bring up Postgres/Redis/MinIO from the [`snow-resorts-infra`](https://github.com/yurileao/snow-resorts-infra) repo (`make dev`).

## CI/CD

[`.github/workflows/ci-cd.yml`](.github/workflows/ci-cd.yml) builds + tests on every PR, and on
push to `staging`/`main` builds the Docker image, pushes to ECR and triggers a rolling ECS
deployment. Requires repo secrets: `AWS_DEPLOY_ROLE_ARN` (the `GITHUB_TOKEN` is built-in).
