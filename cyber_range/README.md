# RedAgent Cyber Range

This folder contains a Docker-based local training playground for safe assessment workflows.
It is designed for rehearsing discovery, triage, validation, and reporting against controlled targets only.

## Services

- `range-web` on `http://localhost:8080` - landing page with a training briefing and service metadata.
- `range-login` on `http://localhost:8081` - login workflow with a simple admin view for local credential validation.
- `range-api` on `http://localhost:8082` - token-gated JSON API with health and scenario endpoints.

## Build and Run

From this folder:

```bash
docker compose up --build
```

Stop the range with:

```bash
docker compose down
```

## Scenario Files

- `scenarios/basic_ctf.yaml` - baseline three-service scenario.
- `scenario_assets/` - supporting manifests and notes for future scenarios.

## Safety Notes

- Use only on the local Docker network.
- Do not point the range at real infrastructure.
- The services are intentionally simple so they can be extended with new training tasks later.
