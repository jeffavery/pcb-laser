# PCB Laser Artwork

A beginner-focused electronics project builder for home-etched, single-sided PCBs. It turns a plain-language project idea into a checked KiCad board, mirrored laser artwork, a parts list, build guidance, and an optional printable enclosure.

It also converts an uploaded KiCad `.kicad_pcb` file (or a ZIP containing one board) into a laser-ready SVG for a paint-removal and etching workflow.

## Current capabilities

- Prompt-based circuit design using each account's own AI API key.
- Deterministic single-sided board placement and routing with explicit insulated jumper wires when needed.
- KiCad CLI validation before fabrication files are released.
- Mirrored B.Cu laser SVG with board, drill, jumper, and enclosure mounting references.
- Through-hole and surface-mount project styles.
- Printable shopping list and beginner-oriented build instructions.
- Optional enclosure STL containing a base, lid, matching PCB standoffs, and battery space when required.
- Account registration with administrator approval and encrypted per-user API keys.
- Advanced conversion of existing KiCad board files.

## Safety and scope

The first phase is intentionally limited to simple, low-voltage projects and a verified component catalog. Lithium charging/protection, mains, and high-voltage designs are rejected. Always inspect the KiCad board, test scale and orientation on paper, check component polarity, and inspect for solder bridges before applying power.

## Docker deployment

Requirements:

- Docker with Compose
- A persistent writable `data/` directory
- A Docker network named `proxy`, or an adjusted network configuration
- HTTPS reverse proxy for internet-facing deployment

```bash
cp .env.example .env
docker network create proxy 2>/dev/null || true
docker compose up -d --build
```

The container listens on port 8000 and the supplied Compose file publishes host port 8091. KiCad CLI is installed inside the image.

On a fresh installation, open `/setup` through a trusted local connection to create the first administrator. Public-host first-admin setup is deliberately refused.

## Configuration

See `.env.example` for optional settings. AI keys are not configured globally: every approved user must save their own key under Settings. Without a personal key, AI project creation is disabled for that account.

Registration requests always appear in the administrator screen. Email notifications additionally require SMTP configuration and a recipient selected in Admin.

## Persistent and private data

Everything under `data/` is runtime state and is excluded from Git. It contains accounts, encrypted user API keys, the server session/encryption secret, project briefs, generated boards, images, SVG/STL files, and recoverable deleted projects. Back up this directory separately and securely.

Never commit `.env`, `data/`, database files, session secrets, or generated user projects.

## Tests

The acceptance suite covers authentication and approval, encrypted user keys, safety gates, board geometry, enclosure STL generation, routing, SVG generation, and real KiCad DRC checks:

```bash
docker exec pcb-laser python -m unittest discover -s tests -v
```
