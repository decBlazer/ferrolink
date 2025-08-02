# FerroLink – Project Roadmap

*Last updated: $(date +'%Y-%m-%d')*

---
## 🎯 High-level Goals
1. Production-grade secure remote-desktop / monitoring stack in Rust.
2. First-class observability (Prometheus + Grafana + structured logs).
3. Simple, reproducible deployment (Docker Compose → K8s).

---
## ✅ Completed
- Latency benchmark script (`bench/latency.sh`) + sample results
- Minimal Grafana dashboard (`grafana/agent-overview.json`)
- Prometheus alert rule example (`grafana/alerts.yml`)
- Startup guide (`startup.md`)

---
## 🗓️ Planned / In-Progress
| Priority | Area | Task | Issue/Notes |
|----------|------|------|-------------|
| P0 | CI/CD | Add GitHub Actions workflow: build, test, clippy, fmt, docker-build |  |
| P0 | Security | Automate dev-cert generation (`make dev-certs`) & document LetsEncrypt for prod |  |
| P1 | Persistence | Flesh out SQLx migrations; store agent logs & file-transfer metadata |  |
| P1 | Config/Secrets | Move from `.env` to Docker secrets / Vault integration |  |
| P1 | Observability | Expand Grafana dashboard (disk IO, network, DB stats) |  |
| P2 | Security | Trivy/Grype scans in CI; drop container capabilities |  |
| P2 | Testing | Integration test harness that spins up agent + runs client commands |  |
| P2 | Features | Resume / verify file-transfer; delta sync |  |
| P3 | Features | Remote desktop (RDP/WebRTC) prototype |  |
| P3 | Docs | Convert README/startup.md to MkDocs site with diagrams |  |
| P3 | Packaging | Cross-compile binaries; Homebrew / winget manifests |  |

---
## 📌 How to use this file
1. **Always** add new work items here before starting implementation.
2. Use GitHub issues linked in the table for detailed discussion.
3. Mark tasks ✅ once merged to `main`.
4. Keep this roadmap in sync with release notes and documentation.

Happy hacking! 🎉 