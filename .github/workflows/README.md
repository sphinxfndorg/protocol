# GitHub Workflows

This directory contains GitHub Actions workflows for the Sphinx Protocol project.

## Workflows Overview

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | push to main, pull_request | Code quality checks, testing, build verification |
| `release.yml` | push tag (v*) | Cross-platform binary builds and GitHub releases |
| `security.yml` | push to main, pull_request, weekly schedule | Vulnerability scanning and CodeQL analysis |

## Workflow Maintenance

### When to Update Workflows

**CI Workflow (`ci.yml`):**
- When upgrading Go version in `go.mod` - Update the test matrix versions
- When adding new linters or changing code quality rules - Update `golangci-lint` config
- When changing build process or test commands - Update the test targets

**Release Workflow (`release.yml`):**
- When adding new build targets (new platforms)
- When changing binary names or output structure
- When updating ldflags or build parameters

**Security Workflow (`security.yml`):**
- Generally doesn't need updates unless CodeQL rules change
- New vulnerability scanners may be added as they become available

### Automatic Updates

Consider using **[Mend Renovate](https://github.com/renovatebot/renovate)** or **[Dependabot](https://docs.github.com/en/code-security/dependabot)** for:
- GitHub Actions version updates
- Tooling version updates (golangci-lint, etc.)

## Adding New Workflows

When the codebase evolves, consider adding:

1. **Integration Tests** - For multi-node blockchain testing
2. **Benchmarks** - Performance monitoring
3. **Documentation** - Auto-deploy docs on changes
4. **Docker Images** - Container build workflow

## Manual Workflow Dispatch

For workflows that need manual triggering, add:
```yaml
on:
  workflow_dispatch:
```

This is useful for:
- Manual release builds
- On-demand security scans
- Database migrations