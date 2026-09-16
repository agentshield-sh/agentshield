# Package Intelligence Sources

AgentShield is deliberately specific about package coverage: it cannot prove a package is safe or detect every compromise. It combines local evidence with primary-source ecosystem data, and it labels each signal rather than flattening everything into one opaque score.

## Sources used by AgentShield

### npm audit: known vulnerability advisories

`npm audit --json` checks the selected project's resolved dependency graph against the configured npm registry's advisory data. AgentShield uses the returned severity, direct/transitive status, and fix availability.

This is a networked check. npm normally submits package names and versions; if its bulk advisory endpoint fails, npm can fall back to sending the full lockfile tree plus environment metadata. Do not run it against a project whose dependency names are sensitive unless its registry and network policy permit that disclosure.

Official reference: <https://docs.npmjs.com/cli/v11/commands/npm-audit/>

### npm audit signatures: registry integrity and provenance

`npm audit signatures --json` verifies registry signatures and available provenance attestations for installed packages. AgentShield reports invalid signatures as high severity and missing signing data as a review signal, not proof of compromise.

Official reference: <https://docs.npmjs.com/verifying-registry-signatures/>

### Local manifests and lockfiles: source and reproducibility

AgentShield reads only the selected project's `package.json` and `package-lock.json` to flag direct Git/archive specs, missing integrity hashes for direct npm-registry packages, and package-tree mismatches from `npm ls`. No project files are uploaded for these checks.

## Supplemental reputable sources

These are useful cross-checks, but AgentShield does not query them automatically yet. They require a clear product/privacy decision before being added as default network calls.

### OSV.dev

OSV is an open vulnerability database with a public batch API. Query package name and version pairs—not a full source tree—when you want cross-registry coverage.

```bash
curl -sS https://api.osv.dev/v1/querybatch \
  -H 'content-type: application/json' \
  --data '{"queries":[{"package":{"ecosystem":"npm","name":"lodash"},"version":"4.17.21"}]}'
```

Official reference: <https://google.github.io/osv.dev/post-v1-querybatch/>

### GitHub Advisory Database and Dependabot

The GitHub Advisory Database covers reviewed vulnerability advisories and separately searchable malware advisories. Search npm-specific advisories with qualifiers such as `ecosystem:npm affects:PACKAGE`; use `type:malware` when reviewing known malicious packages. For a GitHub-hosted repository, enable Dependabot alerts for continuous monitoring of the committed dependency graph.

Official references: <https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/fix-reported-vulnerabilities/browse-advisory-database> and <https://docs.github.com/en/rest/security-advisories/global-advisories>

## What package scanning does not claim

- It cannot prove a package is benign or detect every newly published malicious package.
- It does not currently query private threat-intelligence feeds, scrape developer machines, or upload project source code.
- `npm audit` does not support global package audits. AgentShield can still report global packages that are outdated, but full advisory coverage needs an audited project dependency graph.
- Non-npm ecosystems require their own lockfile and advisory integrations.
