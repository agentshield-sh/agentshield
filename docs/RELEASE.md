# Release Runbook

## Required Decisions

- Confirm the npm package name is still `agentshield-sh` and unclaimed.
- Confirm the executable remains `agentshield`.
- Have qualified legal counsel review `TERMS.md` and the website `/terms` page.
- Publish a real legal/privacy contact and governing-law terms if required for the launch jurisdiction.

## Pre-release Verification

```bash
git pull --ff-only
npm ci
npm run check
npm run verify:e2e
npm audit
npm pack --dry-run
```

Expected:

- all tests pass, and the end-to-end script reports zero failures
- zero known runtime dependency vulnerabilities
- tarball includes CLI, core, dashboard server, README, Terms, Security Policy, Changelog, and docs
- CLI file is executable

Then install the packed tarball into an empty directory and run it from there:

```bash
npm pack
mkdir -p /tmp/agentshield-smoke && cd /tmp/agentshield-smoke
npm install ../path/to/agentshield-sh-0.1.0.tgz
./node_modules/.bin/agentshield --version
./node_modules/.bin/agentshield scan --concise
```

## Repository links

Every link in the repository points at `agentshield-sh/agentshield`. The
installer, the Homebrew formula, and the README badges all derive from that
slug, so if the repository ever moves, replace it everywhere in one pass and
check the result before tagging:

```bash
grep -rn "agentshield-sh/agentshield" --exclude-dir=node_modules --exclude-dir=.git .
```

## Registry Setup

The unscoped npm name `agentshield` belongs to another publisher. Do not publish or document this project under that package name.

Authenticate and verify identity:

```bash
npm login
npm whoami
```

Confirm the selected package name immediately before launch:

```bash
npm view agentshield-sh name version
```

An `E404` means no public package currently exists under that name. Availability is not reserved until publication succeeds.

## Publish

Update `CHANGELOG.md`, remove the `Unreleased` label, and confirm the version in `package.json`.

```bash
npm publish --access public
```

## Registry Smoke Test

Run from a clean temporary directory:

```bash
npx agentshield-sh scan --concise
npx agentshield-sh dashboard
```

Verify the dashboard binds to `127.0.0.1` and opens at `http://127.0.0.1:4173`.

## GitHub Release

```bash
git tag v0.1.0
git push origin v0.1.0
```

Create a GitHub release from the changelog. Include the npm install command and the assessment-not-protection limitation.

## Landing Deployment

In the landing repo:

```bash
npm ci
npm run check
npm audit
```

Set `NEXT_PUBLIC_SITE_URL` to the production origin. Verify `/`, `/terms`, `/privacy`, `/robots.txt`, and the social share image.

Do not deploy install instructions until the npm registry smoke test passes.

## Rollback

If the npm package is broken, deprecate the affected version with a clear message and publish a patch. Avoid unpublishing unless the release contains secrets or creates immediate harm; registry unpublishing has ecosystem consequences.
