import test from 'node:test';
import assert from 'node:assert/strict';
import { isValidNpmPackageName } from '../src/command.js';
import { preupdatePackage, renderPreupdate } from '../src/preupdate.js';

test('npm package validation accepts plain and scoped names', () => {
  assert.equal(isValidNpmPackageName('npm'), true);
  assert.equal(isValidNpmPackageName('@modelcontextprotocol/server-filesystem'), true);
});

test('npm package validation rejects shell syntax and version specifiers', () => {
  assert.equal(isValidNpmPackageName('npm; echo pwned'), false);
  assert.equal(isValidNpmPackageName('npm && whoami'), false);
  assert.equal(isValidNpmPackageName('npm@latest'), false);
});

test('preupdate rejects invalid names before npm execution', () => {
  const result = preupdatePackage({ name: 'npm; echo pwned', global: true });
  assert.equal(result.found, false);
  assert.equal(result.error, 'invalid-package-name');
  assert.match(renderPreupdate(result), /valid npm package name/);
});
