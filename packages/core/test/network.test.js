import test from 'node:test';
import assert from 'node:assert/strict';
import { parseLsofListeners, parseSsListeners, runNetworkExposureScan } from '../src/scanners/network.js';

test('lsof parser separates loopback and wildcard listeners', () => {
  const listeners = parseLsofListeners([
    'p101',
    'cnode',
    'n*:3000',
    'p102',
    'cfigma_agent',
    'n127.0.0.1:44950',
  ].join('\n'));

  assert.equal(listeners.length, 2);
  assert.equal(listeners[0].wildcard, true);
  assert.equal(listeners[1].loopback, true);
});

test('ss parser captures process and exposed endpoint', () => {
  const listeners = parseSsListeners('LISTEN 0 511 0.0.0.0:5173 0.0.0.0:* users:(("node",pid=321,fd=20))');
  assert.equal(listeners.length, 1);
  assert.equal(listeners[0].process, 'node');
  assert.equal(listeners[0].port, 5173);
  assert.equal(listeners[0].wildcard, true);
});

test('network scan ignores loopback and flags exposed development services', () => {
  const findings = runNetworkExposureScan({
    listeners: [
      { process: 'node', pid: '101', endpoint: '*:3000', host: '*', port: 3000, wildcard: true, loopback: false },
      { process: 'node', pid: '102', endpoint: '127.0.0.1:4173', host: '127.0.0.1', port: 4173, wildcard: false, loopback: true },
    ],
  });

  assert.equal(findings.length, 1);
  assert.equal(findings[0].category, 'network-exposure');
  assert.equal(findings[0].severity, 'medium');
  assert.equal(findings[0].metadata.port, 3000);
});

test('network scan classifies a generic exposed service as low severity', () => {
  const findings = runNetworkExposureScan({
    listeners: [
      { process: 'nc', pid: '103', endpoint: '*:8090', host: '*', port: 8090, wildcard: true, loopback: false },
    ],
  });

  assert.equal(findings.length, 1);
  assert.equal(findings[0].title, 'TCP service is reachable beyond localhost');
  assert.equal(findings[0].severity, 'low');
  assert.equal(findings[0].confidence, 'high');
});
