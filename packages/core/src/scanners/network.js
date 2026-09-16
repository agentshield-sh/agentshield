import { textCommand } from '../command.js';
import { createFinding } from '../schema.js';
import { shortHash } from '../id.js';

// Operating-system daemons that listen on every interface by design. Reporting
// them tells the reader nothing they can act on and buries the listener that
// matters. The names are what lsof and ss print.
const systemProcesses = new Set([
  'ControlCenter',
  'rapportd',
  'sharingd',
  'mDNSResponder',
  'launchd',
  'systemd',
  'systemd-resolve',
  'siriactionsd',
  'AirPlayXPCHelper',
  'identityservicesd',
  'remoted',
  'remotepairingd',
  'remotemanagementd',
  'bluetoothd',
  'cupsd',
  'avahi-daemon',
]);

const developmentProcesses = /^(node|npm|npx|bun|deno|python\d*|ruby|php|java|vite|next|webpack|openclaw|claude|codex|mcp)/i;
const developmentPorts = new Set([3000, 3001, 4173, 4180, 4200, 5000, 5173, 8000, 8080, 8888, 9222]);

function endpointParts(endpoint) {
  const match = String(endpoint || '').match(/^(.*):(\d+)$/);
  if (!match) return null;
  const host = match[1].replace(/^\[|\]$/g, '');
  const port = Number(match[2]);
  const loopback = host === '127.0.0.1' || host === '::1' || host === 'localhost';
  const wildcard = host === '*' || host === '0.0.0.0' || host === '::';
  return { host, port, loopback, wildcard };
}

export function parseLsofListeners(raw) {
  const listeners = [];
  let processName = null;
  let pid = null;
  for (const line of String(raw || '').split('\n')) {
    const field = line[0];
    const value = line.slice(1);
    if (field === 'p') pid = value;
    if (field === 'c') processName = value;
    if (field !== 'n') continue;
    const endpoint = endpointParts(value);
    if (endpoint) listeners.push({ process: processName || 'unknown', pid, endpoint: value, ...endpoint });
  }
  return dedupeListeners(listeners);
}

export function parseSsListeners(raw) {
  const listeners = [];
  for (const line of String(raw || '').split('\n')) {
    if (!line.trim()) continue;
    const columns = line.trim().split(/\s+/);
    const endpointValue = columns.find((value) => /:\d+$/.test(value));
    const endpoint = endpointParts(endpointValue);
    if (!endpoint) continue;
    const processMatch = line.match(/\(\("([^"\n]+)"/);
    const pidMatch = line.match(/pid=(\d+)/);
    listeners.push({
      process: processMatch?.[1] || 'unknown',
      pid: pidMatch?.[1] || null,
      endpoint: endpointValue,
      ...endpoint,
    });
  }
  return dedupeListeners(listeners);
}

function dedupeListeners(listeners) {
  return [...new Map(listeners.map((listener) => [
    `${listener.process}|${listener.endpoint}`,
    listener,
  ])).values()];
}

function discoverListeners() {
  const lsof = textCommand('lsof', ['-nP', '-iTCP', '-sTCP:LISTEN', '-F', 'pcPn']);
  if (lsof) return parseLsofListeners(lsof);
  const ss = textCommand('ss', ['-ltnpH']);
  return ss ? parseSsListeners(ss) : [];
}

function isDevelopmentListener(listener) {
  return developmentProcesses.test(listener.process) || developmentPorts.has(listener.port);
}

export function runNetworkExposureScan(options = {}) {
  const listeners = options.listeners || discoverListeners();
  return listeners
    .filter((listener) => !listener.loopback && !systemProcesses.has(listener.process))
    .map((listener) => {
      const development = isDevelopmentListener(listener);
      const key = shortHash(`${listener.process}-${listener.host}-${listener.port}`);
      return createFinding({
        id: `network-listener-${key}`,
        category: 'network-exposure',
        severity: development ? 'medium' : 'low',
        confidence: listener.wildcard ? 'high' : 'medium',
        title: development
          ? 'Development service is reachable beyond localhost'
          : 'TCP service is reachable beyond localhost',
        description: `${listener.process} is listening on ${listener.endpoint}, which may be reachable from other devices or network interfaces.`,
        recommendation: 'Bind the service to 127.0.0.1 unless network access is intentional, authenticated, and restricted.',
        metadata: {
          process: listener.process,
          pid: listener.pid,
          host: listener.host,
          port: listener.port,
          binding: listener.wildcard ? 'wildcard' : 'network-interface',
        },
      });
    });
}
