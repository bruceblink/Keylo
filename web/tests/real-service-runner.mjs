import { spawn } from 'node:child_process';
import { createCipheriv, createHash, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createServer } from 'node:net';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const WEB_ROOT = path.join(REPO_ROOT, 'web');
const POSTGRES_IMAGE = 'postgres:17-alpine';
const MAILPIT_IMAGE = 'axllent/mailpit:v1.21.8';
const CONTAINER_OWNER_LABEL = 'io.keylo.real-service-runner';
const SERVICE_READINESS_TIMEOUT_MS = 120_000;
const CONTAINER_READINESS_TIMEOUT_MS = 60_000;
const SAFE_TEST_TITLES = new Set([
  'OIDC recovery opens an isolated tab and preserves authorization state',
  'real SMTP links verify email and reset a password exactly once'
]);

class RunnerFailure extends Error {
  constructor(stage, exitCode = 1) {
    super(stage);
    this.stage = stage;
    this.exitCode = exitCode;
  }
}

const activeChildren = new Set();
let requestedSignal;
let serveShutdown;
let cleanupInProgress = false;

function writeStatus(message) {
  process.stdout.write(`[real-service] ${message}\n`);
}

function fail(stage, exitCode = 1) {
  throw new RunnerFailure(stage, exitCode);
}

function parseArguments(argv) {
  const options = { serve: false, skipBuild: false, help: false, playwrightArgs: [] };
  let forwarding = false;

  for (const argument of argv) {
    if (forwarding) {
      options.playwrightArgs.push(argument);
      continue;
    }
    if (argument === '--') {
      forwarding = true;
      continue;
    }
    if (argument === '--skip-build') {
      options.skipBuild = true;
      continue;
    }
    if (argument === '--serve') {
      options.serve = true;
      continue;
    }
    if (argument === '--help' || argument === '-h') {
      options.help = true;
      continue;
    }
    fail('invalid_arguments', 64);
  }

  for (let index = 0; index < options.playwrightArgs.length; index += 1) {
    const argument = options.playwrightArgs[index];
    if (argument.startsWith('--grep=')) continue;
    if (argument === '--grep' && index + 1 < options.playwrightArgs.length) {
      index += 1;
      continue;
    }
    fail('unsupported_playwright_argument', 64);
  }

  if (options.serve && options.playwrightArgs.length > 0) {
    fail('serve_does_not_accept_playwright_arguments', 64);
  }
  return options;
}

function printUsage() {
  writeStatus('Usage: node tests/real-service-runner.mjs [--skip-build] [--serve] [-- PLAYWRIGHT_ARGS...]');
}

// Pass only platform runtime paths and the explicit local test inputs to child processes.
function sanitizedEnvironment(overrides = {}) {
  const allowed = [
    'PATHEXT', 'SystemRoot', 'SYSTEMROOT', 'WINDIR', 'ComSpec', 'COMSPEC',
    'TEMP', 'TMP', 'TMPDIR', 'HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA',
    'XDG_CACHE_HOME', 'XDG_CONFIG_HOME', 'PLAYWRIGHT_BROWSERS_PATH'
  ];
  const env = {};
  for (const key of allowed) {
    const value = process.env[key];
    if (value !== undefined && value !== '') env[key] = value;
  }
  const pathValue = process.env.PATH ?? process.env.Path;
  if (pathValue) env[process.platform === 'win32' ? 'Path' : 'PATH'] = pathValue;
  return { ...env, ...overrides };
}

// Build tools receive only their toolchain locations and platform linker settings.
function sanitizedBuildEnvironment() {
  const env = sanitizedEnvironment();
  const buildKeys = [
    'CARGO_HOME', 'RUSTUP_HOME', 'CARGO_TARGET_DIR', 'RUSTUP_TOOLCHAIN', 'RUSTC', 'RUSTDOC',
    'VCINSTALLDIR', 'VCToolsInstallDir', 'VCToolsVersion', 'WindowsSdkDir', 'WindowsSDKVersion',
    'UniversalCRTSdkDir', 'UCRTVersion', 'VisualStudioVersion', 'VSINSTALLDIR', 'LIB', 'LIBPATH', 'INCLUDE'
  ];
  for (const key of buildKeys) {
    const value = process.env[key];
    if (value !== undefined && value !== '') env[key] = value;
  }
  return env;
}

function isChildRunning(child) {
  return Boolean(child && child.exitCode === null && child.signalCode === null);
}

function waitForChildClose(child, timeoutMs) {
  if (!isChildRunning(child)) return Promise.resolve(true);
  return new Promise((resolve) => {
    const timer = setTimeout(() => finish(false), timeoutMs);
    const onClose = () => finish(true);
    const finish = (closed) => {
      clearTimeout(timer);
      child.removeListener('close', onClose);
      resolve(closed);
    };
    child.once('close', onClose);
  });
}

function launchQuiet(command, args, options = {}) {
  const child = spawn(command, args, {
    cwd: options.cwd,
    env: options.env,
    stdio: options.captureStdout ? ['ignore', 'pipe', 'ignore'] : 'ignore',
    detached: process.platform !== 'win32',
    windowsHide: true,
    shell: options.shell ?? false
  });
  activeChildren.add(child);
  child.once('close', () => activeChildren.delete(child));
  child.once('error', () => activeChildren.delete(child));
  return child;
}

async function taskkill(pid, force) {
  return new Promise((resolve) => {
    const args = ['/PID', String(pid), '/T'];
    if (force) args.push('/F');
    const killer = spawn('taskkill.exe', args, { stdio: 'ignore', windowsHide: true });
    let settled = false;
    const done = () => {
      if (settled) return;
      settled = true;
      resolve();
    };
    killer.once('error', done);
    killer.once('close', done);
    setTimeout(done, 3_000).unref();
  });
}

async function terminateProcessTree(child) {
  if (!isChildRunning(child)) return;

  if (process.platform === 'win32') {
    await taskkill(child.pid, false);
  } else {
    try {
      process.kill(-child.pid, 'SIGTERM');
    } catch {
      // The process can exit between the status check and the signal.
    }
  }

  if (await waitForChildClose(child, 2_000)) return;
  if (process.platform === 'win32') {
    await taskkill(child.pid, true);
  } else {
    try {
      process.kill(-child.pid, 'SIGKILL');
    } catch {
      // The process can exit while the termination signal is being sent.
    }
  }
  await waitForChildClose(child, 3_000);
}

// Signals stop detached process groups on Unix and full child trees on Windows.
function handleSignal(signal) {
  if (cleanupInProgress) return;
  requestedSignal = signal;
  if (serveShutdown) serveShutdown();
  for (const child of activeChildren) void terminateProcessTree(child);
}

function requestServeStop() {
  if (cleanupInProgress) return;
  requestedSignal = 'STOP';
  if (serveShutdown) serveShutdown();
  for (const child of activeChildren) void terminateProcessTree(child);
}

function signalExitCode() {
  if (requestedSignal === 'STOP') return 0;
  return requestedSignal === 'SIGINT' ? 130 : 143;
}

function throwIfInterrupted() {
  if (requestedSignal) fail('interrupted', signalExitCode());
}

// Child commands can time out; their process trees are stopped before the runner reports failure.
function runCommand(command, args, options = {}) {
  if (!options.ignoreInterrupt) throwIfInterrupted();
  return new Promise((resolve) => {
    const child = launchQuiet(command, args, options);
    let stdout = '';
    let timedOut = false;
    let settled = false;
    let timer;

    if (options.captureStdout) {
      child.stdout?.on('data', (chunk) => {
        const value = chunk.toString('utf8');
        if (stdout.length < 16_384) stdout += value.slice(0, 16_384 - stdout.length);
        if (options.onStdout) options.onStdout(value);
      });
    }

    const finish = (result) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve({ ...result, stdout });
    };

    if (options.timeoutMs) {
      timer = setTimeout(() => {
        timedOut = true;
        void terminateProcessTree(child).finally(() => finish({ code: 124, timedOut: true }));
      }, options.timeoutMs);
      timer.unref();
    }

    child.once('error', () => finish({ code: 127, timedOut }));
    child.once('close', (code, signal) => {
      finish({ code: timedOut ? 124 : code ?? (signal ? 1 : 127), timedOut });
    });
  });
}

async function getFreeLoopbackPort() {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (!address || typeof address === 'string') {
    server.close();
    fail('loopback_port_allocation_failed');
  }
  const port = address.port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function createTemporaryDirectory() {
  return fs.mkdtemp(path.join(tmpdir(), 'keylo-real-service-'));
}

async function prepareDatabaseCredentials(tempRoot) {
  const secretsDirectory = path.join(tempRoot, '.secrets');
  await fs.mkdir(secretsDirectory, { recursive: true, mode: 0o700 });
  const postgresPasswordFile = path.join(secretsDirectory, 'postgres_password');
  const encryptedPasswordFile = path.join(secretsDirectory, 'database_password.enc');
  const encryptionKeyFile = path.join(secretsDirectory, 'database_password.key');

  // Docker receives only a mounted one-time password file; Keylo receives only its AES-GCM form.
  const postgresPassword = randomBytes(32).toString('hex');
  const encryptionKey = randomBytes(32);
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', encryptionKey, nonce);
  const ciphertext = Buffer.concat([cipher.update(postgresPassword, 'utf8'), cipher.final(), cipher.getAuthTag()]);
  const encryptedValue = [
    'secret', 'v1', 'aes-256-gcm', nonce.toString('base64'), ciphertext.toString('base64')
  ].join(':');

  await fs.writeFile(postgresPasswordFile, `${postgresPassword}\n`, { mode: 0o600 });
  await fs.writeFile(encryptionKeyFile, `${encryptionKey.toString('base64')}\n`, { mode: 0o600 });
  await fs.writeFile(encryptedPasswordFile, `${encryptedValue}\n`, { mode: 0o600 });
  return { postgresPasswordFile, encryptedPasswordFile, encryptionKeyFile };
}

async function prepareTemporaryKeyloConfig(tempRoot, values) {
  const keyDirectory = path.join(tempRoot, 'keys');
  await fs.mkdir(keyDirectory, { recursive: true, mode: 0o700 });
  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' }
  });
  await fs.writeFile(path.join(keyDirectory, 'private.pem'), privateKey, { mode: 0o600 });
  await fs.writeFile(path.join(keyDirectory, 'public.pem'), publicKey, { mode: 0o600 });

  const entries = {
    ENVIRONMENT: 'development',
    SERVER_ADDR: '127.0.0.1',
    SERVER_PORT: String(values.keyloPort),
    DATABASE_URL: `postgres://postgres@127.0.0.1:${values.databasePort}/keylo_test`,
    DATABASE_PASSWORD_ENC_FILE: './.secrets/database_password.enc',
    DATABASE_PASSWORD_KEY_FILE: './.secrets/database_password.key',
    JWT_PRIVATE_KEY_PATH: './keys/private.pem',
    JWT_PUBLIC_KEY_PATH: './keys/public.pem',
    JWT_KEY_ID: `real-${values.runId.slice(0, 16)}`,
    OIDC_PUBLIC_ISSUER: values.baseURL,
    ALLOW_INSECURE_INTERNAL_HTTP: 'true',
    CORS_ALLOWED_ORIGINS: values.baseURL,
    MAIL_PROVIDER: 'smtp',
    SMTP_HOST: '127.0.0.1',
    SMTP_PORT: String(values.smtpPort),
    SMTP_TLS_MODE: 'plain',
    SMTP_FROM: 'no-reply@example.test',
    SMTP_TIMEOUT_SECONDS: '5',
    ADMIN_CLIENT_ID: values.adminId,
    ADMIN_CLIENT_SECRET: values.adminSecret,
    LOG_TO_FILE: 'false',
    ENABLE_SETUP_WIZARD: 'true',
    ALLOW_IN_MEMORY_FALLBACK: 'false'
  };

  const dotenv = `${Object.entries(entries).map(([key, value]) => `${key}=${value}`).join('\n')}\n`;
  await fs.writeFile(path.join(tempRoot, '.env'), dotenv, { mode: 0o600 });
}

async function prepareTemporaryWebAssets(tempRoot) {
  const source = path.join(WEB_ROOT, 'dist');
  const indexFile = path.join(source, 'index.html');
  try {
    await fs.access(indexFile);
  } catch {
    fail('frontend_build_output_missing');
  }
  await fs.cp(source, path.join(tempRoot, 'web', 'dist'), { recursive: true });
}

async function cargoTargetDirectory() {
  const result = await runCommand('cargo', [
    'metadata', '--no-deps', '--format-version', '1', '--manifest-path', path.join(REPO_ROOT, 'Cargo.toml')
  ], {
    cwd: REPO_ROOT,
    env: sanitizedBuildEnvironment(),
    captureStdout: true,
    timeoutMs: 60_000
  });
  if (result.code !== 0) fail('cargo_metadata_failed');
  try {
    const metadata = JSON.parse(result.stdout);
    if (typeof metadata.target_directory === 'string') return metadata.target_directory;
  } catch {
    // Do not surface command output because it may include user-specific paths.
  }
  fail('cargo_target_directory_unavailable');
}

async function buildArtifacts(options) {
  if (options.skipBuild) {
    writeStatus('Build: skipped by --skip-build.');
    return;
  }

  writeStatus('Type checking the frontend.');
  const typecheck = await runCommand(process.execPath, [
    path.join(WEB_ROOT, 'node_modules', 'typescript', 'bin', 'tsc'), '-b'
  ], {
    cwd: WEB_ROOT,
    env: sanitizedEnvironment(),
    timeoutMs: 600_000
  });
  if (typecheck.code !== 0) fail(typecheck.timedOut ? 'frontend_typecheck_timed_out' : 'frontend_typecheck_failed');

  writeStatus('Building frontend assets.');
  const frontend = await runCommand(process.execPath, [
    path.join(WEB_ROOT, 'node_modules', 'vite', 'bin', 'vite.js'), 'build'
  ], {
    cwd: WEB_ROOT,
    env: sanitizedEnvironment(),
    timeoutMs: 600_000
  });
  if (frontend.code !== 0) fail(frontend.timedOut ? 'frontend_build_timed_out' : 'frontend_build_failed');
  writeStatus('Frontend build: passed.');

  writeStatus('Building Keylo.');
  const backend = await runCommand('cargo', ['build', '--manifest-path', path.join(REPO_ROOT, 'Cargo.toml'), '--bin', 'keylo'], {
    cwd: REPO_ROOT,
    env: sanitizedBuildEnvironment(),
    timeoutMs: 900_000
  });
  if (backend.code !== 0) fail(backend.timedOut ? 'keylo_build_timed_out' : 'keylo_build_failed');
  writeStatus('Keylo build: passed.');
}

async function dockerCommand(args, options = {}) {
  return runCommand('docker', args, {
    env: sanitizedEnvironment(),
    cwd: REPO_ROOT,
    captureStdout: options.captureStdout ?? false,
    timeoutMs: options.timeoutMs ?? 180_000,
    ignoreInterrupt: options.ignoreInterrupt ?? false
  });
}

async function ensureLocalDocker() {
  const context = await dockerCommand(['context', 'inspect', '--format', '{{.Endpoints.docker.Host}}'], {
    captureStdout: true,
    timeoutMs: 20_000
  });
  if (context.code !== 0) fail('local_docker_context_unavailable');
  const host = context.stdout.trim();
  const localSocket = /^(unix|npipe):\/\//i.test(host);
  const localTcp = /^tcp:\/\/(localhost|127(?:\.\d{1,3}){3}|\[::1\])(?::\d+)?(?:\/.*)?$/i.test(host);
  if (!localSocket && !localTcp) fail('remote_docker_context_rejected');

  const info = await dockerCommand(['info'], { timeoutMs: 30_000 });
  if (info.code !== 0) fail('local_docker_unavailable');
}

function parsePublishedLoopbackPort(output) {
  const line = output.split(/\r?\n/).map((item) => item.trim()).find((item) => item.length > 0);
  const match = line?.match(/^127\.0\.0\.1:(\d+)$/);
  if (!match) return undefined;
  const port = Number(match[1]);
  return Number.isInteger(port) && port > 0 && port <= 65_535 ? port : undefined;
}

async function createContainer(container, args) {
  const label = `${CONTAINER_OWNER_LABEL}=${container.owner}`;
  const result = await dockerCommand(['create', '--name', container.name, '--label', label, ...args]);
  if (result.code !== 0) fail(container.stage);
  container.created = true;
}

async function getContainerPort(container, internalPort) {
  const result = await dockerCommand(['port', container.name, `${internalPort}/tcp`], { captureStdout: true });
  if (result.code !== 0) fail('docker_published_port_unavailable');
  const port = parsePublishedLoopbackPort(result.stdout);
  if (!port) fail('docker_loopback_binding_invalid');
  return port;
}

async function startContainer(container) {
  const result = await dockerCommand(['start', container.name]);
  if (result.code !== 0) fail(container.stage);
}

async function waitFor(check, stage, timeoutMs, intervalMs = 500) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    throwIfInterrupted();
    try {
      if (await check()) return;
    } catch (error) {
      if (error instanceof RunnerFailure) throw error;
      // Readiness probes can fail while the service is still starting.
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  fail(stage);
}

async function provisionPostgres(state) {
  const container = {
    name: `keylo-real-pg-${state.runId}`,
    owner: state.runId,
    stage: 'postgres_container_start_failed',
    created: false
  };
  state.containers.push(container);
  const passwordPath = state.databaseCredentials.postgresPasswordFile;
  await createContainer(container, [
    '--env', 'POSTGRES_USER=postgres',
    '--env', 'POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password',
    '--env', 'POSTGRES_DB=keylo_test',
    '--volume', `${passwordPath}:/run/secrets/postgres_password:ro`,
    '--publish', '127.0.0.1::5432',
    '--volume', '/var/lib/postgresql/data',
    POSTGRES_IMAGE
  ]);
  await startContainer(container);
  state.databasePort = await getContainerPort(container, 5432);
  await waitFor(async () => {
    const ready = await dockerCommand(['exec', container.name, 'pg_isready', '-U', 'postgres', '-d', 'keylo_test'], {
      timeoutMs: 10_000
    });
    return ready.code === 0;
  }, 'postgres_readiness_timed_out', CONTAINER_READINESS_TIMEOUT_MS);
  writeStatus(`PostgreSQL ready: ${POSTGRES_IMAGE} on 127.0.0.1:${state.databasePort}.`);
}

async function provisionMailpit(state) {
  const container = {
    name: `keylo-real-mail-${state.runId}`,
    owner: state.runId,
    stage: 'mailpit_container_start_failed',
    created: false
  };
  state.containers.push(container);
  await createContainer(container, [
    '--publish', '127.0.0.1::1025',
    '--publish', '127.0.0.1::8025',
    MAILPIT_IMAGE
  ]);
  await startContainer(container);
  state.smtpPort = await getContainerPort(container, 1025);
  state.mailpitPort = await getContainerPort(container, 8025);
  const endpoint = `http://127.0.0.1:${state.mailpitPort}/api/v1/messages`;
  await waitFor(async () => {
    const response = await fetch(endpoint, { signal: AbortSignal.timeout(2_000) });
    return response.status === 200;
  }, 'mailpit_readiness_timed_out', CONTAINER_READINESS_TIMEOUT_MS);
  writeStatus(`Mailpit ready: ${MAILPIT_IMAGE} on 127.0.0.1:${state.mailpitPort}.`);
}

async function startKeylo(state) {
  const binary = path.join(await cargoTargetDirectory(), 'debug', process.platform === 'win32' ? 'keylo.exe' : 'keylo');
  try {
    await fs.access(binary);
  } catch {
    fail('keylo_binary_missing');
  }

  const child = spawn(binary, [], {
    cwd: state.tempRoot,
    env: sanitizedEnvironment({ RUST_LOG: 'off' }),
    stdio: 'ignore',
    detached: process.platform !== 'win32',
    windowsHide: true
  });
  state.service = child;
  activeChildren.add(child);
  child.once('close', () => activeChildren.delete(child));
  child.once('error', () => activeChildren.delete(child));

  await waitFor(async () => {
    if (!isChildRunning(child)) fail('keylo_exited_before_readiness');
    const response = await fetch(`${state.keyloURL}/healthz`, { signal: AbortSignal.timeout(2_000) });
    if (response.status !== 200) return false;
    const body = await response.json();
    return body.status === 'ok' && body.service === 'keylo';
  }, 'keylo_readiness_timed_out', SERVICE_READINESS_TIMEOUT_MS, 400);
  writeStatus(`Keylo health endpoint ready: ${state.keyloURL}/healthz.`);
}

async function initializeKeyloSetup(state) {
  let response;
  try {
    response = await fetch(`${state.keyloURL}/setup/initialize`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        admin_client_id: state.adminId,
        admin_client_secret: state.adminSecret
      }),
      signal: AbortSignal.timeout(15_000)
    });
  } catch {
    fail('keylo_setup_initialization_failed');
  }
  if (response.status !== 200) fail(`keylo_setup_initialization_http_${response.status}`);

  await waitFor(async () => {
    const ready = await fetch(`${state.keyloURL}/readyz`, { signal: AbortSignal.timeout(2_000) });
    if (ready.status !== 200) return false;
    const body = await ready.json();
    return body.status === 'ok' && body.service === 'keylo' && body.checks?.database === 'ok';
  }, 'keylo_readiness_timed_out', SERVICE_READINESS_TIMEOUT_MS, 400);
  writeStatus(`Keylo ready: ${state.keyloURL}/readyz reports database readiness.`);
}

function createReporterFilter() {
  let pending = '';
  let testCount = 0;
  let summary;
  const consume = (rawLine) => {
    const line = rawLine.trim();
    const testMatch = line.match(/^\[real-browser\] (.+): (passed|failed|timedOut|skipped|interrupted)(?: at ([a-z0-9_]+))?$/);
    if (testMatch && SAFE_TEST_TITLES.has(testMatch[1])) {
      testCount += 1;
      const stage = testMatch[3] ? ` at ${testMatch[3]}` : '';
      writeStatus(`Browser test ${testCount}: ${testMatch[1]} — ${testMatch[2]}${stage}.`);
      return;
    }
    const summaryMatch = line.match(/^\[real-browser\] (passed|failed|timedOut|interrupted); (\d+) passed, (\d+) failed$/);
    if (summaryMatch) {
      summary = {
        status: summaryMatch[1],
        passed: Number(summaryMatch[2]),
        failed: Number(summaryMatch[3])
      };
    }
  };
  return {
    onChunk(chunk) {
      pending += chunk;
      const lines = pending.split(/\r?\n/);
      pending = lines.pop() ?? '';
      for (const line of lines) consume(line);
    },
    finish() {
      if (pending) consume(pending);
      return { testCount, summary };
    }
  };
}

async function provisionDemoClient(state) {
  let tokenResponse;
  try {
    tokenResponse = await fetch(`${state.baseURL}/v1/admin/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client_id: state.adminId, client_secret: state.adminSecret }),
      signal: AbortSignal.timeout(10_000)
    });
    if (!tokenResponse.ok) fail(`demo_client_admin_auth_http_${tokenResponse.status}`);
    const token = await tokenResponse.json();
    if (typeof token.access_token !== 'string') fail('demo_client_admin_auth_failed');

    const clientResponse = await fetch(`${state.baseURL}/v1/admin/oidc/clients`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${token.access_token}`
      },
      body: JSON.stringify({
        client_id: 'real-browser-demo',
        name: 'Real Browser Demo',
        client_type: 'public',
        redirect_uris: ['http://127.0.0.1:32000/callback'],
        scopes: ['openid', 'profile'],
        grant_types: ['authorization_code']
      }),
      signal: AbortSignal.timeout(10_000)
    });
    if (!clientResponse.ok) fail(`demo_client_creation_http_${clientResponse.status}`);
  } catch (error) {
    if (error instanceof RunnerFailure) throw error;
    fail('demo_client_creation_failed');
  }
}

function demoAuthorizeURL(baseURL) {
  const verifier = randomBytes(32);
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: 'real-browser-demo',
    redirect_uri: 'http://127.0.0.1:32000/callback',
    scope: 'openid profile',
    state: 'codex-real-browser',
    nonce: 'codex-real-browser',
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256'
  });
  return `${baseURL}/v1/oidc/authorize?${params.toString()}`;
}

async function waitForShutdown() {
  if (requestedSignal) return;
  await new Promise((resolve) => {
    serveShutdown = resolve;
  });
  serveShutdown = undefined;
}

// Remove a container only after its runner label proves it belongs to this invocation.
async function cleanupContainers(containers, runId) {
  let complete = true;
  for (const container of [...containers].reverse()) {
    const inspect = await dockerCommand([
      'inspect', '--format', `{{ index .Config.Labels "${CONTAINER_OWNER_LABEL}" }}`, container.name
    ], { captureStdout: true, timeoutMs: 20_000, ignoreInterrupt: true });

    if (inspect.code !== 0) {
      const dockerAvailable = await dockerCommand(['info'], { timeoutMs: 20_000, ignoreInterrupt: true });
      if (dockerAvailable.code !== 0) complete = false;
      continue;
    }
    if (inspect.stdout.trim() !== runId) {
      complete = false;
      continue;
    }

    const removed = await dockerCommand(['rm', '-f', '-v', container.name], {
      timeoutMs: 60_000,
      ignoreInterrupt: true
    });
    if (removed.code !== 0) complete = false;
  }
  return complete;
}

async function cleanup(state) {
  let complete = true;
  let serviceStopped = true;

  if (state.service) {
    await terminateProcessTree(state.service);
    serviceStopped = !isChildRunning(state.service);
    if (!serviceStopped) complete = false;
    state.service = undefined;
  }

  let otherChildrenStopped = true;
  for (const child of [...activeChildren]) {
    await terminateProcessTree(child);
    if (isChildRunning(child)) otherChildrenStopped = false;
  }
  if (!otherChildrenStopped) {
    complete = false;
    writeStatus('Child process cleanup: incomplete; temporary files may still be in use.');
  }

  let containersRemoved = true;
  if (state.containers.length > 0) {
    if (await cleanupContainers(state.containers, state.runId)) {
      writeStatus('Docker containers and anonymous volumes: removed.');
    } else {
      containersRemoved = false;
      complete = false;
      writeStatus('Docker cleanup: incomplete; check the local Docker daemon.');
    }
  }

  if (state.tempRoot) {
    const resolvedTempRoot = path.resolve(tmpdir());
    const resolvedTarget = path.resolve(state.tempRoot);
    const safeTarget = path.dirname(resolvedTarget) === resolvedTempRoot
      && /^keylo-real-service-[a-zA-Z0-9_-]+$/.test(path.basename(resolvedTarget));
    if (!safeTarget) {
      complete = false;
      writeStatus('Temporary file cleanup: refused an unexpected path.');
    } else if (containersRemoved && serviceStopped && otherChildrenStopped) {
      try {
        await fs.rm(resolvedTarget, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
        writeStatus('Temporary configuration, RSA keys, database credentials, and web assets: removed.');
      } catch {
        complete = false;
        writeStatus('Temporary file cleanup: incomplete; a local file may be locked.');
      }
    } else {
      complete = false;
      writeStatus('Temporary secrets retained because a service or container may still use them.');
    }
  }
  return complete;
}

async function main() {
  const state = {
    containers: [],
    tempRoot: undefined,
    databaseCredentials: undefined,
    service: undefined
  };
  let exitCode = 0;

  process.on('SIGINT', handleSignal);
  process.on('SIGTERM', handleSignal);

  try {
    const options = parseArguments(process.argv.slice(2));
    if (options.help) {
      printUsage();
      return 0;
    }
    state.options = options;
    state.runId = randomUUID().replaceAll('-', '');
    state.adminId = `real-admin-${randomBytes(8).toString('hex')}`;
    state.adminSecret = randomBytes(32).toString('hex');

    await buildArtifacts(options);
    await ensureLocalDocker();

    state.tempRoot = await createTemporaryDirectory();
    state.databaseCredentials = await prepareDatabaseCredentials(state.tempRoot);

    await provisionPostgres(state);
    await provisionMailpit(state);

    state.keyloPort = await getFreeLoopbackPort();
    state.keyloURL = `http://127.0.0.1:${state.keyloPort}`;
    state.baseURL = state.keyloURL;
    await prepareTemporaryKeyloConfig(state.tempRoot, {
      runId: state.runId,
      keyloPort: state.keyloPort,
      databasePort: state.databasePort,
      smtpPort: state.smtpPort,
      baseURL: state.baseURL,
      adminId: state.adminId,
      adminSecret: state.adminSecret
    });
    await prepareTemporaryWebAssets(state.tempRoot);

    await startKeylo(state);
    await initializeKeyloSetup(state);

    if (options.serve) {
      await provisionDemoClient(state);
      writeStatus(`Mailpit UI/API: http://127.0.0.1:${state.mailpitPort}/`);
      writeStatus(`Demo sign-in: ${demoAuthorizeURL(state.baseURL)}`);
      writeStatus('Serve mode is ready. Type stop or press Ctrl+C to remove the isolated services.');
      process.stdin.setEncoding('utf8');
      let stdinBuffer = '';
      process.stdin.on('data', (chunk) => {
        stdinBuffer += chunk;
        const lines = stdinBuffer.split(/\r?\n/);
        stdinBuffer = lines.pop() ?? '';
        if (lines.some((line) => line.trim().toLowerCase() === 'stop')) requestServeStop();
      });
      await waitForShutdown();
      exitCode = requestedSignal ? signalExitCode() : 0;
    } else {
      const mailpitURL = `http://127.0.0.1:${state.mailpitPort}`;
      const outputDirectory = path.join(state.tempRoot, 'playwright-results');
      await fs.mkdir(outputDirectory, { recursive: true, mode: 0o700 });
      const testEnv = sanitizedEnvironment({
        KEYLO_REAL_BASE_URL: state.baseURL,
        KEYLO_REAL_MAILPIT_URL: mailpitURL,
        KEYLO_REAL_ADMIN_ID: state.adminId,
        KEYLO_REAL_ADMIN_SECRET: state.adminSecret,
        KEYLO_REAL_OUTPUT_DIR: outputDirectory,
        PLAYWRIGHT_NO_COPY_PROMPT: '1'
      });
      writeStatus('Running real-service Playwright checks.');
      const reporterFilter = createReporterFilter();
      const playwrightCli = path.join(WEB_ROOT, 'node_modules', '@playwright', 'test', 'cli.js');
      const result = await runCommand(process.execPath, [
        playwrightCli, 'test', '--config', 'playwright.real.config.ts', ...options.playwrightArgs
      ], {
        cwd: WEB_ROOT,
        env: testEnv,
        captureStdout: true,
        onStdout: reporterFilter.onChunk,
        timeoutMs: 390_000
      });
      if (requestedSignal) fail('interrupted', signalExitCode());
      const report = reporterFilter.finish();
      if (report.summary) {
        writeStatus(`Playwright summary: ${report.summary.passed} passed, ${report.summary.failed} failed.`);
      }
      if (result.code !== 0) {
        writeStatus(`Playwright process exit status: ${result.code}.`);
        fail(result.timedOut ? 'playwright_timed_out' : 'playwright_failed', result.code);
      }
      if (report.summary?.status !== 'passed' || report.summary.passed === 0 || report.summary.failed !== 0) {
        fail('playwright_report_incomplete');
      }
      if (!report.summary) fail('playwright_report_incomplete');
      writeStatus(`Playwright checks: ${report.summary.passed} passed, ${report.summary.failed} failed.`);
    }
  } catch (error) {
    if (requestedSignal) {
      exitCode = signalExitCode();
      writeStatus(`Interrupted (${requestedSignal}); preserving exit status ${exitCode}.`);
    } else if (error instanceof RunnerFailure) {
      exitCode = error.exitCode;
      writeStatus(`Failed at ${error.stage}; diagnostics and service logs are suppressed.`);
    } else {
      exitCode = 1;
      writeStatus('Failed during runner setup; diagnostics and service logs are suppressed.');
    }
  } finally {
    cleanupInProgress = true;
    try {
      const cleanupComplete = await cleanup(state);
      if (!cleanupComplete && exitCode === 0) exitCode = 1;
      if (cleanupComplete) writeStatus('Cleanup complete.');
    } catch {
      if (exitCode === 0) exitCode = 1;
      writeStatus('Cleanup failed; diagnostics are suppressed.');
    } finally {
      process.removeListener('SIGINT', handleSignal);
      process.removeListener('SIGTERM', handleSignal);
    }
  }

  return exitCode;
}

main().then((code) => {
  process.exitCode = code;
}).catch(() => {
  writeStatus('Runner failed; diagnostics are suppressed.');
  process.exitCode = requestedSignal ? signalExitCode() : 1;
});
