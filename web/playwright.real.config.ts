import { defineConfig, devices } from '@playwright/test';

// Only the isolated Docker runner supplies endpoints. No Vite proxy or API stubs.
const baseURL = process.env.KEYLO_REAL_BASE_URL;
const outputDir = process.env.KEYLO_REAL_OUTPUT_DIR;
if (!baseURL || new URL(baseURL).hostname !== '127.0.0.1' || !outputDir) {
  throw new Error('Start the isolated local services with npm run test:e2e:real.');
}

// Playwright 1.63 otherwise adds an ARIA error snapshot even with tracing off.
// Its bundled recorder checks this flag before collecting page contents.
process.env.PLAYWRIGHT_NO_COPY_PROMPT = '1';

export default defineConfig({
  testDir: './tests',
  testMatch: '**/*.real.spec.ts',
  outputDir,
  preserveOutput: 'never',
  workers: 1,
  timeout: 90_000,
  globalTimeout: 300_000,
  expect: { timeout: 10_000 },
  reporter: [['./tests/real-service-reporter.ts']],
  // Authentication forms and mail links contain secrets, even for synthetic users.
  // Do not persist traces, screenshots, videos or attached DOM snapshots.
  use: { baseURL, actionTimeout: 10_000, navigationTimeout: 10_000, trace: 'off', screenshot: 'off', video: 'off' },
  projects: [
    { name: 'real-desktop', use: { ...devices['Desktop Chrome'], viewport: { width: 1280, height: 720 } } },
    { name: 'real-mobile', use: { ...devices['Desktop Chrome'], viewport: { width: 390, height: 844 } } }
  ]
});
