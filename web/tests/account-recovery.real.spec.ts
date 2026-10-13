import { expect, test, type APIRequestContext, type Page } from '@playwright/test';
import { createHash, randomBytes, randomUUID } from 'node:crypto';

const baseURL = new URL(process.env.KEYLO_REAL_BASE_URL!).origin;
const mailURL = new URL(process.env.KEYLO_REAL_MAILPIT_URL!).origin;
const neutralMessage = '如果账户可以恢复，邮件会很快送达。请检查收件箱。';

// Report only a fixed stage name. Playwright's normal call logs can echo form
// values, mail addresses and fragment tokens when an assertion fails.
async function sensitiveFlow(flow: string, action: (setStage: (stage: string) => void) => Promise<void>) {
  let currentStage = 'initialization';
  try {
    await action((stage) => { currentStage = stage; });
  } catch {
    throw new Error(`Real-service check failed: ${flow} at ${currentStage}. Sensitive diagnostics suppressed.`);
  }
}

async function post(api: APIRequestContext, route: string, data?: unknown, bearer?: string) {
  const response = await api.post(route, {
    data,
    headers: bearer ? { Authorization: `Bearer ${bearer}` } : undefined,
    timeout: 10_000
  });
  if (!response.ok()) throw new Error('Unexpected API status');
  return response.json();
}

// Match recipient, subject and hosted route in this run's private Mailpit.
// Links stay in memory; polling failures never print mail content or tokens.
async function mailLink(api: APIRequestContext, recipient: string, subject: string, route: string) {
  if (new URL(mailURL).hostname !== '127.0.0.1') throw new Error('Local Mailpit is required');
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    const response = await api.get(`${mailURL}/api/v1/messages`, { timeout: 2_000 });
    if (response.ok()) {
      const list = await response.json();
      for (const message of list.messages ?? []) {
        if (message.Subject !== subject || !message.To?.some((item: { Address: string }) => item.Address === recipient)) continue;
        const detail = await api.get(`${mailURL}/api/v1/message/${message.ID}`, { timeout: 2_000 });
        if (!detail.ok()) continue;
        const body = await detail.json();
        const link = String(body.Text).match(/http:\/\/127\.0\.0\.1:\d+\/account\/[a-z-]+#token=[A-Za-z0-9_-]+/)?.[0];
        if (link && new URL(link).origin === baseURL && new URL(link).pathname === route) return link;
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error('Expected mail not delivered within deadline');
}

async function browserState(page: Page) {
  const state = await page.evaluate(() => ({
    hash: location.hash, search: location.search,
    local: localStorage.length, session: sessionStorage.length,
    width: document.documentElement.clientWidth, content: document.documentElement.scrollWidth
  }));
  expect(state.hash).toBe('');
  expect(state.search).toBe('');
  expect(state.local).toBe(0);
  expect(state.session).toBe(0);
  expect(state.content).toBeLessThanOrEqual(state.width);
}

function watchRuntime(page: Page, errors: boolean[], expectedFailurePaths: string[] = []) {
  page.on('pageerror', () => errors.push(true));
  page.on('console', (message) => {
    if (message.type() !== 'error' && message.type() !== 'warning') return;
    // Chromium reports intentional token-replay 400s as resource errors. Only
    // those exact endpoint/status pairs are expected; console.error still fails.
    const expectedResourceError = expectedFailurePaths.some((route) => message.location().url === `${baseURL}${route}`)
      && /^Failed to load resource: the server responded with a status of 400 /.test(message.text());
    if (!expectedResourceError) errors.push(true);
  });
}

async function accountNavigation(page: Page, link: string) {
  const response = await page.goto(link);
  if (!response?.ok()) throw new Error('Account page did not load');
  const headers = response.headers();
  expect(headers['cache-control']).toBe('no-store');
  expect(headers['referrer-policy']).toBe('no-referrer');
  expect(headers['x-frame-options']).toBe('DENY');
  expect(headers['x-content-type-options']).toBe('nosniff');
  expect(headers['content-security-policy']).toContain("connect-src 'self'");
}

test('OIDC recovery opens an isolated tab and preserves authorization state', async ({ page, request, context }) => {
  await sensitiveFlow('OIDC recovery navigation', async (setStage) => {
    const errors: boolean[] = [];
    context.on('page', (tab) => watchRuntime(tab, errors));
    watchRuntime(page, errors);
    setStage('admin_login');
    const admin = await post(request, '/v1/admin/token', {
      client_id: process.env.KEYLO_REAL_ADMIN_ID, client_secret: process.env.KEYLO_REAL_ADMIN_SECRET
    });
    const clientID = `browser-${randomUUID()}`;
    setStage('create_oidc_client');
    await post(request, '/v1/admin/oidc/clients', {
      client_id: clientID, name: 'Real Browser Regression', client_type: 'public',
      redirect_uris: ['http://127.0.0.1:32000/callback'], scopes: ['openid', 'profile'], grant_types: ['authorization_code']
    }, admin.access_token);
    const params = new URLSearchParams({
      response_type: 'code', client_id: clientID, redirect_uri: 'http://127.0.0.1:32000/callback',
      scope: 'openid profile', state: 'synthetic-state', nonce: 'synthetic-nonce',
      code_challenge: createHash('sha256').update(randomBytes(32)).digest('base64url'), code_challenge_method: 'S256'
    });
    setStage('open_authorization_page');
    await page.goto(`/v1/oidc/authorize?${params}`);
    await expect(page.getByRole('heading', { name: 'Sign in to authorize Real Browser Regression' })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    await page.getByLabel('Username').fill('synthetic-user');
    const originalURL = page.url();
    const hiddenFields = () => page.locator('input[type=hidden]').evaluateAll((fields) => fields.map((field) => ({
      name: (field as HTMLInputElement).name, value: (field as HTMLInputElement).value
    })));
    const originalFields = await hiddenFields();
    expect(originalFields).toHaveLength(8);
    const link = page.getByRole('link', { name: 'Forgot your password?' });
    await expect(link).toHaveAttribute('href', '/account/password-reset');
    await expect(link).toHaveAttribute('target', '_blank');
    await expect(link).toHaveAttribute('rel', 'noopener noreferrer');
    const popupPromise = page.waitForEvent('popup');
    const navigationPromise = context.waitForEvent('request', { predicate: (req) => req.isNavigationRequest() && req.url() === `${baseURL}/account/password-reset` });
    setStage('open_recovery_in_new_tab');
    await link.click();
    const popup = await popupPromise;
    const navigation = await navigationPromise;
    expect((await navigation.allHeaders()).referer).toBeUndefined();
    await expect(popup.getByRole('heading', { name: '恢复账户访问' })).toBeVisible();
    expect(await popup.evaluate(() => window.opener === null)).toBe(true);
    await browserState(popup);
    setStage('submit_account_neutral_request');
    await popup.getByLabel('邮箱或用户名').fill(`absent-${randomUUID()}@example.test`);
    await popup.getByRole('button', { name: '发送恢复邮件' }).click();
    await expect(popup.getByRole('status')).toHaveText(neutralMessage);
    await expect(popup.getByRole('button', { name: '发送恢复邮件' })).toBeEnabled();
    await popup.close();
    expect(page.url()).toBe(originalURL);
    expect(await hiddenFields()).toEqual(originalFields);
    await expect(page.getByLabel('Username')).toHaveValue('synthetic-user');
    expect(errors).toEqual([]);
  });
});

test('real SMTP links verify email and reset a password exactly once', async ({ page, request }) => {
  await sensitiveFlow('SMTP account recovery lifecycle', async (setStage) => {
    const runtimeErrors: boolean[] = [];
    watchRuntime(page, runtimeErrors, ['/v1/auth/email-verification/confirm', '/v1/auth/password-reset/confirm']);
    const username = `recovery-${randomUUID()}`;
    const email = `${username}@example.test`;
    const oldPassword = `Old#${randomBytes(18).toString('hex')}aA1`;
    const newPassword = `New#${randomBytes(18).toString('hex')}aA1`;
    setStage('register_synthetic_account');
    await post(request, '/v1/auth/register', { username, email, password: oldPassword });
    setStage('initial_password_login');
    const oldLogin = await post(request, '/v1/auth/token', { client_id: username, client_secret: oldPassword });
    expect(typeof oldLogin.refresh_token).toBe('string');
    setStage('request_verification_email');
    await post(request, '/v1/user/email-verification/request', undefined, oldLogin.access_token);
    setStage('read_verification_email');
    const verification = await mailLink(request, email, 'Verify your Keylo email address', '/account/email-verification');
    setStage('consume_verification_link');
    await accountNavigation(page, verification);
    setStage('verify_email_success_message');
    await expect(page.getByRole('status')).toHaveText('邮箱已验证，可以继续使用账户。');
    setStage('verify_email_fragment_cleanup');
    await browserState(page);
    setStage('load_verification_replay');
    const verificationReplayPage = await page.context().newPage();
    watchRuntime(verificationReplayPage, runtimeErrors, ['/v1/auth/email-verification/confirm']);
    await accountNavigation(verificationReplayPage, verification);
    setStage('verification_replay_result');
    await expect(verificationReplayPage.getByRole('status')).toHaveText('Invalid or expired email verification token');
    setStage('verification_replay_fragment_cleanup');
    await browserState(verificationReplayPage);
    await verificationReplayPage.close();

    setStage('request_password_reset_in_browser');
    await accountNavigation(page, '/account/password-reset');
    await page.getByLabel('邮箱或用户名').fill(email);
    await page.getByRole('button', { name: '发送恢复邮件' }).click();
    await expect(page.getByRole('status')).toHaveText(neutralMessage);
    setStage('read_password_reset_email');
    const reset = await mailLink(request, email, 'Reset your Keylo password', '/account/password-reset');
    setStage('load_password_reset_link');
    const resetPage = await page.context().newPage();
    watchRuntime(resetPage, runtimeErrors, ['/v1/auth/password-reset/confirm']);
    await accountNavigation(resetPage, reset);
    setStage('password_reset_form');
    await expect(resetPage.getByRole('heading', { name: '设置新密码' })).toBeVisible();
    await browserState(resetPage);
    await resetPage.getByLabel('新密码').fill(newPassword);
    await resetPage.getByRole('button', { name: '更新密码' }).click();
    await expect(resetPage.getByRole('status')).toHaveText('密码已更新。请使用新密码登录。');
    await expect(resetPage.getByRole('heading', { name: '发送恢复邮件' })).toBeVisible();
    await resetPage.close();
    setStage('load_password_reset_replay');
    const resetReplayPage = await page.context().newPage();
    watchRuntime(resetReplayPage, runtimeErrors, ['/v1/auth/password-reset/confirm']);
    await accountNavigation(resetReplayPage, reset);
    setStage('password_reset_replay_result');
    await resetReplayPage.getByLabel('新密码').fill(oldPassword);
    await resetReplayPage.getByRole('button', { name: '更新密码' }).click();
    await expect(resetReplayPage.getByRole('status')).toHaveText('Invalid or expired password reset token');
    await browserState(resetReplayPage);
    await resetReplayPage.close();
    setStage('reject_old_password');
    expect((await request.post('/v1/auth/token', { data: { client_id: username, client_secret: oldPassword } })).status()).toBe(401);
    setStage('login_with_new_password');
    const newLogin = await post(request, '/v1/auth/token', { client_id: username, client_secret: newPassword });
    expect(newLogin.password_change_required).toBe(true);
    expect(typeof newLogin.access_token).toBe('string');
    // Password recovery preserves the mandatory next-login password change.
    // The existing Rust integration suite validates that later change separately.
    setStage('reject_revoked_refresh');
    expect((await request.post('/v1/auth/refresh', { data: {
      refresh_token: oldLogin.refresh_token
    } })).status()).toBe(401);
    expect(runtimeErrors).toEqual([]);
  });
});
