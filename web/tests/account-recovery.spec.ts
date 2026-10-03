import { expect, test as base } from '@playwright/test';

const resetRoute = '/setup/account/password-reset';
const verificationRoute = '/setup/account/email-verification';
const endpoints = {
  issuer: 'https://keylo.example.test',
  jwks_uri: 'https://keylo.example.test/.well-known/jwks.json',
  discovery_uri: 'https://keylo.example.test/.well-known/keylo-configuration',
  admin_token_endpoint: 'https://keylo.example.test/v1/admin/token',
  user_token_endpoint: 'https://keylo.example.test/v1/auth/token',
  service_token_endpoint: 'https://keylo.example.test/v1/service/token'
};

const test = base.extend<{ runtimeErrors: string[] }>({
  runtimeErrors: [
    async ({ page }, use) => {
      const errors: string[] = [];
      page.on('pageerror', (error) => errors.push(error.message));
      await use(errors);
      expect(errors).toEqual([]);
    },
    { auto: true }
  ]
});

test('password recovery request uses the account-neutral success message', async ({ page }) => {
  await page.route('**/v1/auth/password-reset/request', async (route) => {
    await route.fulfill({ json: { message: 'If the account can be recovered, a message will be sent' } });
  });
  await page.goto(resetRoute);

  await page.getByLabel('邮箱或用户名').fill('unknown-account@example.test');
  await page.getByRole('button', { name: '发送恢复邮件' }).click();

  await expect(page.getByRole('status')).toHaveText('如果账户可以恢复，邮件会很快送达。请检查收件箱。');
});

test('password reset consumes a fragment once, clears it, and reports success', async ({ page }) => {
  let requestBody: unknown;
  await page.route('**/v1/auth/password-reset/confirm', async (route) => {
    requestBody = route.request().postDataJSON();
    await route.fulfill({ json: { message: 'Password updated' } });
  });
  await page.goto(`${resetRoute}#token=reset-token-for-test`);

  await expect(page).toHaveURL(`http://127.0.0.1:5174${resetRoute}`);
  await expect(page.getByRole('heading', { name: '设置新密码' })).toBeVisible();
  await page.getByLabel('新密码').fill('Valid-Test-Password-2026!');
  await page.getByRole('button', { name: '更新密码' }).click();

  await expect(page.getByRole('status')).toHaveText('密码已更新。请使用新密码登录。');
  expect(requestBody).toEqual({
    token: 'reset-token-for-test',
    new_password: 'Valid-Test-Password-2026!'
  });
  expect(await page.evaluate(() => ({
    hash: window.location.hash,
    search: window.location.search,
    local: window.localStorage.length,
    session: window.sessionStorage.length
  }))).toEqual({ hash: '', search: '', local: 0, session: 0 });
  await expect(page.locator('body')).not.toContainText('reset-token-for-test');
});

test('password reset presents the API error for an invalid token', async ({ page }) => {
  await page.route('**/v1/auth/password-reset/confirm', async (route) => {
    await route.fulfill({
      status: 400,
      json: { message: 'Invalid or expired password reset token' }
    });
  });
  await page.goto(`${resetRoute}#token=expired-token-for-test`);
  await page.getByLabel('新密码').fill('Valid-Test-Password-2026!');
  await page.getByRole('button', { name: '更新密码' }).click();

  await expect(page.getByRole('status')).toHaveText('Invalid or expired password reset token');
});

test('email verification posts once and removes the token fragment', async ({ page }) => {
  let requests = 0;
  let requestBody: unknown;
  await page.route('**/v1/auth/email-verification/confirm', async (route) => {
    requests += 1;
    requestBody = route.request().postDataJSON();
    await route.fulfill({ json: { message: 'Email verified' } });
  });
  await page.goto(`${verificationRoute}#token=verification-token-for-test`);

  await expect(page.getByRole('status')).toHaveText('邮箱已验证，可以继续使用账户。');
  await expect(page).toHaveURL(`http://127.0.0.1:5174${verificationRoute}`);
  expect(requests).toBe(1);
  expect(requestBody).toEqual({ token: 'verification-token-for-test' });
  expect(await page.evaluate(() => ({
    hash: window.location.hash,
    search: window.location.search,
    local: window.localStorage.length,
    session: window.sessionStorage.length
  }))).toEqual({ hash: '', search: '', local: 0, session: 0 });
});

test('email verification displays API errors and handles a missing fragment without a request', async ({ page }) => {
  let requests = 0;
  await page.route('**/v1/auth/email-verification/confirm', async (route) => {
    requests += 1;
    await route.fulfill({
      status: 400,
      json: { message: 'Invalid or expired email verification token' }
    });
  });
  await page.goto(`${verificationRoute}#token=expired-token-for-test`);
  await expect(page.getByRole('status')).toHaveText('Invalid or expired email verification token');
  expect(requests).toBe(1);

  await page.goto(verificationRoute);
  await expect(page.getByRole('status')).toHaveText(
    '验证链接无效或已过期，请向系统重新申请验证邮件。'
  );
  expect(requests).toBe(1);
});

test('password recovery page fits desktop and 390 by 844 mobile viewports', async ({ page }) => {
  await page.goto(resetRoute);
  await expect(page.getByRole('heading', { name: '恢复账户访问' })).toBeVisible();

  const desktop = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    content: document.documentElement.scrollWidth
  }));
  expect(desktop.content).toBeLessThanOrEqual(desktop.viewport);

  await page.setViewportSize({ width: 390, height: 844 });
  const mobile = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    content: document.documentElement.scrollWidth
  }));
  expect(mobile.content).toBeLessThanOrEqual(mobile.viewport);
});

test('shared frontend shell continues to render the setup status page', async ({ page }) => {
  await page.route('**/setup/status', async (route) => {
    await route.fulfill({
      json: {
        enabled: true,
        completed: true,
        environment: 'test',
        admin_client_id_configured: true,
        admin_client_secret_configured: true,
        checks: [],
        endpoints
      }
    });
  });
  await page.goto('/setup/');

  await expect(page.getByRole('heading', { name: 'Keylo Setup' })).toBeVisible();
  await expect(page.getByText('已完成', { exact: true })).toBeVisible();
});
