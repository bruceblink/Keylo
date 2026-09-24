import React, { useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
// @ts-ignore: CSS side-effect import without type declarations
import './styles.css';

type SetupCheck = {
  key: string;
  label: string;
  ok: boolean;
  required: boolean;
  message: string;
};

type SetupEndpoints = {
  issuer: string;
  jwks_uri: string;
  discovery_uri: string;
  admin_token_endpoint: string;
  user_token_endpoint: string;
  service_token_endpoint: string;
};

type SetupStatus = {
  enabled: boolean;
  completed: boolean;
  environment: string;
  admin_client_id_configured: boolean;
  admin_client_secret_configured: boolean;
  checks: SetupCheck[];
  endpoints: SetupEndpoints;
};

type SetupInitializeResponse = {
  completed: boolean;
  admin_client_id: string;
  endpoints: SetupEndpoints;
};

type ApiError = {
  message?: string;
  error?: string;
};

type AccountMode = 'setup' | 'password-reset' | 'email-verification';

function accountMode(): AccountMode {
  return window.location.pathname.endsWith('/account/password-reset')
    ? 'password-reset'
    : window.location.pathname.endsWith('/account/email-verification')
      ? 'email-verification'
      : 'setup';
}

function takeFragmentToken(): string {
  const fragment = new URLSearchParams(window.location.hash.slice(1));
  const token = fragment.get('token')?.trim() ?? '';
  if (window.location.hash) {
    window.history.replaceState(null, document.title, window.location.pathname);
  }
  return token;
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}

async function readJson<T>(response: Response): Promise<T> {
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = body as ApiError;
    throw new Error(error.message || error.error || `HTTP ${response.status}`);
  }

  return body as T;
}

function App() {
  const mode = accountMode();
  if (mode === 'password-reset') {
    return <PasswordResetPage />;
  }
  if (mode === 'email-verification') {
    return <EmailVerificationPage />;
  }
  return <SetupPage />;
}

function SetupPage() {
  const [adminClientId, setAdminClientId] = useState('');
  const [adminClientSecret, setAdminClientSecret] = useState('');
  const [status, setStatus] = useState<SetupStatus | null>(null);
  const [message, setMessage] = useState('等待状态加载。');
  const [loading, setLoading] = useState(false);

  const requiredFailures = useMemo(
    () => status?.checks.filter((item) => item.required && !item.ok) ?? [],
    [status]
  );
  const setupCompleted = status?.completed === true;
  const adminClientIdConfigured = status?.admin_client_id_configured === true;
  const adminClientSecretConfigured = status?.admin_client_secret_configured === true;
  const canInitialize =
    status !== null &&
    !loading &&
    requiredFailures.length === 0 &&
    (adminClientIdConfigured || adminClientId.trim().length > 0) &&
    (adminClientSecretConfigured || adminClientSecret.trim().length > 0);

  async function loadStatus(nextMessage?: string) {
    setLoading(true);
    setMessage(nextMessage ?? '正在读取安装状态...');
    try {
      const response = await fetch('/setup/status');
      const data = await readJson<SetupStatus>(response);
      setStatus(data);
      if (!data.admin_client_id_configured && !adminClientId.trim()) {
        setAdminClientId('cli-admin-root');
      }
      setMessage(
        nextMessage ??
          (data.completed ? '安装已完成，初始化入口已关闭。' : '状态已更新。')
      );
    } catch (error) {
      setMessage(error instanceof Error ? error.message : '读取状态失败。');
    } finally {
      setLoading(false);
    }
  }

  async function initialize() {
    setLoading(true);
    setMessage('正在初始化...');
    const payload: { admin_client_id?: string; admin_client_secret?: string } = {};
    if (adminClientId.trim()) {
      payload.admin_client_id = adminClientId;
    }
    if (adminClientSecret.trim()) {
      payload.admin_client_secret = adminClientSecret;
    }

    try {
      const response = await fetch('/setup/initialize', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });
      const data = await readJson<SetupInitializeResponse>(response);
      setStatus((current) =>
        current
          ? { ...current, completed: data.completed, endpoints: data.endpoints }
          : current
      );
      setMessage(`初始化完成。Admin Client ID: ${data.admin_client_id}`);
      await loadStatus(`初始化完成。Admin Client ID: ${data.admin_client_id}`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : '初始化失败。');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadStatus();
  }, []);

  return (
    <main className="page">
      <header className="header">
        <div>
          <h1>Keylo Setup</h1>
          <p>首次安装向导用于检查部署依赖、初始化管理客户端，并输出第三方服务接入端点。RSA 密钥缺失时会在服务启动时自动生成并通过 JWKS 发布公钥。</p>
        </div>
        <button className="secondary" onClick={() => void loadStatus()} disabled={loading}>
          刷新状态
        </button>
      </header>

      <div className={setupCompleted ? 'layout status-layout' : 'layout'}>
        <section className="panel">
          <div className="panel-title">
            <h2>环境检查</h2>
            {status ? <span>{status.environment}</span> : null}
          </div>
          <div className="checks">
            {(status?.checks ?? []).map((item) => (
              <div
                className={`check ${item.ok ? 'ok' : ''} ${item.required ? '' : 'optional'}`}
                key={item.key}
              >
                <div className="dot" />
                <div>
                  <div className="label">{item.label}</div>
                  <div className="message">{item.message}</div>
                </div>
                <span className="badge">{item.required ? 'required' : 'optional'}</span>
              </div>
            ))}
          </div>
        </section>

        {setupCompleted ? (
          <section className="panel completed-panel">
            <h2>安装状态</h2>
            <div className="status-mark">已完成</div>
            <p>初始化入口已关闭。后续只能查看当前安装状态和接入端点。</p>
            <p className="status">{message}</p>
          </section>
        ) : (
          <section className="panel">
            <h2>初始化</h2>
            <label htmlFor="admin-client-id">Admin Client ID</label>
            <input
              id="admin-client-id"
              autoComplete="off"
              value={adminClientId}
              placeholder={
                adminClientIdConfigured ? '已从环境配置读取，可留空' : '请输入管理客户端 ID'
              }
              onChange={(event) => setAdminClientId(event.target.value)}
            />
            {adminClientIdConfigured ? (
              <p className="hint ok">
                已检测到环境配置中的 Admin Client ID，初始化时可不填写此项。
              </p>
            ) : (
              <p className="hint">未检测到环境配置中的 Admin Client ID，可使用默认值或输入新的 ID。</p>
            )}

            <label htmlFor="admin-client-secret">Admin Client Secret</label>
            <input
              id="admin-client-secret"
              type="password"
              autoComplete="new-password"
              value={adminClientSecret}
              placeholder={
                adminClientSecretConfigured ? '已从环境配置读取，可留空' : '请输入首次初始化密钥'
              }
              onChange={(event) => setAdminClientSecret(event.target.value)}
            />
            {adminClientSecretConfigured ? (
              <p className="hint ok">
                已检测到环境配置中的 Admin Client Secret，初始化时可不填写此项。
              </p>
            ) : (
              <p className="hint">未检测到环境配置中的 Admin Client Secret，需要在此填写。</p>
            )}

            <div className="actions">
              <button onClick={initialize} disabled={!canInitialize}>
                执行初始化
              </button>
            </div>

            {requiredFailures.length > 0 ? (
              <p className="hint">仍有必需检查未通过，初始化可能失败。请先修复左侧配置。</p>
            ) : null}
            <p className="status">{message}</p>
          </section>
        )}
      </div>

      <section className="panel endpoints">
        <h2>接入端点</h2>
        <pre>{JSON.stringify(status?.endpoints ?? {}, null, 2)}</pre>
      </section>
    </main>
  );
}

function PasswordResetPage() {
  const [identifier, setIdentifier] = useState('');
  const [token, setToken] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const fragmentConsumed = useRef(false);

  useEffect(() => {
    if (fragmentConsumed.current) return;
    fragmentConsumed.current = true;
    setToken(takeFragmentToken());
  }, []);

  async function requestReset(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setMessage('正在提交申请...');
    try {
      await readJson(
        await fetch('/v1/auth/password-reset/request', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ identifier: identifier.trim() })
        })
      );
      setMessage('如果账户可以恢复，邮件会很快送达。请检查收件箱。');
    } catch (error) {
      setMessage(errorMessage(error, '申请失败，请稍后重试。'));
    } finally {
      setLoading(false);
    }
  }

  async function confirmReset(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setMessage('正在更新密码...');
    try {
      await readJson(
        await fetch('/v1/auth/password-reset/confirm', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token, new_password: newPassword })
        })
      );
      setToken('');
      setNewPassword('');
      setMessage('密码已更新。请使用新密码登录。');
    } catch (error) {
      setMessage(errorMessage(error, '链接无效或已过期，请重新申请。'));
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="page account-page">
      <header className="header">
        <div>
          <p className="eyebrow">KEYLO ACCOUNT</p>
          <h1>恢复账户访问</h1>
          <p>使用邮件中的一次性链接设置新的登录密码。</p>
        </div>
      </header>
      <section className="panel recovery-panel">
        {token ? (
          <form onSubmit={(event) => void confirmReset(event)}>
            <h2>设置新密码</h2>
            <label htmlFor="new-password">新密码</label>
            <input
              id="new-password"
              type="password"
              autoComplete="new-password"
              minLength={8}
              required
              value={newPassword}
              onChange={(event) => setNewPassword(event.target.value)}
            />
            <p className="hint">至少 8 个字符，并包含大小写字母、数字和特殊字符。</p>
            <div className="actions">
              <button type="submit" disabled={loading || newPassword.length < 8}>
                更新密码
              </button>
            </div>
          </form>
        ) : (
          <form onSubmit={(event) => void requestReset(event)}>
            <h2>发送恢复邮件</h2>
            <label htmlFor="identifier">邮箱或用户名</label>
            <input
              id="identifier"
              autoComplete="username"
              required
              value={identifier}
              onChange={(event) => setIdentifier(event.target.value)}
            />
            <p className="hint">无论账户是否存在，页面都会显示相同结果。</p>
            <div className="actions">
              <button type="submit" disabled={loading || identifier.trim().length === 0}>
                发送恢复邮件
              </button>
            </div>
          </form>
        )}
        <p className="status" role="status" aria-live="polite">{message}</p>
      </section>
    </main>
  );
}

function EmailVerificationPage() {
  const [token, setToken] = useState('');
  const [message, setMessage] = useState('正在验证邮箱...');
  const fragmentConsumed = useRef(false);

  useEffect(() => {
    if (fragmentConsumed.current) return;
    fragmentConsumed.current = true;
    const nextToken = takeFragmentToken();
    setToken(nextToken);
    if (!nextToken) {
      setMessage('验证链接无效或已过期，请向系统重新申请验证邮件。');
      return;
    }

    void (async () => {
      try {
        await readJson(
          await fetch('/v1/auth/email-verification/confirm', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: nextToken })
          })
        );
        setMessage('邮箱已验证，可以继续使用账户。');
      } catch (error) {
        setMessage(errorMessage(error, '验证链接无效或已过期，请重新申请。'));
      } finally {
        setToken('');
      }
    })();
  }, []);

  return (
    <main className="page account-page">
      <header className="header">
        <div>
          <p className="eyebrow">KEYLO ACCOUNT</p>
          <h1>验证邮箱</h1>
          <p role="status" aria-live="polite">{message}</p>
        </div>
      </header>
      {token ? <div className="loading-mark" aria-hidden="true" /> : null}
    </main>
  );
}

createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
