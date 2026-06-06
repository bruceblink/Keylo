import React, { useEffect, useMemo, useState } from 'react';
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

async function readJson<T>(response: Response): Promise<T> {
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = body as ApiError;
    throw new Error(error.message || error.error || `HTTP ${response.status}`);
  }

  return body as T;
}

function App() {
  const [adminClientId, setAdminClientId] = useState('cli-admin-root');
  const [adminClientSecret, setAdminClientSecret] = useState('');
  const [status, setStatus] = useState<SetupStatus | null>(null);
  const [message, setMessage] = useState('等待状态加载。');
  const [loading, setLoading] = useState(false);

  const requiredFailures = useMemo(
    () => status?.checks.filter((item) => item.required && !item.ok) ?? [],
    [status]
  );
  const setupCompleted = status?.completed === true;
  const adminClientSecretConfigured = status?.admin_client_secret_configured === true;
  const canInitialize =
    !loading &&
    adminClientId.trim().length > 0 &&
    (adminClientSecretConfigured || adminClientSecret.trim().length > 0);

  async function loadStatus(nextMessage?: string) {
    setLoading(true);
    setMessage(nextMessage ?? '正在读取安装状态...');
    try {
      const response = await fetch('/setup/status');
      const data = await readJson<SetupStatus>(response);
      setStatus(data);
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
    const payload: { admin_client_id: string; admin_client_secret?: string } = {
      admin_client_id: adminClientId
    };
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
              onChange={(event) => setAdminClientId(event.target.value)}
            />

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

createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
