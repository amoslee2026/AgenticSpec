import { useState } from "react";
import { authApi } from "../api/endpoints";
import { ApiError } from "../api/client";
import { useAuth } from "./AuthContext";

/** 登录页（REQ-M10-F02 / user_manual §5.1）：SSH 挑战-响应，本地 CLI 签名粘贴。 */
export function LoginPage() {
  const { refresh } = useAuth();
  const [nonce, setNonce] = useState<string | null>(null);
  const [fingerprint, setFingerprint] = useState("");
  const [signature, setSignature] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  async function fetchChallenge() {
    setBusy(true);
    setError(null);
    try {
      const challenge = await authApi.challenge();
      setNonce(challenge.nonce);
      setSignature("");
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc));
    } finally {
      setBusy(false);
    }
  }

  async function submit() {
    if (!nonce || !fingerprint.trim() || !signature.trim()) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await authApi.login(fingerprint.trim(), nonce, signature.trim());
      setDone(true);
      await refresh();
    } catch (exc) {
      setError(exc instanceof ApiError ? exc.message : String(exc));
    } finally {
      setBusy(false);
    }
  }

  const command = nonce
    ? `uv run agenticspec auth sign --login --nonce ${nonce}`
    : "uv run agenticspec auth sign --login --nonce <nonce>";

  return (
    <div className="login-wrap">
      <div className="card login-card">
        <div className="card-head">
          <h2>登录 AgenticSpec</h2>
          <span className="chip">SSH 挑战-响应</span>
        </div>
        <div className="card-body">
          {error ? <div className="notice error">{error}</div> : null}
          <div className="login-steps">
            <div className="login-step">
              <div className="step-title">
                <span className="step-no">1</span> 获取一次性挑战（TTL 120s）
              </div>
              {nonce ? (
                <div className="nonce-box">
                  <span>{nonce}</span>
                  <button className="ghost" onClick={() => void fetchChallenge()} disabled={busy}>
                    换一个
                  </button>
                </div>
              ) : (
                <button className="primary" onClick={() => void fetchChallenge()} disabled={busy}>
                  获取挑战
                </button>
              )}
            </div>

            <div className="login-step">
              <div className="step-title">
                <span className="step-no">2</span> 在本机用 SSH 私钥签名（浏览器不接触私钥）
              </div>
              <div className="cmd-hint">{command}</div>
              <label className="field">
                <span>公钥指纹（ssh-keygen -lf ~/.ssh/id_ed25519.pub 的输出）</span>
                <input
                  type="text"
                  placeholder="SHA256:…"
                  value={fingerprint}
                  onChange={(e) => setFingerprint(e.target.value)}
                />
              </label>
            </div>

            <div className="login-step">
              <div className="step-title">
                <span className="step-no">3</span> 粘贴签名并登录
              </div>
              <label className="field">
                <span>SSHSIG 签名（base64 或 armor 均可）</span>
                <textarea
                  rows={4}
                  placeholder={"-----BEGIN SSH SIGNATURE-----\n…\n-----END SSH SIGNATURE-----"}
                  value={signature}
                  onChange={(e) => setSignature(e.target.value)}
                />
              </label>
              <div className="row end">
                <button
                  className="primary"
                  disabled={busy || !nonce || !fingerprint.trim() || !signature.trim()}
                  onClick={() => void submit()}
                >
                  登录
                </button>
              </div>
            </div>
          </div>
          <details className="login-help">
            <summary>签名登录详细说明（首次使用必读）</summary>
            <div className="login-help-body">
              <p>本系统无密码，身份唯一根为 SSH 公钥（ADR-007）：浏览器永不接触私钥，由你本机用私钥对一次性挑战签名后，再把签名粘贴回来换取 8 小时会话。</p>
              <ol>
                <li>
                  <b>前提</b>：登录机持有与系统注册身份一致的 SSH 私钥（推荐 Ed25519），且能运行 CLI。私钥查找顺序：
                  <code>$AGENTICSPEC_SSH_KEY</code> → <code>~/.ssh/id_ed25519</code> → <code>~/.ssh/id_rsa</code>；
                  加密私钥的口令经环境变量 <code>AGENTICSPEC_SSH_KEY_PASSPHRASE</code> 传入。
                </li>
                <li>
                  <b>获取挑战</b>：点上方「获取挑战」按钮，页面显示一次性 nonce（有效期 120s，过期点「换一个」重取）。
                </li>
                <li>
                  <b>本机签名</b>：在登录机的终端里运行（在 AgenticSpec 仓库目录下）：
                  <div className="cmd-hint">{command}</div>
                  命令输出以 <code>-----BEGIN SSH SIGNATURE-----</code> 开头的签名块。
                </li>
                <li>
                  <b>取公钥指纹</b>：另开一条命令 <code>ssh-keygen -lf ~/.ssh/id_ed25519.pub</code>，
                  复制输出中形如 <code>SHA256:…</code> 的那段（与签名所用私钥配对）。
                </li>
                <li>
                  <b>粘贴登录</b>：把指纹与完整签名块分别粘贴到上方输入框，点「登录」。
                </li>
              </ol>
              <div className="login-help-notes">
                <p>常见问题：</p>
                <ul>
                  <li>找不到私钥 / 提示无可用 SSH 私钥：先 <code>ssh-keygen -t ed25519</code> 生成并注册公钥（管理员在「用户管理」添加）。</li>
                  <li>验签失败（SignatureVerificationError）：公钥未被注册，或本机时钟偏移超过 ±300s（超前 &gt;30s 同样拒绝）——先同步 NTP 再重试。</li>
                  <li>nonce 已使用（重放拒绝）：签名只能用一次，重新获取挑战再签。</li>
                  <li>系统无任何 <code>active</code> admin 时全部请求 401（fail-closed）：管理员先执行 <code>agenticspec auth bootstrap</code> 自举。</li>
                </ul>
              </div>
            </div>
          </details>
          <div className="login-foot">
            会话 8 小时滑动续期 · 无密码体系，身份唯一根为 SSH 公钥（ADR-007）
          </div>
          {done ? <div className="notice ok">登录成功，正在进入…</div> : null}
        </div>
      </div>
    </div>
  );
}
