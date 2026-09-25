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
  const [copied, setCopied] = useState(false);
  const [pasteOut, setPasteOut] = useState("");
  const [parseState, setParseState] = useState<"pending" | "ok" | "failed">("pending");

  /** 命令输出 → 自动提取 FP 指纹行与 SSHSIG 签名块，回填两个输入框。 */
  function onPasteOutput(text: string) {
    setPasteOut(text);
    const fp = text.match(/^FP\s+(\S+)/m)?.[1];
    const sig = text.match(/-----BEGIN SSH SIGNATURE-----[\s\S]*?-----END SSH SIGNATURE-----/)?.[0];
    if (fp) setFingerprint(fp);
    if (sig) setSignature(sig);
    setParseState(fp && sig ? "ok" : "failed");
  }

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
      if (!nonce) {
        setError("挑战已缺失或过期：请先点「获取挑战」重新取 nonce 再签名。");
      }
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

  const nonceText = nonce ?? "<页面上的nonce>";
  // 一条命令完成：写 nonce 文件 → 签名 → 输出两段（FP 指纹行 + SSHSIG 签名块），页面自动拆分
  const winOneCmd = `$f="$env:TEMP\\agenticspec-nonce.txt"; [IO.File]::WriteAllText($f, "${nonceText}"); ssh-keygen -Y sign -f $env:USERPROFILE\\.ssh\\id_ed25519 -n agenticspec@auth $f | Out-Null; $fp=((ssh-keygen -lf $env:USERPROFILE\\.ssh\\id_ed25519.pub) -split ' ')[1]; Write-Output "FP $fp"; Get-Content "$f.sig" -Raw`;
  const cliSign = `uv run agenticspec auth sign --login --nonce ${nonceText}`;

  async function copyCmd() {
    if (!nonce) return;
    try {
      await navigator.clipboard.writeText(winOneCmd);
    } catch {
      /* 剪贴板不可用（权限/非安全上下文）：用户手动框选复制 */
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

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
                <span className="step-no">2</span> 在本机签名（复制命令即可，浏览器不接触私钥）
              </div>
              {nonce ? (
                <div className="cmd-wrap">
                  <div className="cmd-hint">{winOneCmd}</div>
                  <div className="cmd-actions">
                    <button className="ghost" onClick={() => void copyCmd()}>复制命令</button>
                    {copied ? <span className="cmd-copied">已复制，去 PowerShell 粘贴运行</span> : null}
                  </div>
                </div>
              ) : (
                <div className="step-note">先点上方「获取挑战」，这里会生成一条带 token 的签名命令。</div>
              )}
              <div className="step-note">
                复制上面一条命令到 <b>Windows PowerShell</b> 回车即完成签名（Win10/11 内置 OpenSSH，
                无需安装）：终端会输出两段——<code>FP SHA256:…</code> 指纹行与
                <code>-----BEGIN…END SSH SIGNATURE-----</code> 签名块，整段贴到第 3 步即可自动拆分。
                已装 AgenticSpec CLI 时可改用 <code>{cliSign}</code>。
              </div>
              <label className="field">
                <span>公钥指纹（上条命令运行后终端输出的 SHA256:…）</span>
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
                <span className="step-no">3</span> 把命令输出贴回来，自动拆分后登录
              </div>
              <label className="field">
                <span>粘贴上一步命令的完整输出（一段搞定）</span>
                <textarea
                  rows={5}
                  placeholder={"FP SHA256:…\n-----BEGIN SSH SIGNATURE-----\n…\n-----END SSH SIGNATURE-----"}
                  value={pasteOut}
                  onChange={(e) => onPasteOutput(e.target.value)}
                />
              </label>
              <div className="step-note">
                自动识别 <code>FP SHA256:…</code> 行与 <code>-----BEGIN…END SSH SIGNATURE-----</code> 块；
                识别失败时下方会展开手动输入。
              </div>
              {parsed ? (
                <div className="notice ok">
                  已自动识别指纹 <code>{fingerprint}</code> 与 SSHSIG 签名，点「登录」即可。
                  <button className="ghost" onClick={() => setParsed(false)}>手动修改</button>
                </div>
              ) : (
                <>
                  <label className="field">
                    <span>公钥指纹（手填时只复制 SHA256:… 那段即可）</span>
                    <input
                      type="text"
                      placeholder="SHA256:…"
                      value={fingerprint}
                      onChange={(e) => setFingerprint(e.target.value)}
                    />
                  </label>
                  <label className="field">
                    <span>SSHSIG 签名</span>
                    <textarea
                      rows={4}
                      placeholder={"-----BEGIN SSH SIGNATURE-----\n…\n-----END SSH SIGNATURE-----"}
                      value={signature}
                      onChange={(e) => setSignature(e.target.value)}
                    />
                  </label>
                </>
              )}
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
              <p>本系统无密码，身份唯一根为 SSH 公钥（ADR-007）：浏览器永不接触私钥，由你本机用私钥对一次性挑战签名后，再把签名粘贴回来换取长期会话（1 年滑动续期）。</p>
              <ol>
                <li>
                  <b>前提</b>：登录机持有与系统注册身份一致的 SSH 私钥（推荐 Ed25519，无则先生成
                  <code>ssh-keygen -t ed25519</code> 并让管理员注册公钥）。签名用系统内置 OpenSSH，<b>无需安装 AgenticSpec 软件或仓库</b>；
                  如已装 AgenticSpec CLI，私钥查找顺序为 <code>$AGENTICSPEC_SSH_KEY</code> → <code>~/.ssh/id_ed25519</code> → <code>~/.ssh/id_rsa</code>。
                </li>
                <li>
                  <b>获取挑战</b>：点上方「获取挑战」按钮，页面显示一次性 nonce（有效期 120s，过期点「换一个」重取）。
                </li>
                <li>
                  <b>本机签名</b>：回到步骤 2 复制那条已带 token 的单行命令，到 PowerShell / Bash 粘贴回车即可。
                  Win10/11 与 Linux 都内置 OpenSSH，<b>无需安装任何东西</b>。终端会输出
                  <code>FP SHA256:…</code> 指纹行与 <code>-----BEGIN…END SSH SIGNATURE-----</code> 签名块两段，
                  整段复制贴回第 3 步自动拆分。已装 AgenticSpec CLI 时可改用 <code>{cliSign}</code>。
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
                <p>常见问题（状态码为登录接口实际返回）：</p>
                <ul>
                  <li>找不到私钥：先 <code>ssh-keygen -t ed25519</code> 生成密钥对，并把公钥让管理员在「用户管理」注册。</li>
                  <li><code>403</code> 公钥未注册或其属主已禁用（S8）：公钥匹配不到可用账号，联系管理员添加/启用后重试。</li>
                  <li><code>401</code> 验签失败（SignatureVerificationError）：用错私钥（指纹与签名不配对）、<code>.sig</code> 未整块复制、或 nonce 写入文件时带了换行/空格。验签失败<strong>不消耗挑战</strong>，120s 内可直接重试。时钟时间窗（±300s）只约束 CLI/API 请求签名（X-Timestamp），与登录无关。</li>
                  <li><code>401</code> 挑战未知或已过期：nonce 一次性、TTL 120s，重新点「获取挑战」再签。</li>
                  <li>系统无任何 <code>active</code> admin（fail-closed）：登录无法匹配到用户，管理员先执行 <code>agenticspec auth bootstrap</code> 自举。</li>
                </ul>
              </div>
            </div>
          </details>
          <div className="login-foot">
            会话 1 年滑动续期 · 无密码体系，身份唯一根为 SSH 公钥（ADR-007）
          </div>
          {done ? <div className="notice ok">登录成功，正在进入…</div> : null}
        </div>
      </div>
    </div>
  );
}
