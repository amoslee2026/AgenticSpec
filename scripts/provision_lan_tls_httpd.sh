#!/usr/bin/env bash
# AgenticSpec LAN 访问：httpd TLS 反向代理一键配置（ADR-007 S6：非环回访问必须经 TLS 反代终止）
# 用法：sudo bash scripts/provision_lan_tls_httpd.sh
#       CERT_FORCE=1 sudo bash scripts/provision_lan_tls_httpd.sh   # 重签证书（如新增网卡/ZeroTier IP 后）
#
# 动作（幂等，可重复执行）：
#   1. 生成自签证书（SAN 含本机全部 IPv4 + localhost）
#   2. 写 /etc/httpd/conf.d/agenticspec-lan.conf：443 → 127.0.0.1:8787
#   3. SELinux 放行 httpd 出站连接；firewalld 放行 https
#   4. 启用 httpd 并端到端验证
#
# 回滚：mv /etc/httpd/conf.d/agenticspec-lan.conf /tmp/ && systemctl restart httpd
# 前提：agenticspec-api systemd user 服务已运行（unit 内已设 AUTH_TRUSTED_PROXY=1）。
set -euo pipefail

CONF=/etc/httpd/conf.d/agenticspec-lan.conf
TLSDIR=/etc/pki/tls/private/agenticspec
CERT=$TLSDIR/lan.crt
KEY=$TLSDIR/lan.key

if [[ $EUID -ne 0 ]]; then
  echo "错误：请用 sudo 运行" >&2
  exit 1
fi
command -v httpd >/dev/null || { echo "错误：缺少 httpd（dnf install httpd mod_ssl）" >&2; exit 1; }
[[ -f /etc/httpd/conf.d/ssl.conf ]] || { echo "错误：缺 mod_ssl（dnf install mod_ssl）" >&2; exit 1; }

# 1) 自签证书（SAN=全部 IPv4；ZeroTier 装好后 zt 接口 IP 也在 hostname -I 里，重跑加 CERT_FORCE=1 即可）
mapfile -t ALL_IPS < <(hostname -I | tr ' ' '\n' | sed '/^$/d')
if [[ ! -s $CERT || ${CERT_FORCE:-0} = 1 ]]; then
  install -d -m 700 "$TLSDIR"
  SAN="DNS:localhost"
  for ip in "${ALL_IPS[@]}"; do SAN+=",IP:$ip"; done
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$KEY" -out "$CERT" -subj "/CN=agenticspec-lan" \
    -addext "subjectAltName=$SAN" 2>/dev/null
  chmod 600 "$KEY"
  echo "证书已生成：$CERT（SAN: $SAN）"
else
  echo "证书已存在：$CERT（CERT_FORCE=1 可重签）"
fi

# 2) 反代配置（注意：不再写 Listen 443，ssl.conf 已有，重复会 Address already in use）
cat > "$CONF" <<'EOF'
# AgenticSpec LAN 访问（由 scripts/provision_lan_tls_httpd.sh 生成，勿手工改；回滚见脚本头注释）
<VirtualHost *:443>
    ServerName agenticspec-lan
    SSLEngine on
    SSLCertificateFile    /etc/pki/tls/private/agenticspec/lan.crt
    SSLCertificateKeyFile /etc/pki/tls/private/agenticspec/lan.key
    ProxyPreserveHost On
    ProxyPass        / http://127.0.0.1:8787/
    ProxyPassReverse / http://127.0.0.1:8787/
    RequestHeader set X-Forwarded-Proto "https"
</VirtualHost>
EOF
echo "反代配置已写入：$CONF"

# 3) SELinux / firewalld
if [[ $(getenforce) != "Disabled" ]]; then
  setsebool -P httpd_can_network_connect on
  echo "SELinux：httpd_can_network_connect=on"
fi
if systemctl is-active --quiet firewalld; then
  firewall-cmd --permanent --add-service=https >/dev/null
  firewall-cmd --reload >/dev/null
  echo "firewalld：https 已放行"
else
  echo "提示：firewalld 未运行，跳过放行（如用其他防火墙请自行放行 443/tcp）"
fi

# 4) 启用 + 验证
httpd -t
systemctl enable --now httpd
systemctl restart httpd
sleep 1
code_local=$(curl -ks -o /dev/null -w '%{http_code}' https://127.0.0.1/healthz)
echo "本机  https://127.0.0.1/healthz → $code_local"
code_lan=$(curl -ks -o /dev/null -w '%{http_code}' "https://${ALL_IPS[0]}/")
echo "LAN   https://${ALL_IPS[0]}/ → $code_lan"
if [[ $code_local != 200 || $code_lan != 200 ]]; then
  echo "验证失败，请查：journalctl -u httpd -n 50" >&2
  exit 1
fi
echo "完成：浏览器访问 https://${ALL_IPS[0]}/（自签证书，首次需手动信任）"
