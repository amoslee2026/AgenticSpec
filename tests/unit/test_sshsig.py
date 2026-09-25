"""M10 SSHSIG 单测（S2/S11；`ssh-keygen -Y sign` 互操作）。

覆盖：帧解析（armor / 裸 base64 / 二进制）、被签名数据构造、Ed25519 与 RSA（PSS 与
PKCS#1 v1.5）验签、namespace / 哈希算法 / 曲线 / 强度的拒绝路径、指纹与
``ssh-keygen -lf`` 一致、S2 载荷公式（query 参与签名）。

**互操作是硬验收**：用本机 ``ssh-keygen`` 生成密钥并签名，本模块的验签器必须通过
（反向亦验：本模块签名 → ``ssh-keygen -Y verify``）；``ssh-keygen`` 不可用时该组用例 skip。
"""

from __future__ import annotations

import base64
import hashlib
import shutil
import struct
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

from agenticspec.auth import sessions, signing, sshsig
from agenticspec.auth.errors import SignatureFormatError, SignatureVerificationError

SSH_KEYGEN = shutil.which("ssh-keygen")
needs_ssh_keygen = pytest.mark.skipif(SSH_KEYGEN is None, reason="需要本机 ssh-keygen")

MESSAGE = b'GET\n/api/v1/docs?limit=5&expected_version=7\n' + b"0" * 64 + b"\n2026-09-16T00:00:00Z\nnonce-x\n"


def _frame(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def _ssh_blob(public_key: ed25519.Ed25519PublicKey | rsa.RSAPublicKey) -> bytes:
    line = public_key.public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )
    return base64.b64decode(line.split()[1])


def _build_blob(
    public_blob: bytes,
    signature_algorithm: str,
    signature: bytes,
    *,
    namespace: str = sshsig.NAMESPACE,
    hash_algorithm: str = "sha512",
    reserved: bytes = b"",
    trailing: bytes = b"",
) -> bytes:
    """手工拼 SSHSIG 帧（用于构造畸形帧与算法策略用例）。"""
    signature_field = _frame(signature_algorithm.encode()) + _frame(signature)
    return (
        b"SSHSIG"
        + struct.pack(">I", 1)
        + _frame(public_blob)
        + _frame(namespace.encode())
        + _frame(reserved)
        + _frame(hash_algorithm.encode())
        + _frame(signature_field)
        + trailing
    )


def _sign_ed25519(key: ed25519.Ed25519PrivateKey, message: bytes, **kwargs: object) -> bytes:
    blob = _build_blob(_ssh_blob(key.public_key()), "ssh-ed25519", b"\x00" * 64, **kwargs)  # type: ignore[arg-type]
    sig = sshsig.parse_sshsig(blob)
    data = sshsig.signed_data(sig, message)
    return _build_blob(_ssh_blob(key.public_key()), "ssh-ed25519", key.sign(data), **kwargs)  # type: ignore[arg-type]


def _sign_rsa(
    key: rsa.RSAPrivateKey,
    message: bytes,
    *,
    scheme: object,
    hash_cls: object = hashes.SHA512,
    _hash_name: str = "sha512",
) -> bytes:
    digest = hashlib.new(_hash_name, message).digest()
    data = b"SSHSIG" + _frame(sshsig.NAMESPACE.encode()) + _frame(b"") + _frame(_hash_name.encode()) + _frame(digest)
    signature = key.sign(data, scheme, hash_cls())  # type: ignore[operator]
    return _build_blob(
        _ssh_blob(key.public_key()), f"rsa-sha2-{hash_cls.digest_size * 8}", signature,  # type: ignore[attr-defined]
        hash_algorithm=_hash_name,
    )


# --------------------------------------------------------------------- 帧解析


def test_parse_sshsig_accepts_armor_base64_and_binary() -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    blob = _sign_ed25519(key, MESSAGE)
    line = signing.public_key_line(key)

    assert sshsig.dearmor(sshsig.armor(blob)) == blob
    # 三种线上形态：armor（文件）、单行 base64（HTTP 头）、二进制
    for encoded in (sshsig.armor(blob), base64.b64encode(blob).decode(), blob):
        parsed = sshsig.parse_sshsig(encoded)
        assert parsed.namespace == sshsig.NAMESPACE
        assert parsed.hash_algorithm == "sha512"
        assert parsed.key_type == "ssh-ed25519"
        assert parsed.public_key_blob == _ssh_blob(key.public_key())
        sshsig.verify_sshsig(line, encoded, MESSAGE)


def test_armor_matches_openssh_shape() -> None:
    blob = _sign_ed25519(ed25519.Ed25519PrivateKey.generate(), MESSAGE)
    armored = sshsig.armor(blob)
    lines = armored.strip().splitlines()
    assert lines[0] == "-----BEGIN SSH SIGNATURE-----"
    assert lines[-1] == "-----END SSH SIGNATURE-----"
    assert all(len(line) <= 70 for line in lines[1:-1])
    # 折行丢失（HTTP 头场景）仍可解
    assert sshsig.dearmor("".join(lines)) == blob


@pytest.mark.parametrize(
    "bad, reason",
    [
        (b"", "empty_signature"),
        (b"not-base64!!!", "bad_base64"),
        (base64.b64encode(b"NOTSSHSIG").decode(), "bad_magic"),
    ],
)
def test_dearmor_rejects_garbage(bad: bytes, reason: str) -> None:
    with pytest.raises(SignatureFormatError) as excinfo:
        sshsig.dearmor(bad)
    assert excinfo.value.reason == reason
    assert excinfo.value.status_code == 401


def test_parse_rejects_trailing_bytes_and_bad_version() -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    blob = _sign_ed25519(key, MESSAGE)
    with pytest.raises(SignatureFormatError) as excinfo:
        sshsig.parse_sshsig(blob + b"\x00")
    assert excinfo.value.reason == "trailing_bytes"

    with pytest.raises(SignatureFormatError) as excinfo:
        sshsig.parse_sshsig(b"SSHSIG" + struct.pack(">I", 2) + blob[10:])
    assert excinfo.value.reason == "unsupported_version"

    truncated = blob[: len(blob) // 2]
    with pytest.raises(SignatureFormatError) as excinfo:
        sshsig.parse_sshsig(truncated)
    assert excinfo.value.reason in ("truncated", "bad_base64")


def test_signed_data_includes_namespace_reserved_and_hash() -> None:
    sig = sshsig.SshSig(
        version=1,
        public_key_blob=b"\x00" * 4,
        key_type="ssh-ed25519",
        namespace="demo@ns",
        reserved=b"",
        hash_algorithm="sha256",
        signature_algorithm="ssh-ed25519",
        signature=b"\x00" * 64,
    )
    expected = (
        b"SSHSIG"
        + _frame(b"demo@ns")
        + _frame(b"")
        + _frame(b"sha256")
        + _frame(hashlib.sha256(MESSAGE).digest())
    )
    assert sshsig.signed_data(sig, MESSAGE) == expected


# ------------------------------------------------------------------ 验签策略


def test_verify_ed25519_roundtrip_and_tamper_detection() -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    line = signing.public_key_line(key)
    blob = _sign_ed25519(key, MESSAGE)

    assert sshsig.verify_sshsig(line, blob, MESSAGE).key_type == "ssh-ed25519"
    with pytest.raises(SignatureVerificationError) as excinfo:
        sshsig.verify_sshsig(line, blob, MESSAGE + b"tampered")
    assert excinfo.value.reason == "bad_signature"

    # 换一把钥匙（登记公钥与签名公钥不一致）→ 明确拒绝
    other = signing.public_key_line(ed25519.Ed25519PrivateKey.generate())
    with pytest.raises(SignatureVerificationError) as excinfo:
        sshsig.verify_sshsig(other, blob, MESSAGE)
    assert excinfo.value.reason == "public_key_mismatch"


def test_verify_rejects_wrong_namespace() -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    line = signing.public_key_line(key)
    blob = _sign_ed25519(key, MESSAGE, namespace="someone-else@ns")
    with pytest.raises(SignatureFormatError) as excinfo:
        sshsig.verify_sshsig(line, blob, MESSAGE)
    assert excinfo.value.reason == "namespace_mismatch"


def test_verify_rejects_unsupported_hash_and_key_types() -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    line = signing.public_key_line(key)
    with pytest.raises(SignatureFormatError) as excinfo:
        sshsig.parse_sshsig(
            _build_blob(_ssh_blob(key.public_key()), "ssh-ed25519", b"\x00" * 64, hash_algorithm="sha1")
        )
    assert excinfo.value.reason == "unsupported_hash_algorithm"

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ecdsa_blob = _build_blob(_ssh_blob(rsa_key.public_key()), "ecdsa-sha2-nistp256", b"\x00" * 64)
    with pytest.raises(SignatureFormatError) as excinfo:
        sshsig.verify_sshsig(signing.public_key_line(rsa_key), ecdsa_blob, MESSAGE)
    assert excinfo.value.reason == "unsupported_signature_algorithm"


def test_verify_rsa_accepts_pss_and_legacy_pkcs1v15() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    line = signing.public_key_line(key)

    pss = _sign_rsa(key, MESSAGE, scheme=padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=64))
    assert sshsig.verify_sshsig(line, pss, MESSAGE).signature_algorithm == "rsa-sha2-512"

    legacy = _sign_rsa(key, MESSAGE, scheme=padding.PKCS1v15())
    assert sshsig.verify_sshsig(line, legacy, MESSAGE).signature_algorithm == "rsa-sha2-512"

    # 严格 PSS 模式（AUTH_RSA_REQUIRE_PSS=1）下拒绝 v1.5
    with pytest.raises(SignatureVerificationError):
        sshsig.verify_sshsig(line, legacy, MESSAGE, require_pss=True)
    with pytest.raises(SignatureVerificationError):
        sshsig.verify_sshsig(line, pss, MESSAGE + b"x", require_pss=True)


def test_verify_rsa_rejects_sha1_and_algorithm_mismatch() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    line = signing.public_key_line(key)
    blob = _ssh_blob(key.public_key())

    # 旧 ssh-rsa（SHA-1）签名算法：直接拒绝（ADR-007 §1）
    with pytest.raises(SignatureFormatError) as excinfo:
        sshsig.verify_sshsig(line, _build_blob(blob, "ssh-rsa", b"\x00" * 384), MESSAGE)
    assert excinfo.value.reason == "unsupported_signature_algorithm"

    # sig_alg=rsa-sha2-512 却声明 sha256 → 不一致即拒（不留混淆面）
    mismatch = _build_blob(
        blob, "rsa-sha2-512", b"\x00" * 384, hash_algorithm="sha256"
    )
    with pytest.raises(SignatureFormatError) as excinfo:
        sshsig.verify_sshsig(line, mismatch, MESSAGE)
    assert excinfo.value.reason == "hash_algorithm_mismatch"


def test_validate_public_key_rejects_weak_rsa() -> None:
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    with pytest.raises(SignatureFormatError) as excinfo:
        sshsig.validate_public_key(signing.public_key_line(weak))
    assert excinfo.value.reason == "weak_key"


# ------------------------------------------------------------------ 公钥与指纹


def test_fingerprint_and_key_type() -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    line = signing.public_key_line(key)
    digest = hashlib.sha256(_ssh_blob(key.public_key())).digest()
    expected = "SHA256:" + base64.b64encode(digest).decode().rstrip("=")

    assert signing.fingerprint(line) == expected
    assert expected == sshsig.fingerprint_of_blob(_ssh_blob(key.public_key()))
    assert signing.normalize_key_id(expected.removeprefix("SHA256:")) == expected
    # ssh-keygen -lf 整行输出（尾随位数/注释）只取指纹段；首尾空白容忍
    assert signing.normalize_key_id(f"{expected} user@host") == expected
    assert signing.normalize_key_id(f"256 {expected} user@host") == expected
    assert signing.normalize_key_id(f"  {expected}  256 user@host  ") == expected
    assert signing.normalize_key_id("") == signing.KEY_ID_PREFIX
    assert signing.key_type_for(line) == "ssh-ed25519"

    rsa_line = signing.public_key_line(rsa.generate_private_key(public_exponent=65537, key_size=3072))
    assert signing.key_type_for(rsa_line) == "rsa-sha2-512"


def test_login_bad_signature_diagnosis_key_mismatch() -> None:
    """签名帧内公钥指纹 ≠ 登记指纹（用错私钥）→ 展示真实 signer 指纹。"""
    signer = ed25519.Ed25519PrivateKey.generate()
    claimed = ed25519.Ed25519PrivateKey.generate()
    sig = signing.sign_message_armored(signer, b"payload")
    fp_signer = signing.fingerprint(signing.public_key_line(signer))
    fp_claimed = signing.fingerprint(signing.public_key_line(claimed))
    exc = SignatureVerificationError("mismatch", reason="public_key_mismatch")
    result = sessions._bad_signature_error(exc, fp_claimed, sig)
    assert result.reason == "bad_signature"
    assert fp_signer in str(result)
    assert "不一致" in str(result)


def test_login_bad_signature_diagnosis_nonce_mismatch() -> None:
    """同一公钥验签失败（bad_signature）→ 提示挑战已过期/更换，不装解析失败。"""
    key = ed25519.Ed25519PrivateKey.generate()
    sig = signing.sign_message_armored(key, b"payload")
    fp = signing.fingerprint(signing.public_key_line(key))
    exc = SignatureVerificationError("Ed25519 验签失败", reason="bad_signature")
    result = sessions._bad_signature_error(exc, fp, sig)
    assert result.reason == "bad_signature"
    assert "挑战" in str(result)
    assert "签名" in str(result) and "该公钥" in str(result)


def test_login_bad_signature_unparseable() -> None:
    """非 SSHSIG 内容 → 提示粘贴完整签名块。"""
    exc = SignatureFormatError("frame truncated", reason="truncated")
    result = sessions._bad_signature_error(exc, "SHA256:whatever", "garbage-not-a-signature")
    assert result.reason == "bad_signature"
    assert "不完整" in str(result)


def test_validate_public_key_rejects_malformed_lines() -> None:
    for bad in ("", "ssh-ed25519", "ssh-ed25519 !!!notbase64", "ssh-foo AAAABBBB"):
        with pytest.raises(SignatureFormatError):
            sshsig.validate_public_key(bad)


def test_load_private_key_errors_are_actionable(tmp_path: Path) -> None:
    with pytest.raises(signing.SigningError):
        signing.load_private_key(tmp_path / "missing")
    broken = tmp_path / "broken"
    broken.write_text("not a key")
    with pytest.raises(signing.SigningError):
        signing.load_private_key(broken)


# ------------------------------------------------------------------ S2 载荷公式


def test_request_payload_binds_method_path_query_body_timestamp_nonce() -> None:
    payload = signing.request_payload(
        "post", "/api/v1/nodes?expected_version=3", b'{"a":1}', "2026-09-16T00:00:00Z", "nonce"
    )
    lines = payload.decode().split("\n")
    assert lines[0] == "POST"
    assert lines[1] == "/api/v1/nodes?expected_version=3"  # query 原样参与（S2）
    assert lines[2] == hashlib.sha256(b'{"a":1}').hexdigest()
    assert lines[3] == "2026-09-16T00:00:00Z"
    assert lines[4] == "nonce"

    assert signing.request_payload("GET", "/x", None, "t", "n") == signing.request_payload(
        "get", "/x", b"", "t", "n"
    )
    assert signing.request_payload("GET", "/x?a=1", None, "t", "n") != signing.request_payload(
        "GET", "/x?a=2", None, "t", "n"
    )


def test_sign_request_headers_shape() -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    headers = signing.sign_request_headers(key, "GET", "/api/v1/docs?limit=1", None)
    assert set(headers) == {"X-SSH-Key-Id", "X-SSH-Signature", "X-Timestamp", "X-Nonce"}
    assert headers["X-SSH-Key-Id"] == signing.fingerprint(signing.public_key_line(key))
    assert "\n" not in headers["X-SSH-Signature"]  # 单行 base64，可直接进 HTTP 头
    payload = signing.request_payload(
        "GET", "/api/v1/docs?limit=1", None, headers["X-Timestamp"], headers["X-Nonce"]
    )
    assert sshsig.verify_sshsig(
        signing.public_key_line(key), headers["X-SSH-Signature"], payload
    )


# ------------------------------------------------------- ssh-keygen 互操作（S11）


@pytest.fixture(scope="module")
def openssh_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """用**真实 ssh-keygen** 生成 Ed25519 与 RSA 密钥（互操作用），返回目录。"""
    directory = tmp_path_factory.mktemp("openssh")
    for name, args in (
        ("id_ed25519", ["-t", "ed25519"]),
        ("id_rsa", ["-t", "rsa", "-b", "3072"]),
    ):
        subprocess.run(
            [SSH_KEYGEN, "-q", "-N", "", "-f", str(directory / name), *args],
            check=True,
            capture_output=True,
        )
    (directory / "message").write_bytes(MESSAGE)
    return directory


@needs_ssh_keygen
def test_fingerprint_matches_ssh_keygen_lf(openssh_dir: Path) -> None:
    for name in ("id_ed25519", "id_rsa"):
        expected = subprocess.run(
            [SSH_KEYGEN, "-lf", str(openssh_dir / f"{name}.pub")],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.split()[1]
        assert signing.fingerprint((openssh_dir / f"{name}.pub").read_text()) == expected, name


@needs_ssh_keygen
@pytest.mark.parametrize("key_name", ["id_ed25519", "id_rsa"])
def test_verify_real_ssh_keygen_signature(openssh_dir: Path, key_name: str) -> None:
    """**硬验收（S11）**：``ssh-keygen -Y sign`` 的产物必须被本验签器接受。"""
    path = openssh_dir / key_name
    message = openssh_dir / f"{key_name}.msg"
    message.write_bytes(MESSAGE)
    subprocess.run(
        [SSH_KEYGEN, "-Y", "sign", "-n", sshsig.NAMESPACE, "-f", str(path), str(message)],
        check=True,
        capture_output=True,
    )
    signature = Path(f"{message}.sig").read_text()
    public_key = (openssh_dir / f"{key_name}.pub").read_text()
    verified = sshsig.verify_sshsig(public_key, signature, MESSAGE)
    assert verified.namespace == sshsig.NAMESPACE
    assert sshsig.fingerprint_of_blob(verified.public_key_blob) == signing.fingerprint(public_key)

    # 篡改消息（签名载荷的任一字节）→ 拒绝
    with pytest.raises(SignatureVerificationError):
        sshsig.verify_sshsig(public_key, signature, MESSAGE + b"!")


@needs_ssh_keygen
@pytest.mark.parametrize("key_name", ["id_ed25519", "id_rsa"])
def test_ssh_keygen_verifies_our_signature(
    openssh_dir: Path, key_name: str, tmp_path: Path
) -> None:
    """反向互操作：本模块签名 → ``ssh-keygen -Y verify`` 判定 Good signature。

    注：本机 OpenSSH 8.0p1 对 RSA **只支持 PKCS#1 v1.5**（实测其 ``-Y verify`` 拒绝 PSS），
    故该方向对 RSA 用 v1.5 生成签名的验签器输入；签名侧默认 PSS（S11）已由
    ``test_verify_rsa_accepts_pss_and_legacy_pkcs1v15`` 覆盖。
    """
    path = openssh_dir / key_name
    key = signing.load_private_key(path)
    if key_name == "id_ed25519":
        signature = signing.sign_message(key, MESSAGE)
    else:
        signature = base64.b64encode(
            _sign_rsa(key, MESSAGE, scheme=padding.PKCS1v15())
        ).decode()

    allowed_signers = tmp_path / "allowed_signers"
    allowed_signers.write_text(f"user {path.with_suffix('.pub').read_text().strip()}\n")
    signature_file = tmp_path / "sig"
    signature_file.write_text(sshsig.armor(base64.b64decode(signature)))
    proc = subprocess.run(
        [
            SSH_KEYGEN, "-Y", "verify", "-f", str(allowed_signers), "-I", "user",
            "-n", sshsig.NAMESPACE, "-s", str(signature_file),
        ],
        input=MESSAGE,
        capture_output=True,
    )
    assert proc.returncode == 0, proc.stderr.decode()
