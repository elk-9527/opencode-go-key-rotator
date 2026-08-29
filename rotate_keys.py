# -*- coding: utf-8 -*-
"""
OpenCode Go key rotator — 一次性替换所有 agent 的 opencode.go API key

覆盖:
  1. Hermes           -> E:\\Program Files\\Hermes\\.env  (OPENCODE_GO_API_KEY)
  2. Continue 插件     -> ~/.continue/config.yaml        (apiKey)
  3. dsh              -> ~/.dsh/.credentials.yaml        (refs.DEEPSEEK_API_KEY)
  4. VS Code          -> state.vscdb (SecretStorage 加密条目 + 指纹/模型配置明文)
                         chatLanguageModels.json (模型设置键名内嵌指纹)
  5. (可选) opencode CLI -> auth.json 中的 opencode-go 条目删除

用法:
  python rotate_keys.py --detect               # 只检测当前各位置 key 状态
  python rotate_keys.py <新key> --dry-run       # 预览（默认，不写文件）
  python rotate_keys.py <新key> --apply         # 执行替换
  python rotate_keys.py <新key> --apply --delete-opencode-auth   # 顺带删除 opencode CLI 旧 key

安全设计:
  - 默认 dry-run，--apply 才真改
  - 改前自动备份全部文件到 backups/ 目录
  - 全程不打印完整 key（只显示前8+后4）
  - state.vscdb 写入前要求 VS Code 已关闭（文件锁/WAL 保护）
  - 只替换 == 旧 key 的 secret 条目；其它 key（如 DeepSeek/小米）不碰
"""
import argparse
import base64
import copy
import json
import os
import re
import shutil
import sqlite3
import sys
import time
import ctypes
import ctypes.wintypes as wt

# ─── 依赖 cryptography（仅用 AESGCM）──────────────────────────────
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit('[!] 需要 cryptography 库：pip install cryptography')


# ─── 配置区（Windows 默认路径；可用环境变量 RK_PATHS_JSON 覆盖，用于测试）────────────────
def _paths() -> dict:
    appdata = os.environ.get('APPDATA') or os.path.join(os.path.expanduser('~'), 'AppData', 'Roaming')
    home = os.path.expanduser('~')
    p = {
        'HERMES_ENV': r'E:\Program Files\Hermes\.env',
        'CONTINUE_CONFIG': os.path.join(home, '.continue', 'config.yaml'),
        'DSH_CREDENTIALS': os.path.join(home, '.dsh', '.credentials.yaml'),
        'VSCODE_STATE_DB': os.path.join(appdata, 'Code', 'User', 'globalStorage', 'state.vscdb'),
        'VSCODE_LOCAL_STATE': os.path.join(appdata, 'Code', 'Local State'),
        'CHAT_LM_JSON': os.path.join(appdata, 'Code', 'User', 'chatLanguageModels.json'),
        'OPENCODE_AUTH': os.path.join(home, '.local', 'share', 'opencode', 'auth.json'),
    }
    ov = os.environ.get('RK_PATHS_JSON')
    if ov:
        p.update(json.loads(ov))
    return p


PATHS = _paths()
HERMES_ENV = PATHS['HERMES_ENV']
CONTINUE_CONFIG = PATHS['CONTINUE_CONFIG']
DSH_CREDENTIALS = PATHS['DSH_CREDENTIALS']
VSCODE_STATE_DB = PATHS['VSCODE_STATE_DB']
VSCODE_LOCAL_STATE = PATHS['VSCODE_LOCAL_STATE']
CHAT_LM_JSON = PATHS['CHAT_LM_JSON']
OPENCODE_AUTH = PATHS['OPENCODE_AUTH']

BACKUP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backups')

VSCode_SECRET_KEYS = [
    'secret://{"extensionId":"ltmoerdani.opencode-copilot-chat","key":"opencodego.apiKey"}',
]

VSCode_SECRET_PREFIX = 'secret://chat.lm.secret.'


def list_vscode_lm_secret_keys(db: sqlite3.Connection) -> list[str]:
    """动态发现 chat.lm.secret.* 条目（各机器 id 不同）"""
    cur = db.cursor()
    cur.execute("SELECT key FROM ItemTable WHERE key LIKE ?", (VSCode_SECRET_PREFIX + '%',))
    return [r[0] for r in cur.fetchall()]

# ─── DPAPI ────────────────────────────────────────────────────────
class DATA_BLOB(ctypes.Structure):
    _fields_ = [('cbData', wt.DWORD), ('pbData', ctypes.POINTER(ctypes.c_byte))]


def dpapi_decrypt(blob: bytes) -> bytes:
    d = DATA_BLOB(len(blob), ctypes.cast(ctypes.create_string_buffer(blob), ctypes.POINTER(ctypes.c_byte)))
    out = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(d), None, None, None, None, 0, ctypes.byref(out)):
        raise OSError(f'CryptUnprotectData failed, err={ctypes.windll.kernel32.GetLastError():#x}')
    b = ctypes.string_at(out.pbData, out.cbData)
    ctypes.windll.kernel32.LocalFree(out.pbData)
    return b


def get_vscode_aes_key() -> bytes:
    """从 VS Code Local State 取 DPAPI 保护的 AES key（Chromium os_crypt）"""
    ls = json.load(open(VSCODE_LOCAL_STATE, encoding='utf-8'))
    enc = base64.b64decode(ls['os_crypt']['encrypted_key'])
    assert enc.startswith(b'DPAPI'), 'Local State encrypted_key 不是 DPAPI 格式'
    raw = dpapi_decrypt(enc[5:])
    return raw if len(raw) == 32 else base64.b64decode(raw)


def vscode_secret_decrypt(v10_value: bytes, aes_key: bytes) -> str:
    assert v10_value.startswith(b'v10'), '非 v10 格式'
    blob = v10_value[3:]
    return AESGCM(aes_key).decrypt(blob[:12], blob[12:], None).decode('utf-8')


def vscode_secret_encrypt(plain: str, aes_key: bytes) -> bytes:
    nonce = os.urandom(12)
    return b'v10' + nonce + AESGCM(aes_key).encrypt(nonce, plain.encode('utf-8'), None)


def mask(s: str) -> str:
    if not s:
        return '(空)'
    return f'{s[:8]}...{s[-4:]}({len(s)})' if len(s) > 12 else s


def fingerprint_of(key: str) -> str:
    """扩展的指纹算法: 前8位-后8位"""
    return f'{key[:8]}-{key[-8:]}'


# ─── 读取各处 key ─────────────────────────────────────────────────
def read_key_from_env(path: str, var: str) -> str | None:
    if not os.path.isfile(path):
        return None
    t = open(path, encoding='utf-8', errors='ignore').read()
    m = re.search(rf'^{var}=(\S+)', t, re.M)
    return m.group(1) if m else None


def read_key_from_yaml(path: str, field: str) -> str | None:
    """匹配 <field>: <value>（YAML 缩进也兼容）"""
    if not os.path.isfile(path):
        return None
    t = open(path, encoding='utf-8', errors='ignore').read()
    m = re.search(rf'^\s*{re.escape(field)}:\s*"([^"]+)"\s*$', t, re.M) or \
        re.search(rf'^\s*{re.escape(field)}:\s*\'([^\']+)\'\s*$', t, re.M) or \
        re.search(rf'^\s*{re.escape(field)}:\s*(\S+)\s*$', t, re.M)
    return m.group(1) if m else None


def read_vscode_secrets(aes_key: bytes) -> dict:
    out = {}
    db = sqlite3.connect(f'file:{VSCODE_STATE_DB}?mode=ro', uri=True)
    try:
        cur = db.cursor()
        for sk in VSCode_SECRET_KEYS + list_vscode_lm_secret_keys(db):
            try:
                cur.execute('SELECT value FROM ItemTable WHERE key=?', (sk,))
                r = cur.fetchone()
                if r:
                    out[sk] = vscode_secret_decrypt(bytes(json.loads(r[0])['data']), aes_key)
            except Exception as e:
                out[sk] = f'ERR:{e}'
    finally:
        db.close()
    return out


def detect() -> dict:
    """返回 {位置: key 或 错误说明}"""
    result = {}
    result['Hermes .env'] = read_key_from_env(HERMES_ENV, 'OPENCODE_GO_API_KEY')
    result['Continue config.yaml'] = read_key_from_yaml(CONTINUE_CONFIG, 'apiKey')
    result['dsh .credentials.yaml'] = read_key_from_yaml(DSH_CREDENTIALS, 'DEEPSEEK_API_KEY')
    try:
        aes = get_vscode_aes_key()
        sec = read_vscode_secrets(aes)
        for k, v in sec.items():
            result[f'VS Code secret ({k.split(".")[-1][:12]}...)'] = v
    except Exception as e:
        result['VS Code secrets'] = f'ERR:{e}'
    return result


def main_key_from_detect(d: dict) -> str | None:
    """取最关键的那把 key（VS Code chat.lm.secret 或 Hermes 的）作为旧主 key"""
    for k in d:
        v = d[k]
        if isinstance(v, str) and v.startswith('sk-') and v != 'ERR' and not v.startswith('ERR'):
            return v
    return None


# ─── 备份 ─────────────────────────────────────────────────────────
def backup(files: list[str]) -> str:
    ts = time.strftime('%Y%m%d-%H%M%S')
    bdir = os.path.join(BACKUP_DIR, ts)
    os.makedirs(bdir, exist_ok=True)
    for f in files:
        if os.path.isfile(f):
            shutil.copy2(f, os.path.join(bdir, os.path.basename(f)))
    return bdir


# ─── 替换执行 ─────────────────────────────────────────────────────
def replace_in_file(path: str, pairs: list[tuple[str, str]], apply: bool = False) -> list[str]:
    """文件内字符串替换；返回修改的描述。文件不存在则跳过。apply=False 只预览。"""
    if not os.path.isfile(path):
        return [f'[跳过] {path} 不存在']
    t = open(path, encoding='utf-8', errors='ignore').read()
    changed = []
    for old, new in pairs:
        if old and old in t:
            n = t.count(old)
            t = t.replace(old, new)
            changed.append(f'  替换 {mask(old)} -> {mask(new)} x{n} ({os.path.basename(path)})')
    if changed and apply:
        open(path, 'w', encoding='utf-8', newline='').write(t)
    return changed or [f'[无变化] {path}']


def replace_vscode_db(old_key: str, new_key: str, aes_key: bytes, apply: bool) -> list[str]:
    """state.vscdb：secret 重加密 + 全表字符串替换"""
    msgs = []
    db = sqlite3.connect(VSCODE_STATE_DB)
    try:
        cur = db.cursor()
        # 1) secret 条目：解密值 == 旧 key 的，重加密为新 key（chat.lm.secret.* 动态发现）
        for sk in VSCode_SECRET_KEYS + list_vscode_lm_secret_keys(db):
            cur.execute('SELECT value FROM ItemTable WHERE key=?', (sk,))
            r = cur.fetchone()
            if not r:
                continue
            try:
                plain = vscode_secret_decrypt(bytes(json.loads(r[0])['data']), aes_key)
            except Exception:
                continue
            if plain == old_key:
                new_val = json.dumps({'type': 'Buffer', 'data': list(vscode_secret_encrypt(new_key, aes_key))})
                if apply:
                    cur.execute('UPDATE ItemTable SET value=? WHERE key=?', (new_val, sk))
                msgs.append(f'  重加密 secret {sk[:44]}...')
            elif isinstance(plain, str) and plain.startswith('sk-'):
                msgs.append(f'  [保留-不同key] {sk[:44]}... -> {mask(plain)}')
        # 2) 全表字符串替换 旧key/旧指纹 -> 新key/新指纹
        old_fp, new_fp = fingerprint_of(old_key), fingerprint_of(new_key)
        cur.execute('SELECT key, value FROM ItemTable')
        for k, v in cur.fetchall():
            if not isinstance(v, str):
                continue
            hits = []
            for old, new, tag in ((old_key, new_key, '完整key'), (old_fp, new_fp, '指纹')):
                if old and old in v:
                    hits.append((tag, v.count(old)))
            if hits:
                if apply:
                    nv = v.replace(old_key, new_key).replace(old_fp, new_fp)
                    cur.execute('UPDATE ItemTable SET value=? WHERE key=?', (nv, k))
                msgs.append(f'  表内替换 {k[:50]} ({", ".join(f"{t}x{n}" for t, n in hits)})')
        if apply:
            db.commit()
    finally:
        db.close()
    return msgs


def delete_opencode_auth(apply: bool) -> list[str]:
    """删除 opencode CLI auth.json 里的 opencode-go 条目（用户已确认不用 opencode）"""
    if not os.path.isfile(OPENCODE_AUTH):
        return ['[跳过] opencode auth.json 不存在']
    d = json.load(open(OPENCODE_AUTH, encoding='utf-8'))
    if 'opencode-go' not in d:
        return ['[跳过] auth.json 里没有 opencode-go 条目']
    old = d['opencode-go'].get('key', '')
    if apply:
        del d['opencode-go']
        json.dump(d, open(OPENCODE_AUTH, 'w', encoding='utf-8'), indent=2, ensure_ascii=False)
    return [f'  删除 opencode-go 条目 (key={mask(old)})']


def vscode_running() -> bool:
    if os.environ.get('RK_SKIP_VSCODE_CHECK') == '1':
        return False
    try:
        r = os.popen('tasklist /FI "IMAGENAME eq Code.exe" /NH 2>nul').read()
        return 'Code.exe' in r
    except Exception:
        return False


# ─── 主流程 ───────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description='OpenCode Go key rotator')
    ap.add_argument('new_key', nargs='?', help='新的 opencode.go API key (sk-...)')
    ap.add_argument('--detect', action='store_true', help='只检测当前各位置 key 状态')
    ap.add_argument('--dry-run', action='store_true', help='预览不执行（默认）')
    ap.add_argument('--apply', action='store_true', help='真正执行替换')
    ap.add_argument('--delete-opencode-auth', action='store_true', help='同时删除 opencode CLI auth.json 里的旧 key')
    args = ap.parse_args()

    print('=' * 62)
    print(' OpenCode Go key rotator')
    print('=' * 62)

    if args.detect:
        d = detect()
        print('各位置当前 key:')
        for k, v in d.items():
            print(f'  {k}: {mask(v) if isinstance(v, str) and not v.startswith("ERR") else v}')
        return

    if not args.new_key or not args.new_key.startswith('sk-'):
        sys.exit('[!] 请提供新 key（sk- 开头）。用法: python rotate_keys.py <新key> [--apply]')

    if not args.apply:
        print('[!] 预览模式（dry-run），不写任何文件。加 --apply 执行。')

    d = detect()
    old_key = main_key_from_detect(d)
    if not old_key:
        sys.exit('[!] 无法探测旧 key，请检查各配置是否存在')
    new_key = args.new_key
    if new_key == old_key:
        sys.exit('[!] 新 key 和当前旧 key 相同，无需替换')
    old_fp, new_fp = fingerprint_of(old_key), fingerprint_of(new_key)

    print(f'旧 key: {mask(old_key)} | 指纹: {mask(old_fp)}')
    print(f'新 key: {mask(new_key)} | 指纹: {mask(new_fp)}')
    print(f'（各位置当前 key: ' + ', '.join(f'{k}={mask(v)}' if isinstance(v, str) and v.startswith("sk-") else f'{k}=?' for k, v in d.items()) + '）')
    print()

    if vscode_running():
        print('[!] 检测到 VS Code 正在运行！state.vscdb 被占用，写入会失败或损坏。')
        print('    请先完全退出 VS Code 再执行 --apply。')
        if args.apply:
            sys.exit(1)
    else:
        print('[✓] VS Code 未运行，可安全写入')

    # 备份
    files = [HERMES_ENV, CONTINUE_CONFIG, DSH_CREDENTIALS, VSCODE_STATE_DB, CHAT_LM_JSON, OPENCODE_AUTH]
    if args.apply:
        bdir = backup(files)
        print(f'[✓] 备份完成 -> {bdir}')
    else:
        print('[.] 本次为预览，不产生备份（apply 时自动备份全部文件）')
    print()

    # 1) 明文文件
    print('【1. 明文配置替换】')
    for f, name in ((HERMES_ENV, 'Hermes .env'), (CONTINUE_CONFIG, 'Continue config.yaml'), (CHAT_LM_JSON, 'chatLanguageModels.json')):
        msgs = replace_in_file(f, [(old_key, new_key), (old_fp, new_fp)], apply=args.apply)
        print(f'  {name}:')
        for m in msgs:
            print(m)

    print()
    print('【2. dsh .credentials.yaml】')
    for m in replace_in_file(DSH_CREDENTIALS, [(old_key, new_key)], apply=args.apply):
        print(m)

    print()
    print('【3. VS Code state.vscdb】')
    aes = get_vscode_aes_key()
    for m in replace_vscode_db(old_key, new_key, aes, args.apply):
        print(m)

    print()
    print('【4. opencode CLI auth.json】')
    if args.delete_opencode_auth:
        for m in delete_opencode_auth(args.apply):
            print(m)
    else:
        print('  [跳过] 未指定 --delete-opencode-auth')

    print()
    if args.apply:
        print('✓ 全部完成！建议重启 VS Code 检查模型可用性。')
    else:
        print('^ 以上为预览。确认无误后执行: python rotate_keys.py <新key> --apply')


if __name__ == '__main__':
    main()