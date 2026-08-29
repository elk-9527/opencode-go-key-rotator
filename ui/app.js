const state = {
  token: '',
  busy: false,
  busyAction: '',
  previewToken: '',
  demo: false,
  theme: 'system',
  targets: [],
  hasDetected: false,
  vscodeRunning: false,
  changes: [],
};

const $ = (selector) => document.querySelector(selector);
const elements = {
  urlField: $('#urlField'),
  connectionForm: $('#connectionForm'),
  urlInput: $('#urlInput'),
  keyField: $('#keyField'),
  keyInput: $('#keyInput'),
  revealButton: $('#revealButton'),
  validationText: $('#validationText'),
  sourceStatus: $('#sourceStatus'),
  targets: $('#targets'),
  selectedCount: $('#selectedCount'),
  detectButton: $('#detectButton'),
  detectSummary: $('#detectSummary'),
  previewButton: $('#previewButton'),
  applyButton: $('#applyButton'),
  summaryRail: $('.summary-rail'),
  modeText: $('#modeText'),
  changeCount: $('#changeCount'),
  emptyState: $('#emptyState'),
  changeList: $('#changeList'),
  logDetails: $('#logDetails'),
  logWindow: $('#logWindow'),
  logCount: $('#logCount'),
  footerStatus: $('#footerStatus'),
  versionText: $('#versionText'),
  confirmDialog: $('#confirmDialog'),
  confirmText: $('#confirmText'),
  confirmApply: $('#confirmApply'),
  quitButton: $('#quitButton'),
  toast: $('#toast'),
  themeButtons: [...document.querySelectorAll('[data-theme-choice]')],
};

const themeMedia = window.matchMedia('(prefers-color-scheme: dark)');
const monograms = {hermes: 'HM', continue: 'CO', dsh: 'DS', vscode: 'VS', claude: 'CC', pi: 'PI'};

function applyTheme(choice, {persist = true} = {}) {
  const theme = ['light', 'dark', 'system'].includes(choice) ? choice : 'system';
  const resolved = theme === 'system' ? (themeMedia.matches ? 'dark' : 'light') : theme;
  state.theme = theme;
  document.documentElement.dataset.theme = theme;
  document.documentElement.dataset.resolvedTheme = resolved;
  elements.themeButtons.forEach((button) => {
    button.setAttribute('aria-checked', String(button.dataset.themeChoice === theme));
  });
  if (persist) localStorage.setItem('key-rotator-theme', theme);
}

function normalizedUrl() {
  return elements.urlInput.value.trim().replace(/\/+$/, '');
}

function validUrl() {
  try {
    const parsed = new URL(elements.urlInput.value.trim());
    if (!['http:', 'https:'].includes(parsed.protocol)) return false;
    if (parsed.username || parsed.password || parsed.search || parsed.hash) return false;
    if (parsed.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname)) return false;
    return Boolean(parsed.hostname);
  } catch (_) {
    return false;
  }
}

function validKey() {
  const key = elements.keyInput.value.trim();
  return key.length >= 4 && key.length <= 2048 && !/\s/.test(key) && !/[\u0000-\u001f\u007f]/.test(key);
}

function selectedIds() {
  return [...elements.targets.querySelectorAll('input[type="checkbox"]:checked')].map((input) => input.value);
}

function setMode(label, tone = 'idle') {
  elements.modeText.textContent = label;
  elements.summaryRail.dataset.tone = tone;
}

function setFooter(label) {
  elements.footerStatus.textContent = label;
}

function renderEmpty(title, text, tone = 'idle') {
  elements.emptyState.querySelector('h3').textContent = title;
  elements.emptyState.querySelector('p').textContent = text;
  elements.emptyState.dataset.tone = tone;
  elements.emptyState.hidden = false;
  elements.changeList.hidden = true;
}

function invalidatePreview({resetView = true} = {}) {
  state.previewToken = '';
  state.changes = [];
  elements.changeCount.textContent = '0 处更改';
  setMode('等待预览', 'idle');
  if (resetView) renderEmpty('准备一次批量替换', '填写 URL 和 Key，选择工具后生成预览。');
  refreshButtons();
}

function refreshSourceState({invalidate = false} = {}) {
  const urlText = elements.urlInput.value.trim();
  const keyText = elements.keyInput.value.trim();
  const urlOkay = validUrl();
  const keyOkay = validKey();
  elements.urlField.dataset.valid = urlText ? String(urlOkay) : '';
  elements.keyField.dataset.valid = keyText ? String(keyOkay) : '';

  if (!keyText) {
    elements.validationText.textContent = '未输入';
    elements.validationText.dataset.tone = 'idle';
  } else if (keyOkay) {
    elements.validationText.textContent = `${keyText.slice(0, 4)}••••${keyText.slice(-4)}`;
    elements.validationText.dataset.tone = 'ok';
  } else {
    elements.validationText.textContent = '格式无效';
    elements.validationText.dataset.tone = 'error';
  }

  const ready = urlOkay && keyOkay && selectedIds().length > 0;
  elements.sourceStatus.textContent = ready ? '可预览' : '等待输入';
  elements.sourceStatus.dataset.tone = ready ? 'ok' : (urlText || keyText ? 'error' : 'idle');
  if (invalidate) invalidatePreview();
  refreshButtons();
}

function refreshSelection({invalidate = false} = {}) {
  const count = selectedIds().length;
  elements.selectedCount.textContent = String(count);
  if (invalidate) invalidatePreview();
  refreshSourceState();
}

function refreshButtons() {
  const canPreview = validUrl() && validKey() && selectedIds().length > 0;
  elements.previewButton.disabled = state.busy || !canPreview;
  elements.applyButton.disabled = state.busy || state.demo || !state.previewToken;
  elements.detectButton.disabled = state.busy;
  elements.urlInput.disabled = state.busy;
  elements.keyInput.disabled = state.busy;
  elements.revealButton.disabled = state.busy;
  elements.targets.querySelectorAll('input[type="checkbox"]').forEach((input) => {
    const selectable = input.closest('.target-row')?.dataset.selectable === 'true';
    input.disabled = state.busy || !selectable;
  });
  elements.previewButton.dataset.busy = String(state.busy && state.busyAction === 'preview');
  elements.applyButton.dataset.busy = String(state.busy && state.busyAction === 'apply');
}

function setBusy(busy, action = '', label = '处理中') {
  state.busy = busy;
  state.busyAction = busy ? action : '';
  if (busy) {
    setMode(label, 'working');
    setFooter(label);
  }
  refreshButtons();
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    cache: 'no-store',
    headers: {
      'Content-Type': 'application/json',
      ...(options.method ? {'X-Key-Rotator-Token': state.token} : {}),
      ...(options.headers || {}),
    },
  });
  const data = await response.json();
  if (!response.ok || !data.ok) throw new Error(data.error || `请求失败 (${response.status})`);
  return data;
}

function timestamp() {
  return new Intl.DateTimeFormat('zh-CN', {hour: '2-digit', minute: '2-digit', hour12: false}).format(new Date());
}

function logTone(message) {
  if (/失败|错误|不可写入/.test(message)) return 'error';
  if (/注意|请关闭|跳过/.test(message)) return 'warn';
  if (/完成|已备份|已找到/.test(message)) return 'ok';
  return 'muted';
}

function appendLog(message, tone = logTone(message)) {
  const line = document.createElement('div');
  line.className = 'log-line';
  line.dataset.tone = tone;
  const time = document.createElement('time');
  time.textContent = timestamp();
  const text = document.createElement('span');
  text.textContent = message || ' ';
  line.append(time, text);
  elements.logWindow.append(line);
  elements.logCount.textContent = String(elements.logWindow.children.length);
  elements.logWindow.scrollTop = elements.logWindow.scrollHeight;
}

function clearLog() {
  elements.logWindow.replaceChildren();
  elements.logCount.textContent = '0';
}

let toastTimer;
function showToast(message, tone = 'ok') {
  clearTimeout(toastTimer);
  elements.toast.textContent = message;
  elements.toast.dataset.tone = tone;
  elements.toast.classList.add('is-visible');
  toastTimer = setTimeout(() => elements.toast.classList.remove('is-visible'), 2800);
}

function renderTargets(items) {
  const previous = new Map([...elements.targets.querySelectorAll('input[type="checkbox"]')].map((input) => [input.value, input.checked]));
  elements.targets.replaceChildren();
  items.forEach((item) => {
    const row = document.createElement('label');
    row.className = 'target-row';
    row.dataset.state = item.state;
    row.dataset.selectable = String(Boolean(item.selectable));

    const input = document.createElement('input');
    input.type = 'checkbox';
    input.name = 'targetIds';
    input.value = item.id;
    input.checked = item.selectable && (state.hasDetected ? previous.get(item.id) !== false : true);
    input.disabled = !item.selectable;
    input.addEventListener('change', () => refreshSelection({invalidate: true}));

    const monogram = document.createElement('span');
    monogram.className = 'target-monogram';
    monogram.textContent = monograms[item.id] || item.title.slice(0, 2).toUpperCase();

    const copy = document.createElement('span');
    copy.className = 'target-copy';
    const title = document.createElement('strong');
    title.textContent = item.title;
    const detail = document.createElement('small');
    detail.textContent = item.detail || item.location || '未找到配置';
    detail.title = item.detail || item.location || '';
    copy.append(title, detail);

    const badge = document.createElement('span');
    badge.className = 'target-state';
    badge.textContent = item.badge || (item.selectable ? '可写入' : '不可用');
    row.append(input, monogram, copy, badge);
    elements.targets.append(row);
  });
  state.targets = items;
  state.hasDetected = true;
  refreshSelection();
}

function renderChanges(changes) {
  elements.changeList.replaceChildren();
  changes.forEach((change, index) => {
    const row = document.createElement('div');
    row.className = 'change-row';
    row.style.animationDelay = `${Math.min(index * 28, 168)}ms`;
    const target = document.createElement('span');
    target.className = 'change-target';
    target.textContent = change.target;
    const file = document.createElement('span');
    file.className = 'change-file';
    file.textContent = change.file;
    file.title = change.file;
    const summary = document.createElement('span');
    summary.className = 'change-summary';
    summary.textContent = change.summary;
    const arrow = document.createElement('span');
    arrow.className = 'change-arrow';
    arrow.textContent = '→';
    arrow.setAttribute('aria-label', '将更新');
    row.append(target, file, summary, arrow);
    elements.changeList.append(row);
  });
  elements.emptyState.hidden = true;
  elements.changeList.hidden = false;
  elements.changeCount.textContent = `${changes.length} 处更改`;
}

async function detect() {
  if (state.busy) return;
  setBusy(true, 'detect', '检测中');
  elements.detectSummary.textContent = '正在读取本机配置';
  clearLog();
  appendLog('正在检测支持的工具…');
  try {
    const data = await api('/api/detect');
    state.vscodeRunning = data.vscodeRunning;
    renderTargets(data.items);
    const selectable = data.items.filter((item) => item.selectable).length;
    elements.detectSummary.textContent = data.vscodeRunning
      ? `${selectable} 个可写入 · VS Code 需退出`
      : `${selectable} 个工具可写入`;
    data.items.forEach((item) => appendLog(`${item.title} · ${item.badge}`, item.selectable ? 'ok' : 'warn'));
    if (data.vscodeRunning) appendLog('VS Code 正在运行；预览后需退出才能应用。', 'warn');
    setMode('等待预览', 'idle');
    setFooter('就绪');
  } catch (error) {
    elements.detectSummary.textContent = '检测失败';
    setMode('检测失败', 'error');
    setFooter('错误');
    appendLog(error.message, 'error');
    showToast(error.message, 'error');
  } finally {
    state.busy = false;
    state.busyAction = '';
    refreshButtons();
  }
}

async function rotate(apply) {
  if (state.busy || !validUrl() || !validKey() || !selectedIds().length) return;
  setBusy(true, apply ? 'apply' : 'preview', apply ? '正在应用' : '正在预览');
  clearLog();
  appendLog(apply ? '开始备份并应用配置。' : '生成只读预览，不会写入配置。');
  try {
    const targetIds = selectedIds();
    const data = await api(apply ? '/api/apply' : '/api/preview', {
      method: 'POST',
      body: JSON.stringify({
        baseUrl: normalizedUrl(),
        newKey: elements.keyInput.value.trim(),
        targetIds,
        previewToken: state.previewToken,
      }),
    });
    data.logs.forEach((line) => appendLog(line));
    state.changes = data.changes || [];
    renderChanges(state.changes);

    if (apply) {
      state.previewToken = '';
      elements.keyInput.value = '';
      refreshSourceState();
      setMode('应用完成', 'ok');
      setFooter('已完成');
      showToast(`已更新 ${targetIds.length} 个工具`, 'ok');
    } else if (data.vscodeRunning && targetIds.includes('vscode')) {
      state.previewToken = '';
      setMode('等待退出 VS Code', 'error');
      setFooter('需关闭 VS Code');
      elements.logDetails.open = true;
      appendLog('关闭 VS Code 后重新检测并预览。', 'warn');
      showToast('请先完全退出 VS Code', 'error');
    } else {
      state.previewToken = data.previewToken;
      setMode('预览就绪', 'ok');
      setFooter('可安全应用');
      showToast('预览已生成', 'ok');
    }
  } catch (error) {
    state.previewToken = '';
    setMode(apply ? '应用失败' : '预览失败', 'error');
    setFooter('错误');
    appendLog(error.message, 'error');
    elements.logDetails.open = true;
    renderEmpty(apply ? '没有完成写入' : '无法生成预览', error.message, 'error');
    showToast(error.message, 'error');
  } finally {
    state.busy = false;
    state.busyAction = '';
    refreshButtons();
  }
}

elements.themeButtons.forEach((button) => {
  button.addEventListener('click', () => applyTheme(button.dataset.themeChoice));
});
themeMedia.addEventListener('change', () => {
  if (state.theme === 'system') applyTheme('system', {persist: false});
});

elements.urlInput.addEventListener('input', () => refreshSourceState({invalidate: true}));
elements.keyInput.addEventListener('input', () => refreshSourceState({invalidate: true}));
elements.connectionForm.addEventListener('submit', (event) => {
  event.preventDefault();
  rotate(false);
});
elements.revealButton.addEventListener('click', () => {
  const hidden = elements.keyInput.type === 'password';
  elements.keyInput.type = hidden ? 'text' : 'password';
  elements.revealButton.textContent = hidden ? '隐藏' : '显示';
  elements.revealButton.setAttribute('aria-label', hidden ? '隐藏 API Key' : '显示 API Key');
});
elements.detectButton.addEventListener('click', detect);
elements.previewButton.addEventListener('click', () => rotate(false));
elements.applyButton.addEventListener('click', () => {
  elements.confirmText.textContent = `将先备份，再写入 ${selectedIds().length} 个工具的 ${state.changes.length} 处配置。`;
  elements.confirmDialog.showModal();
});
elements.confirmApply.addEventListener('click', (event) => {
  event.preventDefault();
  elements.confirmDialog.close();
  rotate(true);
});
elements.quitButton.addEventListener('click', async () => {
  try { await api('/api/shutdown', {method: 'POST', body: '{}'}); } catch (_) { /* 服务可能先关闭 */ }
  window.close();
});

async function init() {
  applyTheme(document.documentElement.dataset.theme || 'system', {persist: false});
  refreshSourceState();
  try {
    const session = await api('/api/session');
    state.token = session.token;
    state.demo = session.demo;
    elements.versionText.textContent = `v${session.version}${session.demo ? ' · DEMO' : ''}`;
    if (session.demo) {
      elements.urlInput.value = 'https://api.example.com/v1';
      elements.keyInput.value = 'sk-demo-1234567890-example';
      refreshSourceState();
    }
    await detect();
  } catch (error) {
    setMode('服务离线', 'error');
    setFooter('离线');
    renderEmpty('本地服务未连接', '请重新启动 Key Router。', 'error');
    appendLog(error.message, 'error');
    showToast('本地服务未连接', 'error');
  }
}

init();
