const state = {
  accessToken: new URLSearchParams(window.location.hash.slice(1)).get('access') || '',
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
  selectedTargetId: '',
  targetOptions: {},
  pendingInstaller: null,
  installToken: '',
};

if (window.location.hash) history.replaceState(null, '', window.location.pathname);

const VSCODE_TARGETS = new Set(['vscode', 'opencode_copilot', 'deepseek_copilot', 'mimo_copilot']);
const $ = (selector) => document.querySelector(selector);
const elements = {
  connectionForm: $('#connectionForm'),
  urlInput: $('#urlInput'),
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
  modeText: $('#modeText'),
  changeCount: $('#changeCount'),
  emptyState: $('#emptyState'),
  changeList: $('#changeList'),
  targetInspector: $('#targetInspector'),
  inspectorState: $('#inspectorState'),
  logDetails: $('#logDetails'),
  logWindow: $('#logWindow'),
  logCount: $('#logCount'),
  footerStatus: $('#footerStatus'),
  versionText: $('#versionText'),
  confirmDialog: $('#confirmDialog'),
  confirmText: $('#confirmText'),
  confirmApply: $('#confirmApply'),
  installDialog: $('#installDialog'),
  installForm: $('#installForm'),
  installTitle: $('#installTitle'),
  installPublisher: $('#installPublisher'),
  installIdentity: $('#installIdentity'),
  installLocation: $('#installLocation'),
  chooseInstallLocation: $('#chooseInstallLocation'),
  installPathHint: $('#installPathHint'),
  installNote: $('#installNote'),
  installProgress: $('#installProgress'),
  installProgressText: $('#installProgressText'),
  cancelInstall: $('#cancelInstall'),
  confirmInstall: $('#confirmInstall'),
  quitButton: $('#quitButton'),
  toast: $('#toast'),
  themeButtons: [...document.querySelectorAll('[data-theme-choice]')],
};

const themeMedia = window.matchMedia('(prefers-color-scheme: dark)');

function node(tag, className = '', text = '') {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== '') element.textContent = text;
  return element;
}

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
    const raw = elements.urlInput.value.trim();
    const parsed = new URL(raw);
    const authority = raw.slice(raw.indexOf('://') + 3).split(/[/?#]/, 1)[0];
    if (!['http:', 'https:'].includes(parsed.protocol)) return false;
    if (authority.endsWith(':')) return false;
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

function selectedOptions() {
  const selected = new Set(selectedIds());
  const output = {};
  if (selected.has('continue') && state.targetOptions.continue) {
    output.continue = {...state.targetOptions.continue};
  }
  VSCODE_TARGETS.forEach((targetId) => {
    if (selected.has(targetId) && state.targetOptions[targetId]) {
      output[targetId] = {...state.targetOptions[targetId]};
    }
  });
  if (selected.has('dsh') && state.targetOptions.dsh) {
    output.dsh = {...state.targetOptions.dsh};
  }
  return output;
}

function setMode(label) {
  elements.modeText.textContent = label;
}

function setFooter(label) {
  elements.footerStatus.textContent = label;
}

function renderEmpty(title, text) {
  elements.emptyState.querySelector('strong').textContent = title;
  elements.emptyState.querySelector('span').textContent = text;
  elements.emptyState.hidden = false;
  elements.changeList.hidden = true;
}

function invalidatePreview({resetView = true} = {}) {
  state.previewToken = '';
  state.changes = [];
  elements.changeCount.textContent = '0';
  setMode('配置有变化，请重新生成预览');
  if (resetView) renderEmpty('尚未生成预览', '填写连接参数并选择工具。');
  refreshButtons();
}

function refreshSourceState({invalidate = false} = {}) {
  const urlText = elements.urlInput.value.trim();
  const keyText = elements.keyInput.value.trim();
  const urlOkay = validUrl();
  const keyOkay = validKey();

  if (!keyText) {
    elements.validationText.textContent = '未输入';
    elements.validationText.dataset.tone = 'idle';
  } else if (keyOkay) {
    elements.validationText.textContent = keyText.length <= 12
      ? `${'•'.repeat(keyText.length)} (${keyText.length})`
      : `••••…${keyText.slice(-4)} (${keyText.length})`;
    elements.validationText.dataset.tone = 'ok';
  } else {
    elements.validationText.textContent = '格式无效';
    elements.validationText.dataset.tone = 'error';
  }

  const ready = urlOkay && keyOkay && selectedIds().length > 0;
  elements.sourceStatus.textContent = ready ? '可预览' : (urlText || keyText ? '待补全' : '未填写');
  elements.sourceStatus.dataset.tone = ready ? 'ok' : (urlText || keyText ? 'error' : 'idle');
  if (invalidate) invalidatePreview();
  refreshButtons();
}

function refreshSelection({invalidate = false} = {}) {
  elements.selectedCount.textContent = String(selectedIds().length);
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
  elements.quitButton.disabled = state.busy;
  elements.targets.querySelectorAll('input[type="checkbox"]').forEach((input) => {
    const row = input.closest('.target-row');
    input.disabled = state.busy || row?.dataset.selectable !== 'true';
  });
  elements.targets.querySelectorAll('.install-action').forEach((button) => {
    button.disabled = state.busy || button.dataset.installable !== 'true';
  });
  elements.targetInspector.querySelectorAll('select, button').forEach((control) => {
    control.disabled = state.busy || control.dataset.disabled === 'true';
  });
  elements.confirmInstall.disabled = state.busy || !state.installToken;
  elements.cancelInstall.disabled = state.busyAction === 'install';
  elements.chooseInstallLocation.disabled = state.busy;
}

function setBusy(busy, action = '', label = '处理中') {
  state.busy = busy;
  state.busyAction = busy ? action : '';
  if (busy) {
    setMode(label);
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
      'X-Key-Rotator-Access': state.accessToken,
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
  if (/注意|请关闭|跳过|未安装/.test(message)) return 'warn';
  if (/完成|已备份|已找到|已安装/.test(message)) return 'ok';
  return 'muted';
}

function appendLog(message, tone = logTone(message)) {
  const line = node('div', 'log-line');
  line.dataset.tone = tone;
  const time = node('time', '', timestamp());
  const text = node('span', '', message || ' ');
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

function currentTarget() {
  return state.targets.find((item) => item.id === state.selectedTargetId) || null;
}

function addProperty(list, label, value, {mono = false} = {}) {
  const row = node('div', 'property-row');
  const term = node('dt', '', label);
  const description = node('dd');
  const content = node(mono ? 'code' : 'span', '', value || '—');
  description.append(content);
  row.append(term, description);
  list.append(row);
}

function replaceTarget(nextItem) {
  const index = state.targets.findIndex((item) => item.id === nextItem.id);
  if (index >= 0) state.targets[index] = nextItem;
  renderTargets(state.targets);
}

function configureDshCandidate(item, path) {
  const candidate = item.candidates.find((entry) => entry.path === path);
  if (!candidate) return;
  const providers = candidate.providers || [];
  const requestedProvider = state.targetOptions.dsh?.provider || item.selectedProvider || candidate.currentProvider;
  const writableProviders = providers.filter((provider) => provider.writable);
  const preferred = requestedProvider
    ? (providers.find((provider) => provider.id === requestedProvider && provider.writable) || null)
    : (writableProviders.length === 1 ? writableProviders[0] : null);
  const requested = providers.find((provider) => provider.id === requestedProvider) || null;
  item.location = candidate.path;
  item.providers = providers;
  item.selectedProvider = preferred?.id || requested?.id || '';
  item.selectable = Boolean(preferred);
  const configured = Boolean(preferred?.baseUrl);
  item.state = preferred ? (configured ? 'ok' : 'ready') : 'unsupported';
  item.badge = preferred ? (configured ? '已配置' : '可写入') : '需配置';
  const blocked = requested?.blockedReason ? requested : providers.find((provider) => provider.blockedReason);
  item.detail = preferred
    ? (preferred.baseUrl || `提供商 ${preferred.id}`)
    : (blocked?.blockedReason || (writableProviders.length > 1 ? '请选择要轮换的提供商' : '没有带 apiKeyEnv 的可写提供商'));
  state.targetOptions.dsh = {settingsPath: candidate.path, provider: preferred?.id || ''};
}

function configureContinueModel(item, modelIndex) {
  const model = (item.providers || []).find((entry) => entry.id === String(modelIndex));
  item.selectedProvider = model?.id || '';
  item.selectable = Boolean(model?.writable);
  item.state = model ? (model.writable ? (model.baseUrl ? 'ok' : 'ready') : 'unsupported') : 'selection-required';
  item.badge = model ? (model.writable ? (model.baseUrl ? '已配置' : '可写入') : '不可写') : '需选择';
  item.detail = model
    ? (model.writable ? `${model.name}${model.provider ? ` · ${model.provider}` : ''}` : model.blockedReason)
    : `发现 ${(item.providers || []).length} 个模型，请选择要轮换的模型`;
  if (model?.writable) {
    state.targetOptions.continue = {modelIndex: model.id};
  } else {
    delete state.targetOptions.continue;
  }
}

function configureOpenCodeVendor(item, vendorId) {
  const vendor = (item.providers || []).find((entry) => entry.id === String(vendorId));
  item.selectedProvider = vendor?.id || '';
  item.selectable = Boolean(vendor?.writable);
  item.state = vendor ? (vendor.writable ? (vendor.baseUrl ? 'ok' : 'ready') : 'byok-managed') : 'selection-required';
  item.badge = vendor ? (vendor.writable ? (vendor.baseUrl ? '已配置' : '可写入') : '由 VS Code 管理') : '需选择';
  item.detail = vendor
    ? (vendor.writable ? (vendor.baseUrl || `将更新 ${vendor.name}`) : `${vendor.name} 已由 VS Code BYOK 分组管理`)
    : '请选择 OpenCode Go 或 OpenCode Zen';
  if (vendor) {
    state.targetOptions.opencode_copilot = {
      ...(state.targetOptions.opencode_copilot || {}),
      vendor: vendor.id,
    };
  } else {
    delete state.targetOptions.opencode_copilot;
  }
}

function configureVscodeProfile(item, userDataDir) {
  const profile = (item.candidates || []).find((entry) => entry.path === userDataDir);
  if (!profile) return;
  state.targetOptions[item.id] = {
    ...(state.targetOptions[item.id] || {}),
    userDataDir: profile.path,
  };
}

function renderInspector(item) {
  elements.targetInspector.replaceChildren();
  if (!item) {
    elements.inspectorState.textContent = '—';
    elements.targetInspector.append(node('p', 'plain-empty', '检测完成后，在左侧选择一个工具。'));
    return;
  }
  elements.inspectorState.textContent = item.badge || '—';

  const title = node('div', 'inspector-title');
  title.append(node('strong', '', item.title), node('span', '', item.detail || '未找到详细信息'));
  elements.targetInspector.append(title);

  const properties = node('dl', 'property-grid');
  addProperty(properties, '配置位置', item.location || '—', {mono: true});
  if (item.extension) {
    addProperty(properties, '扩展名称', item.extension.name);
    addProperty(properties, '发布者', item.extension.publisher, {mono: true});
    addProperty(properties, '扩展 ID', item.extension.id, {mono: true});
    addProperty(properties, '版本', item.extension.installed ? (item.extension.version || '已安装') : '未安装', {mono: true});
  }
  if (item.installer && !item.installer.installed && !item.extension) {
    addProperty(properties, '官方来源', item.installer.publisher);
    addProperty(properties, '安装标识', item.installer.identity, {mono: true});
  }
  if (item.note) addProperty(properties, '注意', item.note);
  elements.targetInspector.append(properties);

  if (item.id === 'dsh') {
    const controls = node('div', 'choice-panel');
    const pathLabel = node('label', '', '配置文件');
    const pathSelect = node('select');
    (item.candidates || []).forEach((candidate) => {
      const option = node('option', '', `${candidate.source} — ${candidate.path}`);
      option.value = candidate.path;
      option.selected = candidate.path === (state.targetOptions.dsh?.settingsPath || item.location);
      pathSelect.append(option);
    });
    if (!item.candidates?.length) {
      const option = node('option', '', '未自动发现');
      option.value = '';
      pathSelect.append(option);
    }
    pathSelect.addEventListener('change', () => {
      configureDshCandidate(item, pathSelect.value);
      invalidatePreview();
      replaceTarget(item);
    });
    pathLabel.append(pathSelect);

    const providerLabel = node('label', '', 'API 提供商');
    const providerSelect = node('select');
    (item.providers || []).forEach((provider) => {
      const option = node('option', '', `${provider.name} (${provider.id})${provider.writable ? '' : ' · 不可写'}`);
      option.value = provider.id;
      option.disabled = !provider.writable;
      option.selected = provider.id === (state.targetOptions.dsh?.provider || item.selectedProvider);
      providerSelect.append(option);
    });
    if (!item.providers?.length) {
      const option = node('option', '', '没有可用提供商');
      option.value = '';
      providerSelect.append(option);
    }
    providerSelect.addEventListener('change', () => {
      state.targetOptions.dsh = {
        settingsPath: state.targetOptions.dsh?.settingsPath || item.location,
        provider: providerSelect.value,
      };
      item.selectedProvider = providerSelect.value;
      const provider = item.providers.find((entry) => entry.id === providerSelect.value);
      if (provider) {
        item.selectable = Boolean(provider.writable);
        item.detail = provider.baseUrl || `提供商 ${provider.id}`;
        item.state = provider.baseUrl ? 'ok' : 'ready';
        item.badge = provider.baseUrl ? '已配置' : '可写入';
      }
      invalidatePreview();
      renderTargets(state.targets);
    });
    providerLabel.append(providerSelect);

    const locate = node('button', 'button secondary', '手动定位…');
    locate.type = 'button';
    locate.addEventListener('click', pickDshConfig);
    controls.append(pathLabel, providerLabel, locate);
    elements.targetInspector.append(controls);
  }

  if (item.id === 'continue' && item.providers?.length) {
    const controls = node('div', 'choice-panel');
    const modelLabel = node('label', '', '目标模型');
    const modelSelect = node('select');
    if (item.providers.length > 1) {
      const placeholder = node('option', '', '请选择要轮换的模型');
      placeholder.value = '';
      placeholder.selected = !state.targetOptions.continue?.modelIndex;
      modelSelect.append(placeholder);
    }
    item.providers.forEach((model) => {
      const details = [model.provider, model.model].filter(Boolean).join(' / ');
      const option = node('option', '', `${model.name}${details ? ` — ${details}` : ''}${model.writable ? '' : ' · 不可写'}`);
      option.value = model.id;
      option.disabled = !model.writable;
      option.selected = model.id === (state.targetOptions.continue?.modelIndex || item.selectedProvider);
      modelSelect.append(option);
    });
    modelSelect.addEventListener('change', () => {
      configureContinueModel(item, modelSelect.value);
      invalidatePreview();
      replaceTarget(item);
    });
    modelLabel.append(modelSelect);
    controls.append(modelLabel);
    elements.targetInspector.append(controls);
  }

  if (item.id === 'opencode_copilot' && item.providers?.length) {
    const controls = node('div', 'choice-panel');
    const vendorLabel = node('label', '', 'OpenCode 提供商');
    const vendorSelect = node('select');
    item.providers.forEach((vendor) => {
      const option = node('option', '', `${vendor.name}${vendor.writable ? '' : ' · 由 VS Code BYOK 管理'}`);
      option.value = vendor.id;
      option.selected = vendor.id === (state.targetOptions.opencode_copilot?.vendor || item.selectedProvider);
      vendorSelect.append(option);
    });
    vendorSelect.addEventListener('change', () => {
      configureOpenCodeVendor(item, vendorSelect.value);
      invalidatePreview();
      replaceTarget(item);
    });
    vendorLabel.append(vendorSelect);
    controls.append(vendorLabel);
    elements.targetInspector.append(controls);
  }

  if (VSCODE_TARGETS.has(item.id) && item.candidates?.length > 1) {
    const controls = node('div', 'choice-panel');
    const profileLabel = node('label', '', 'VS Code 用户数据');
    const profileSelect = node('select');
    const placeholder = node('option', '', '请选择要修改的 VS Code 配置');
    placeholder.value = '';
    placeholder.selected = !state.targetOptions[item.id]?.userDataDir && !item.selectedProfile;
    profileSelect.append(placeholder);
    item.candidates.forEach((profile) => {
      const option = node('option', '', `${profile.source} — ${profile.path}`);
      option.value = profile.path;
      option.selected = profile.path === (state.targetOptions[item.id]?.userDataDir || item.selectedProfile);
      profileSelect.append(option);
    });
    profileSelect.addEventListener('change', async () => {
      if (!profileSelect.value) return;
      configureVscodeProfile(item, profileSelect.value);
      invalidatePreview();
      await detect();
      state.selectedTargetId = item.id;
      renderTargets(state.targets);
    });
    profileLabel.append(profileSelect);
    controls.append(profileLabel);
    elements.targetInspector.append(controls);
  }

  if (item.installer && !item.installer.installed) {
    const install = node('button', 'button primary inspector-install install-action',
      item.installer.enabled ? `安装 ${item.installer.name}…` : '需要先安装 VS Code');
    install.type = 'button';
    install.dataset.disabled = String(!item.installer.enabled);
    install.dataset.installable = String(Boolean(item.installer.enabled));
    install.addEventListener('click', () => promptInstaller(item));
    elements.targetInspector.append(install);
  }

  const discovery = (item.discovery || []).filter((entry) => entry.path);
  if (discovery.length) {
    const block = node('div', 'source-block');
    block.append(node('h4', '', '发现来源'));
    const list = node('div', 'source-list');
    discovery.forEach((entry) => {
      const row = node('div', 'source-row');
      row.append(node('span', '', entry.source || '自动发现'), node('code', '', entry.path));
      list.append(row);
    });
    block.append(list);
    elements.targetInspector.append(block);
  }
  refreshButtons();
}

function renderTargets(items) {
  const previous = new Map(
    [...elements.targets.querySelectorAll('input[type="checkbox"]')]
      .map((input) => [input.value, input.checked]),
  );
  elements.targets.replaceChildren();

  if (!state.selectedTargetId || !items.some((item) => item.id === state.selectedTargetId)) {
    state.selectedTargetId = (items.find((item) => item.id === 'dsh') || items[0] || {}).id || '';
  }

  items.forEach((item) => {
    const row = node('div', 'target-row');
    row.setAttribute('role', 'listitem');
    row.dataset.state = item.state;
    row.dataset.selectable = String(Boolean(item.selectable));
    row.classList.toggle('is-active', item.id === state.selectedTargetId);

    const input = document.createElement('input');
    input.type = 'checkbox';
    input.name = 'targetIds';
    input.value = item.id;
    input.setAttribute('aria-label', `选择 ${item.title}`);
    input.checked = item.selectable && (previous.has(item.id) ? previous.get(item.id) : true);
    input.disabled = !item.selectable;
    input.addEventListener('change', () => refreshSelection({invalidate: true}));

    const focus = node('button', 'target-focus');
    focus.type = 'button';
    focus.append(node('strong', '', item.title), node('small', '', item.detail || item.location || '未发现'));
    focus.addEventListener('click', () => {
      state.selectedTargetId = item.id;
      renderTargets(state.targets);
    });

    const end = node('div', 'target-end');
    end.append(node('span', 'target-state', item.badge || (item.selectable ? '可写入' : '不可用')));
    if (item.installer && !item.installer.installed) {
      const install = node('button', 'install-mini install-action', '↓ 安装');
      install.type = 'button';
      install.dataset.installable = String(Boolean(item.installer.enabled));
      install.disabled = !item.installer.enabled;
      install.title = item.installer.enabled ? `安装 ${item.installer.name}` : '需要先安装 VS Code';
      install.addEventListener('click', () => promptInstaller(item));
      end.append(install);
    }
    row.append(input, focus, end);
    elements.targets.append(row);
  });

  state.targets = items;
  state.hasDetected = true;
  renderInspector(currentTarget());
  refreshSelection();
}

function renderChanges(changes) {
  elements.changeList.replaceChildren();
  changes.forEach((change) => {
    const row = node('div', 'change-row');
    row.append(
      node('span', 'change-target', change.target),
      node('span', 'change-file', change.path || change.file),
      node('span', 'change-summary', change.summary),
    );
    row.children[1].title = change.path || change.file;
    elements.changeList.append(row);
  });
  elements.emptyState.hidden = true;
  elements.changeList.hidden = false;
  elements.changeCount.textContent = String(changes.length);
}

async function detect() {
  if (state.busy) return;
  setBusy(true, 'detect', '正在检测本机工具');
  elements.detectSummary.textContent = '检测中';
  clearLog();
  appendLog('读取配置、命令和开始菜单快捷方式…');
  try {
    const data = await api('/api/detect-options', {
      method: 'POST',
      body: JSON.stringify({targetOptions: state.targetOptions}),
    });
    state.vscodeRunning = data.vscodeRunning;
    const dsh = data.items.find((item) => item.id === 'dsh');
    if (dsh?.candidates?.length) {
      const candidate = dsh.candidates.find((entry) => entry.path === state.targetOptions.dsh?.settingsPath)
        || dsh.candidates[0];
      configureDshCandidate(dsh, candidate.path);
    }
    const continueTarget = data.items.find((item) => item.id === 'continue');
    if (continueTarget?.providers?.length) {
      const previousModel = state.targetOptions.continue?.modelIndex;
      if (previousModel && continueTarget.providers.some((model) => model.id === previousModel)) {
        configureContinueModel(continueTarget, previousModel);
      } else if (continueTarget.providers.length === 1) {
        configureContinueModel(continueTarget, continueTarget.providers[0].id);
      } else {
        delete state.targetOptions.continue;
      }
    }
    const openCodeTarget = data.items.find((item) => item.id === 'opencode_copilot');
    if (openCodeTarget?.providers?.length) {
      const requestedVendor = state.targetOptions.opencode_copilot?.vendor || openCodeTarget.selectedProvider || 'opencodego';
      configureOpenCodeVendor(openCodeTarget, requestedVendor);
    }
    renderTargets(data.items);
    const selectable = data.items.filter((item) => item.selectable).length;
    const missingInstallers = data.items.filter((item) => item.installer && !item.installer.installed).length;
    elements.detectSummary.textContent = missingInstallers
      ? `${selectable} 可用 · ${missingInstallers} 可安装`
      : `${selectable} 可用`;
    data.items.forEach((item) => appendLog(`${item.title} · ${item.badge}`, item.selectable ? 'ok' : 'warn'));
    if (data.vscodeRunning) appendLog('VS Code 正在运行；写入相关配置前需要退出。', 'warn');
    setMode('选择工具查看路径与发现来源');
    setFooter('本地运行');
  } catch (error) {
    state.installToken = '';
    elements.detectSummary.textContent = '检测失败';
    setMode('检测失败');
    setFooter('错误');
    appendLog(error.message, 'error');
    showToast(error.message, 'error');
  } finally {
    state.busy = false;
    state.busyAction = '';
    refreshButtons();
  }
}

async function pickDshConfig() {
  if (state.busy) return;
  setBusy(true, 'pick', '等待选择 DSH 配置');
  try {
    const data = await api('/api/pick-dsh-config', {method: 'POST', body: '{}'});
    if (data.cancelled) {
      setMode('未更改 DSH 配置位置');
      return;
    }
    const item = data.item;
    const candidate = item.candidates.find((entry) => entry.path === item.location) || item.candidates[0];
    if (candidate) configureDshCandidate(item, candidate.path);
    state.selectedTargetId = 'dsh';
    replaceTarget(item);
    invalidatePreview();
    showToast('已采用所选 DSH 配置', 'ok');
  } catch (error) {
    state.installToken = '';
    appendLog(error.message, 'error');
    showToast(error.message, 'error');
  } finally {
    state.busy = false;
    state.busyAction = '';
    setFooter('本地运行');
    refreshButtons();
  }
}

function fillInstallDialog() {
  const installer = state.pendingInstaller;
  if (!installer) return;
  elements.installTitle.textContent = `安装 ${installer.name}`;
  elements.installPublisher.textContent = installer.publisher;
  elements.installIdentity.textContent = installer.identity;
  elements.installLocation.value = installer.location || '';
  elements.installLocation.title = installer.location || '';
  elements.chooseInstallLocation.hidden = installer.pathMode === 'fixed';
  const locationMode = installer.pathMode === 'fixed' ? '官方固定位置' : '自动加入用户 PATH';
  elements.installPathHint.textContent = `${installer.sizeLabel} · ${locationMode}`;
  elements.installNote.textContent = installer.note;
  elements.installProgress.hidden = true;
  elements.installProgress.removeAttribute('data-tone');
  elements.installProgressText.textContent = '正在下载安装包…';
  elements.installForm.removeAttribute('aria-busy');
  elements.cancelInstall.disabled = false;
  elements.confirmInstall.disabled = !state.installToken;
  elements.confirmInstall.lastChild.textContent = '安装';
}

async function requestInstallLocation(installer) {
  const data = await api('/api/pick-install-location', {
    method: 'POST',
    body: JSON.stringify({targetId: installer.targetId}),
  });
  if (data.cancelled) return false;
  installer.location = data.location;
  state.installToken = data.installToken;
  return true;
}

async function promptInstaller(item) {
  const installer = item.installer;
  if (!installer?.enabled || installer.installed || state.busy) return;
  state.pendingInstaller = {...installer, targetId: item.id};
  state.installToken = '';
  setBusy(true, 'pick-install', installer.pathMode === 'fixed' ? '正在准备官方安装器' : '等待选择安装位置');
  try {
    if (!await requestInstallLocation(state.pendingInstaller)) {
      state.pendingInstaller = null;
      setMode('未更改安装状态');
      return;
    }
    fillInstallDialog();
    elements.installDialog.showModal();
  } catch (error) {
    state.pendingInstaller = null;
    state.installToken = '';
    appendLog(error.message, 'error');
    showToast(error.message, 'error');
  } finally {
    state.busy = false;
    state.busyAction = '';
    setFooter('本地运行');
    refreshButtons();
  }
}

async function repickInstallLocation() {
  if (!state.pendingInstaller || state.busy || state.pendingInstaller.pathMode === 'fixed') return;
  elements.chooseInstallLocation.disabled = true;
  elements.chooseInstallLocation.textContent = '选择中…';
  try {
    if (await requestInstallLocation(state.pendingInstaller)) fillInstallDialog();
  } catch (error) {
    showToast(error.message, 'error');
  } finally {
    elements.chooseInstallLocation.disabled = false;
    elements.chooseInstallLocation.textContent = '更改';
  }
}

async function installPendingAgent() {
  const installer = state.pendingInstaller;
  if (!installer || !state.installToken || state.busy) return;
  setBusy(true, 'install', `正在安装 ${installer.name}`);
  clearLog();
  appendLog(`官方来源：${installer.identity}`);
  appendLog(`安装位置：${installer.location}`);
  elements.installForm.setAttribute('aria-busy', 'true');
  elements.installProgress.hidden = false;
  elements.installProgressText.textContent = installer.kind === 'extension'
    ? '正在调用 VS Code 安装扩展…'
    : '正在下载并验证官方安装包…';
  elements.confirmInstall.lastChild.textContent = '安装中';
  elements.confirmInstall.disabled = true;
  elements.cancelInstall.disabled = true;
  elements.chooseInstallLocation.disabled = true;
  try {
    const data = await api('/api/install-agent', {
      method: 'POST',
      body: JSON.stringify({targetId: installer.targetId, installToken: state.installToken}),
    });
    appendLog(`安装完成：${data.installed.name} ${data.installed.version}`, 'ok');
    appendLog(`位置：${data.installed.location}`, 'ok');
    if (data.installed.warning) appendLog(data.installed.warning, 'warn');
    showToast(data.installed.warning || `${data.installed.name} 安装完成`, data.installed.warning ? 'warn' : 'ok');
    state.pendingInstaller = null;
    state.installToken = '';
    elements.installDialog.close();
    state.busy = false;
    state.busyAction = '';
    await detect();
  } catch (error) {
    appendLog(error.message, 'error');
    elements.logDetails.open = true;
    elements.installProgressText.textContent = error.message;
    elements.installProgress.dataset.tone = 'error';
    elements.installNote.textContent = installer.pathMode === 'fixed'
      ? '安装未完成。请检查网络，关闭此窗口后再次点击安装。'
      : '安装未完成。请检查目标目录，重新选择安装位置后再试。';
    showToast(error.message, 'error');
  } finally {
    state.busy = false;
    state.busyAction = '';
    elements.installForm.removeAttribute('aria-busy');
    elements.confirmInstall.lastChild.textContent = state.installToken ? '重试' : '需要重新确认';
    elements.cancelInstall.disabled = false;
    elements.chooseInstallLocation.disabled = false;
    setFooter('本地运行');
    refreshButtons();
  }
}

async function rotate(apply) {
  if (state.busy || !validUrl() || !validKey() || !selectedIds().length) return;
  setBusy(true, apply ? 'apply' : 'preview', apply ? '正在应用更改' : '正在生成预览');
  clearLog();
  appendLog(apply ? '创建备份并写入所选配置。' : '只读预览，不会写入配置。');
  try {
    const targetIds = selectedIds();
    const data = await api(apply ? '/api/apply' : '/api/preview', {
      method: 'POST',
      body: JSON.stringify({
        baseUrl: normalizedUrl(),
        newKey: elements.keyInput.value.trim(),
        targetIds,
        targetOptions: selectedOptions(),
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
      setMode(`已更新 ${targetIds.length} 个工具`);
      setFooter('应用完成');
      showToast('配置已更新，备份已保留', 'ok');
    } else if (data.vscodeRunning && targetIds.some((id) => VSCODE_TARGETS.has(id))) {
      state.previewToken = '';
      setMode('请完全退出 VS Code 后重新预览');
      setFooter('等待退出 VS Code');
      elements.logDetails.open = true;
      appendLog('VS Code 相关配置不会在进程运行时写入。', 'warn');
      showToast('请先完全退出 VS Code', 'error');
    } else {
      state.previewToken = data.previewToken;
      setMode(`预览完成 · ${state.changes.length} 处更改`);
      setFooter('可以应用');
      showToast('预览已生成', 'ok');
    }
  } catch (error) {
    state.previewToken = '';
    setMode(apply ? '应用失败' : '预览失败');
    setFooter('错误');
    appendLog(error.message, 'error');
    elements.logDetails.open = true;
    renderEmpty(apply ? '没有完成写入' : '无法生成预览', error.message);
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
elements.chooseInstallLocation.addEventListener('click', repickInstallLocation);
elements.confirmInstall.addEventListener('click', installPendingAgent);
elements.installDialog.addEventListener('cancel', (event) => {
  if (state.busyAction === 'install') event.preventDefault();
});
elements.installDialog.addEventListener('close', () => {
  if (state.busyAction === 'install') return;
  state.pendingInstaller = null;
  state.installToken = '';
  elements.installProgress.removeAttribute('data-tone');
});
elements.quitButton.addEventListener('click', async () => {
  try { await api('/api/shutdown', {method: 'POST', body: '{}'}); } catch (_) { /* 服务可能先关闭 */ }
  window.close();
});

window.addEventListener('beforeunload', (event) => {
  if (!state.busy) return;
  event.preventDefault();
  event.returnValue = '';
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
      elements.keyInput.value = 'demo-local-key-1234567890-example';
      refreshSourceState();
    }
    await detect();
  } catch (error) {
    setMode('本地服务未连接');
    setFooter('离线');
    renderEmpty('本地服务未连接', '请重新启动 Key Router。');
    appendLog(error.message, 'error');
    showToast('本地服务未连接', 'error');
  }
}

init();
