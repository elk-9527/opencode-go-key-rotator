(() => {
  const allowed = new Set(['light', 'dark', 'system']);
  let preference = 'system';
  try {
    const stored = localStorage.getItem('key-rotator-theme');
    if (allowed.has(stored)) preference = stored;
  } catch (_) {
    // Storage can be unavailable in hardened browser profiles.
  }
  const systemDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  document.documentElement.dataset.theme = preference;
  document.documentElement.dataset.resolvedTheme = preference === 'system'
    ? (systemDark ? 'dark' : 'light')
    : preference;
})();
