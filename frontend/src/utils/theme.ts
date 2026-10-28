export type ThemeMode = 'dark' | 'light' | 'system';

const STORAGE_KEY = 'sv_theme_preference';

export function getStoredTheme(): ThemeMode {
  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored === 'dark' || stored === 'light' || stored === 'system') {
    return stored;
  }
  return 'dark'; // Default to dark mode
}

export function applyTheme(theme: ThemeMode): 'dark' | 'light' {
  let effectiveTheme: 'dark' | 'light';

  if (theme === 'system') {
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    effectiveTheme = prefersDark ? 'dark' : 'light';
  } else {
    effectiveTheme = theme;
  }

  document.documentElement.setAttribute('data-theme', effectiveTheme);
  localStorage.setItem(STORAGE_KEY, theme);

  // Update meta theme-color for mobile browsers
  const metaThemeColor = document.querySelector('meta[name="theme-color"]');
  if (metaThemeColor) {
    metaThemeColor.setAttribute('content', effectiveTheme === 'dark' ? '#060913' : '#f8fafc');
  }

  return effectiveTheme;
}
