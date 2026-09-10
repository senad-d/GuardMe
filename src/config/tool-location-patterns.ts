// Read-only tool installations agents inspect while working: `which node`,
// `head -1 $(which pnpm)`, version checks. Nothing here is writable, and the
// credential path classifier still protects keyword-named files inside them.
export const TOOL_LOCATION_PATTERNS = [
  "/opt/homebrew/**",
  "/usr/local/bin/**",
  "/usr/local/lib/**",
  "/usr/local/opt/**",
  "/usr/local/Cellar/**",
  "/usr/bin/**",
  "/bin/**",
  "/usr/lib/**",
  "/usr/share/**",
  "~/.nvm/versions/**",
  "~/.volta/**",
  "~/.local/share/pnpm/**",
  "~/Library/pnpm/**",
  "~/.asdf/installs/**",
  "~/.local/share/mise/**",
] as const;
