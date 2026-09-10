// Declarative policy match patterns only; this module must not perform filesystem I/O.
// S5443 is excluded for this data-only file in sonar-project.properties because
// these strings identify allowed paths, not locations where GuardMe creates files.
export const OS_TEMP_ROOT_PATTERNS = [
  "/tmp",
  "/private/tmp",
  "/var/tmp",
  "/private/var/tmp",
  "/var/folders/*/*/T",
  "/private/var/folders/*/*/T",
] as const;
