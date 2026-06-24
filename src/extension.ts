import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

import { registerGuardMeCommand } from "./commands/guardme-command.ts";
import { registerGuard } from "./events/register-guard.ts";
import { registerGuidance } from "./events/register-guidance.ts";
import { registerLifecycle } from "./events/register-lifecycle.ts";

/**
 * GuardMe extension entry point.
 *
 * Keep this factory as a small registration layer. Policy evaluation, config
 * loading, state persistence, UI, and command behavior live in dedicated
 * modules so they can be tested without importing Pi runtime APIs.
 */
export default function guardMe(pi: ExtensionAPI): void {
  registerLifecycle(pi);
  registerGuard(pi);
  registerGuidance(pi);
  registerGuardMeCommand(pi);
}
