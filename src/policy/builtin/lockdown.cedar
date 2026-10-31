// Lockdown, while the policy files differ from what was approved: every request needs a fresh
// human check. A running `mairu exec` keeps its approval until it goes 1 hour without credentials.
@id("builtin-lockdown")
permit (principal, action == Mairu::Action::"AssumeRole", resource)
when {
  context.presence.verified &&
  (context.presence.scope == "request" ||
   (context.presence.scope == "process" && context.presence.idle <= 3600))
};

// AI agents are refused at both gates.
@id("builtin-lockdown-no-ai")
forbid (principal, action, resource)
when { context.tools.contains("ai-agent") };
