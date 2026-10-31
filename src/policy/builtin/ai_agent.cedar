// AI agents: a human approves every new request; a running `mairu exec` keeps its approval
// as above.
@id("builtin-ai-agent-per-request")
permit (principal, action == Mairu::Action::"AssumeRole", resource)
when {
  context.tools.contains("ai-agent") &&
  context.presence.verified &&
  (context.presence.scope == "request" ||
   (context.presence.scope == "process" && context.presence.idle <= 3600))
};
