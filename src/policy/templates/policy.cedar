// The authorization policy of the mairu agent, in Cedar (https://www.cedarpolicy.com/).
//
// `mairu policy check` validates this file, `mairu policy schema` prints the attributes a policy can use,
// `mairu policy show` prints what the agent has in force, and `mairu policy explain` what it would decide.
//
// Until this file is approved, the agent applies only its `forbid` policies, on top of its built-in policies;
// the `permit` policies here are ignored. A `forbid` always wins over a `permit`.
// Credentials whose real account differs from the one the role name declares are always refused.

// Humans: one check per terminal session, remembered for 5 minutes idle, 12 hours at most.
// A running `mairu exec` keeps its approval for its lifetime, until it goes 1 hour without credentials.
@id("human")
permit (principal, action == Mairu::Action::"AssumeRole", resource)
when {
  !context.tools.contains("ai-agent") &&
  context.presence.verified &&
  (context.presence.scope != "session" ||
   (context.presence.idle <= 300 && context.presence.age <= 43200)) &&
  (context.presence.scope != "process" || context.presence.idle <= 3600)
};

// AI agents: a human approves every new request; a running `mairu exec` keeps its approval as above.
@id("ai-agent-per-request")
permit (principal, action == Mairu::Action::"AssumeRole", resource)
when {
  context.tools.contains("ai-agent") &&
  context.presence.verified &&
  (context.presence.scope == "request" ||
   (context.presence.scope == "process" && context.presence.idle <= 3600))
};

// Examples. A `forbid` takes effect as soon as it is saved.
//
// Never hand production to AI agents, on any server:
// @id("no-ai-prod")
// forbid (principal, action, resource in Mairu::Account::"999999999999")
// when { context.tools.contains("ai-agent") };
//
// Credentials whose real account is production need a fresh human check, whatever the role is called:
// @id("prod-by-real-account")
// forbid (principal, action == Mairu::Action::"UseCredentials", resource in Mairu::Account::"999999999999")
// unless { context.presence.verified && context.presence.scope == "request" };
