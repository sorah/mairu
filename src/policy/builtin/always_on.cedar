// Gate 2 is open unless a forbid closes it. A forbid that a fresh human check would satisfy
// makes the agent ask at gate 2.
@id("builtin-use-credentials")
permit (principal, action == Mairu::Action::"UseCredentials", resource);

// Credentials for another account than the one the role name declares are never vended.
@id("builtin-caller-account-mismatch")
forbid (principal, action == Mairu::Action::"UseCredentials", resource)
when {
  resource has account_id && context has caller &&
  resource.account_id != context.caller.account
};
