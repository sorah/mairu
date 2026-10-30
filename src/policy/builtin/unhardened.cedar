// An unhardened agent cannot tell clients apart, so asking a human would protect nothing.
@id("builtin-unhardened")
permit (principal, action == Mairu::Action::"AssumeRole", resource);
