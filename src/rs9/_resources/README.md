# Installed starter resources

`consumer/project.toml` and `consumer/releases.toml` are deliberately inert
examples of the closed v1alpha1 contract. Copy them into a selected consumer's
`.rs9/` and replace identity, license and artifact facts before use. No adapter,
destination, credential, publisher registration or publication authority is
enabled by copying them. The installed Python validators are the schema owner.

Resource identity is available through Python `importlib.resources.files("rs9")`
under `_resources/`; it does not depend on a source checkout. These starter
files do not constitute a qualified publisher or remote onboarding.
