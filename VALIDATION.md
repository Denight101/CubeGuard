# Validation

- Node integration suite: 12 tests, covering local CONNECT requests with test-only DNS and local upstream servers.
- PowerShell parser: both scripts parsed without errors.
- Windows Firewall script: default Preview ran successfully with an empty IP block list.
- No firewall rules applied, system proxy settings changed, public upstream connections tested, or persistent service installed.
- Real Windows Firewall Apply/Remove, external HTTPS interoperability, load handling and performance have not been validated. This is a prototype requiring further review before deployment.
