# Security policy

CubeGuard 0.1 is experimental and has no production security assurance or guaranteed support window. Do not use it as the sole protection for bank accounts, public services, industrial equipment or safety-critical systems.

## Reporting

If GitHub private vulnerability reporting is enabled for this repository, use the repository's Security tab to submit a private report. If that option is unavailable, open an issue asking the maintainer for a private reporting channel, without posting exploit details, credentials, logs, IP addresses or personal data. No private reporting channel or response deadline is promised by this document.

Include the affected version, expected behavior, a minimal local reproduction and impact. Test only systems you own or have permission to test. Use dummy credentials and local simulated services. Do not target actual refrigeration controllers or other people's infrastructure.

## Known boundaries

- Only explicitly proxied CONNECT traffic is covered; direct connections bypass it.
- Loopback checks are not device attestation and a shared credential is not per-user identity.
- TLS payloads, server names inside TLS, banking actions and equipment commands are not inspected.
- Allowed hosts can be relays; domain filtering is not complete data-loss prevention.
- Policy, credentials and checks share one host process; local compromise defeats this boundary.
- IPv6 and UDP are unsupported; production performance, flood resistance and OS firewall changes need further validation.
- Global budgets can let one local client deny capacity to others.

Keep Windows Firewall and other existing protections enabled. Review the code and policy before enabling forwarding. Do not publish actual proxy credentials or audit logs.
