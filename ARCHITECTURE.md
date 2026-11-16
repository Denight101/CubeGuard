# One cube per protected endpoint

## Design goal

Give each protected device its own access boundary and narrowly scoped permissions, while optionally sharing status with a central monitor. A compromised credential or neighboring device should not automatically grant control of the entire fleet. The cube is a visual model for multiple checks; geometric shape has no cryptographic significance.

For industrial equipment, the gateway should cover all remote and local command paths that it claims to control. A gateway that can be bypassed is not a complete boundary. Critical safety functions must remain independently engineered and tested rather than delegated to this prototype.

| Proposed face | Per-device design goal | Current implementation |
|---|---|---|
| Identity | Individual accounts, scoped authorization, expiring access | One shared proxy credential |
| Device trust | Approved technician devices and gateway identity | IPv4 loopback listener only |
| Traffic | Restricted management paths, minimum required protocols | CONNECT destination domains and ports |
| Behavior | Detect unexpected control changes or fleet-wide activity | Global rate, concurrency and time budgets |
| Commands/data | Validate commands against equipment-specific limits | Bidirectional byte budget only |
| Containment | Separate controller access, credentials and failure domains | Public IPv4 destination filtering and DNS pinning |

## Refrigeration example: future work only

A protocol-aware gateway could check a maintenance request before it reaches a controller. It would need validated equipment-specific rules for temperature targets, defrost duration, mode changes and service overrides. Generic rules such as 'never allow a positive temperature' are unsafe assumptions because legitimate defrost behavior varies by equipment.

An independent sensor, alarm and safety mechanism would need a separate design appropriate to the machinery. Loss of network access must not interrupt safe local control. Recovery procedures and authorized maintenance overrides would need to be tested with the equipment owner and qualified engineers. CubeGuard currently implements none of these physical control functions.

## Threat model for this release

The prototype checks authenticated CONNECT requests from cooperating local clients before forwarding them to allowed public IPv4 destinations. It assumes the host OS, Node runtime, source, policy and process environment have not been compromised. A local administrator or compromised same-user process can bypass or modify it. An allowed destination may act as a relay, and the encrypted payload can contain requests the proxy does not understand.

The proxy does not provide application sandboxing, decrypted payload inspection, OS-wide traffic capture, IPv6/UDP coverage, per-device certificates, MFA, persistent service hardening or distributed trust. The Windows script independently adds literal-IP outbound blocks for all applications; it does not turn the proxy into a Windows Filtering Platform driver.

## Future milestones

1. Add a simulated controller and tests for authorized and rejected command changes.
2. Define protocol-specific adapters, separate device identities and explicit bypass assumptions.
3. Add independent process isolation and an authenticated policy-management design.
4. Measure latency, throughput, memory use and behavior under connection floods.
5. Obtain external security review before considering real deployments.

These are proposed directions, not delivered features or promises.
