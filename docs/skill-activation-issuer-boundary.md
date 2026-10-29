# Skill Activation issuer boundary

The control plane issues a Skill Activation only after all of the following are true:

- tenant and project are currently active
- the requested role/skill resolves to an active immutable Skill Package admission
- the supplied Skill Package exactly matches that persisted admission
- the package authority class matches the requested work authority class
- the governing Work Authority or Execution Grant has been independently verified for the same current tenant/project context, task and agent
- activation lifetime is at most 120 seconds
- every external signer returns a valid Ed25519 signature that Foundry verifies immediately against its configured public key

Private signing keys remain outside Foundry. The issuer accepts external signer callbacks and never treats signer output as trusted until cryptographic verification succeeds.

The runner cannot request a different package after activation. Package id, contract hash and artifact digest are signed activation material.
