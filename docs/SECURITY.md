# Security Policy

## Scope

This repository contains IdentityIQ configuration, a Java library that plans
access changes on Linux file servers, and application server configuration.
Defects that could grant, retain or hide access are treated as security
issues. Examples: a plan that grants before it revokes, a revocation that
leaves access through a nested group without a warning, a codec field that
lets one step smuggle another, evidence whose digest does not cover a field
the reviewer relied on, or a rule that signs in the wrong identity.

## Reporting

Report suspected vulnerabilities privately through GitHub security advisories
on this repository ("Report a vulnerability" on the Security tab). Do not
open a public issue. Include the affected file, the input that triggers the
behaviour and the access outcome observed. Reports are acknowledged within
five working days.

## Handling of secrets

* No credential, key, client secret or token is stored in this repository.
  Database passwords and the Entra ID client secret are held in an Elytron
  credential store on the host and supplied to JBoss CLI through a local
  properties file that is excluded by `.gitignore`.
* `sandbox.target.properties` carries non secret placeholders only.
* The build fails if a private key block, a credential store or a
  `local.properties` file is found in the tree.

## Design controls

* The connector never runs commands on a target host. It writes structured
  change steps to a queue; the host executor parses fields and applies them.
  Fields containing tab, carriage return or newline are rejected at encode
  time.
* Revocations are ordered before grants, and a grant and a revocation of the
  same access in one plan resolve to the revocation.
* XML parsing in the build disables external entities and external DTD
  loading.
* SSO sign in returns no identity unless exactly one active identity matches
  the authenticated principal.

## Supported versions

Only the `main` branch is maintained.
